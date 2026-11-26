package scanners

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/draugr-dev/draugr/internal/credential"
	"github.com/draugr-dev/draugr/internal/english"
	"github.com/draugr-dev/draugr/internal/netpolicy"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// SonarQube's security findings, read from its Web API: the issues with a security impact. SonarQube
// writes no report file; what a scan found is held by the server, and read from it as GitHub's alerts
// are. Security hotspots are not read: SonarQube deprecated their API in favor of security issues,
// which a former hotspot's rule now raises.

// sonarTokenEnv and sonarHostEnv are the variables SonarSource's scanners read the token and the
// server from, which a pipeline that runs SonarQube already sets.
//
// #nosec G101 -- the name of an environment variable, not a credential.
const (
	sonarTokenEnv = "SONAR_TOKEN"
	sonarHostEnv  = "SONAR_HOST_URL"
	// sonarCloud is SonarQube Cloud, the server read where $SONAR_HOST_URL names none.
	sonarCloud = "https://sonarcloud.io"
	// sonarService is the service as a reader is told it.
	sonarService = "SonarQube"
	// sonarPageSize is the most results one page of a search returns, and sonarSearchCap the most a
	// search returns at all, however it is paged.
	sonarPageSize  = 500
	sonarSearchCap = 10000
)

// sonarClient reads a project's findings from SonarQube's Web API.
type sonarClient struct {
	// base is the server: $SONAR_HOST_URL, else SonarQube Cloud. Read from the pipeline's environment
	// and never from the descriptor, which changes by pull request: the token goes to this host, and
	// a pull request must not be able to send it elsewhere.
	base string
	// http sends the requests. It refuses to take the token to another origin on a redirect.
	http *http.Client
	// sleep waits out a rate limit, and now is the clock a Retry-After date is read against.
	// Injectable for tests.
	sleep func(ctx context.Context, d time.Duration) error
	now   func() time.Time
}

// newSonarClient is the client a scan uses.
func newSonarClient() sonarClient {
	gh := newGitHubClient()
	return sonarClient{
		base:  strings.TrimSuffix(cmp.Or(strings.TrimSpace(os.Getenv(sonarHostEnv)), sonarCloud), "/"),
		http:  credential.Client(&http.Client{Timeout: time.Minute}),
		sleep: gh.sleep,
		now:   time.Now,
	}
}

// sonarError is a refusal from SonarQube or about the import, worded for the errors block: one
// clause, no colon inside it, within 80 columns.
type sonarError struct{ reason string }

func (e *sonarError) Error() string { return e.reason }

// sonarStatus is a status SonarQube answered with in place of what was asked, and its first message.
type sonarStatus struct {
	code    int
	message string
}

func (e *sonarStatus) Error() string {
	return fmt.Sprintf("SonarQube answered HTTP %d", e.code)
}

// sonarAttempts is how many times one page is asked for while SonarQube limits requests, and
// sonarMaxWait the longest one wait may be.
const (
	sonarAttempts = 3
	sonarMaxWait  = 2 * time.Minute
)

// get asks for one page, waiting out a rate limit SonarQube names where it is short enough.
func (c sonarClient) get(ctx context.Context, token, path string, q url.Values) ([]byte, error) {
	target := c.base + path + "?" + q.Encode()
	for attempt := 1; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/json")
		if err := credential.Guard(req); err != nil {
			return nil, err
		}
		resp, err := c.http.Do(req)
		if err != nil {
			return nil, &sonarError{"SonarQube did not answer. " + strings.TrimSpace(transportReason(err))}
		}
		body, rerr := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
		_ = resp.Body.Close()
		if rerr != nil {
			return nil, rerr
		}
		if resp.StatusCode == http.StatusOK {
			return body, nil
		}
		if resp.StatusCode != http.StatusTooManyRequests {
			var msg struct {
				Errors []struct {
					Msg string `json:"msg"`
				} `json:"errors"`
			}
			_ = json.Unmarshal(body, &msg)
			status := &sonarStatus{code: resp.StatusCode}
			if len(msg.Errors) > 0 {
				status.message = msg.Errors[0].Msg
			}
			return nil, status
		}
		wait, ok := retryAfter(resp.Header.Get("Retry-After"), c.now())
		if !ok {
			wait = githubDefaultWait
		}
		if attempt >= sonarAttempts {
			return nil, &sonarError{fmt.Sprintf("SonarQube kept limiting requests after %d tries (HTTP 429)", attempt)}
		}
		if wait > sonarMaxWait {
			return nil, &sonarError{fmt.Sprintf("SonarQube's rate limit lasts until %s (HTTP 429)",
				c.now().Add(wait).UTC().Format("15:04 UTC"))}
		}
		slog.DebugContext(ctx, "waiting out SonarQube's rate limit", "wait", wait, "attempt", attempt)
		if err := c.sleep(ctx, wait); err != nil {
			return nil, err
		}
	}
}

// sonarPaging is the paging every search answers with.
type sonarPaging struct {
	PageIndex int `json:"pageIndex"`
	PageSize  int `json:"pageSize"`
	Total     int `json:"total"`
}

// search reads every page of a search, handing each page's body to add, which returns how many
// results the page held. A search whose total is above what SonarQube returns is refused rather than
// read in part, since the findings past the cap would be missing with nothing to show it.
func (c sonarClient) search(ctx context.Context, token, path string, q url.Values, what string,
	add func(body []byte) (sonarPaging, int, error)) error {
	read := 0
	for page := 1; ; page++ {
		q.Set("p", strconv.Itoa(page))
		q.Set("ps", strconv.Itoa(sonarPageSize))
		body, err := c.get(ctx, token, path, q)
		if err != nil {
			return err
		}
		paging, n, err := add(body)
		if err != nil {
			return err
		}
		if paging.Total > sonarSearchCap {
			return &sonarError{fmt.Sprintf("SonarQube counts %d %s, more than the %d its search returns",
				paging.Total, what, sonarSearchCap)}
		}
		read += n
		if n == 0 || read >= paging.Total {
			return nil
		}
	}
}

// sonarComponent is a file or the project, as a search lists it beside its results.
type sonarComponent struct {
	Key  string `json:"key"`
	Path string `json:"path"`
}

// sonarComment is a comment a person left on an issue.
type sonarComment struct {
	Login     string `json:"login"`
	Markdown  string `json:"markdown"`
	CreatedAt string `json:"createdAt"`
}

// sonarImpact is one of the software qualities an issue affects, and how severely.
type sonarImpact struct {
	SoftwareQuality string `json:"softwareQuality"`
	Severity        string `json:"severity"`
}

// sonarTextRange is where in its file a result is.
type sonarTextRange struct {
	StartLine int `json:"startLine"`
	EndLine   int `json:"endLine"`
}

// sonarIssue is one issue as api/issues/search returns it.
type sonarIssue struct {
	Key          string          `json:"key"`
	Rule         string          `json:"rule"`
	Component    string          `json:"component"`
	Organization string          `json:"organization"`
	Line         int             `json:"line"`
	TextRange    *sonarTextRange `json:"textRange"`
	Message      string          `json:"message"`
	// Impacts are the qualities the issue affects, SECURITY among them for a security issue, on a
	// server of the Multi-Quality Rule mode. An older server, or one in standard mode, gives Type and
	// a legacy Severity instead.
	Impacts  []sonarImpact `json:"impacts"`
	Type     string        `json:"type"`
	Severity string        `json:"severity"`
	// IssueStatus is OPEN, CONFIRMED, ACCEPTED, FALSE_POSITIVE or FIXED. An older server gives
	// Status and Resolution instead.
	IssueStatus string         `json:"issueStatus"`
	Status      string         `json:"status"`
	Resolution  string         `json:"resolution"`
	UpdateDate  string         `json:"updateDate"`
	Comments    []sonarComment `json:"comments"`
}

// sonarImpactBands are the bands of the severities SonarQube gives an issue's security impact.
// Info, the mildest, is low, as GitLab's Info is.
var sonarImpactBands = map[string]sarif.Severity{
	"BLOCKER": sarif.SeverityCritical,
	"HIGH":    sarif.SeverityHigh,
	"MEDIUM":  sarif.SeverityMedium,
	"LOW":     sarif.SeverityLow,
	"INFO":    sarif.SeverityLow,
}

// sonarLegacyBands are the bands of the severities an issue had before impacts, which an older
// server gives in their place.
var sonarLegacyBands = map[string]sarif.Severity{
	"BLOCKER":  sarif.SeverityCritical,
	"CRITICAL": sarif.SeverityHigh,
	"MAJOR":    sarif.SeverityMedium,
	"MINOR":    sarif.SeverityLow,
	"INFO":     sarif.SeverityLow,
}

// sonarDecision is what a person decided about an issue in SonarQube, which the import honors or
// counts as its suppressions setting says.
type sonarDecision struct {
	// said is the decision as SonarQube words it, "accepted" or "marked as a false positive".
	said string
	// key is the issue, comment the latest a person left on it, and at when the issue last changed.
	key     string
	comment *sonarComment
	at      string
}

// sonarFindings are a project's findings, each with the decision a person made about it and where its
// severity came from, and the rules they are raised under.
type sonarFindings struct {
	results   []sarif.Result
	decisions []*sonarDecision
	rated     []string
	// rules are the rules the findings name, and organization the organization of the project on
	// SonarQube Cloud, which a rule is looked up in.
	rules        []string
	organization string
	// skipped counts the issues a server answered the security search with that carry no security
	// impact or type, which an older server that ignores the search's filter returns.
	skipped int
}

// scanSonarQube reads the security issues of the project a sonarqube source names and makes them
// findings.
func (s sarifImport) scanSonarQube(ctx context.Context, ft plugin.FileTarget) (sarif.Report, error) {
	fail := func(err error) (sarif.Report, error) {
		return sarif.Report{}, fmt.Errorf("%s: %s: %w", plugin.ImportScanner, ft.Identity(), err)
	}
	if netpolicy.Offline() {
		return fail(&sonarError{"an offline run does not reach SonarQube, which holds these findings"})
	}
	project := strings.TrimSpace(ft.Project)
	if project == "" {
		return fail(&sonarError{"the import names no SonarQube project. Name it with project"})
	}
	repo, err := sourceRepositoryOf(ft)
	if err != nil {
		return fail(err)
	}
	variable, token, err := sonarToken(ft)
	if err != nil {
		return fail(err)
	}
	c := s.sonar
	refusal := func(err error) error {
		var status *sonarStatus
		if errors.As(err, &status) {
			return sonarRefusal(status, variable, project, c.base)
		}
		return err
	}
	revision, err := c.analyzedRevision(ctx, token, project)
	if err != nil {
		return fail(refusal(err))
	}
	found := sonarFindings{}
	if err := c.readIssues(ctx, token, project, &found); err != nil {
		return fail(refusal(err))
	}
	rules, err := c.readRules(ctx, token, found.rules, found.organization)
	if err != nil {
		return fail(refusal(err))
	}

	rep := sarif.Report{Tool: sonarService, Rules: map[string]sarif.Rule{}}
	for i := range found.results {
		r := found.results[i]
		rule := rules[r.RuleID]
		r.CWE = rule.cwe
		r.ImportedRepository = repo.Source()
		r.ImportFormat = ft.Source
		settleSonarDecision(&r, found.decisions[i], ft)
		rep.Results = append(rep.Results, r)
		if _, ok := rep.Rules[r.RuleID]; !ok {
			rep.Rules[r.RuleID] = rule.rule
		}
	}
	commit, caveat, err := s.bindSonar(ctx, repo, revision)
	if err != nil {
		return fail(err)
	}
	if caveat != "" {
		undetermineAbsence(rep.Results)
	}
	keep, scoped := scopeImported(rep.Results, nil, ft.Repositories)
	rep.Results = keepOnly(rep.Results, keep)
	rated := keepOnly(found.rated, keep)

	read := c.now().UTC()
	fields := []sarif.Field{
		{Key: "tool", Value: sonarService},
		{Key: "source", Value: sonarService + " project " + project + " on " + c.base},
		{Key: "read", Value: read.Format("2006-01-02 15:04 UTC")},
		{Key: "severity", Value: severitySource(rep, rated, "CVSS score") + "; SonarQube gives no score"},
		{Key: "commit", Value: commit},
	}
	if ft.Component != "" {
		fields = append(fields, sarif.Field{Key: "component", Value: ft.Component})
	}
	if found.skipped > 0 {
		fields = append(fields, sarif.Field{Key: "left out", Value: english.Count(found.skipped, "issue") +
			" with no security impact, which the server returned to a search for security issues"})
	}
	fields = append(fields, scoped.fields()...)
	detail := scoped.detail()
	if caveat != "" {
		detail = append(detail, sarif.Field{Key: sarif.ImportUnbound, Value: caveat})
	}
	rep.Provenance = append(rep.Provenance, sarif.Provenance{Tool: plugin.ImportScanner, Fields: fields, Detail: detail})
	return rep, nil
}

// sonarToken reads the token from the variable the import names, or SONAR_TOKEN. A name the pipeline
// has not listed in $DRAUGR_TOKEN_ENVS is refused before anything is read, and an empty variable is
// an error rather than a request SonarQube would answer with a public project's findings or none.
func sonarToken(ft plugin.FileTarget) (variable, token string, err error) {
	name, value, err := credential.Token(ft.TokenEnv, sonarTokenEnv)
	var refused *credential.RefusedVariableError
	if errors.As(err, &refused) {
		return name, "", &sonarError{fmt.Sprintf("$%s is not listed in $%s. List it there, or use $%s",
			refused.Name, credential.TokenEnvsVar, sonarTokenEnv)}
	}
	if err != nil {
		return name, "", err
	}
	if strings.TrimSpace(value) == "" {
		return name, "", &sonarError{fmt.Sprintf("$%s is empty. Set it to a token that can browse the project", name)}
	}
	return name, strings.TrimSpace(value), nil
}

// sonarRefusal is the error for a status SonarQube answered with, naming what a reader can do about
// it. None is an empty import: each would otherwise read as a project with no findings.
func sonarRefusal(s *sonarStatus, variable, project, base string) error {
	switch s.code {
	case http.StatusUnauthorized:
		return &sonarError{fmt.Sprintf("SonarQube refused $%s as invalid or expired. Create a new one", variable)}
	case http.StatusForbidden:
		return &sonarError{fmt.Sprintf("$%s cannot browse project %s (HTTP 403)", variable, project)}
	case http.StatusNotFound:
		return &sonarError{fmt.Sprintf("%s has no project %s, or the token cannot see it (HTTP 404)", base, project)}
	}
	if s.message != "" {
		return &sonarError{fmt.Sprintf("SonarQube answered HTTP %d. %s", s.code, strings.TrimSuffix(s.message, "."))}
	}
	return s
}

// analyzedRevision is the commit the project's latest analysis read, empty where SonarQube states
// none, as for an analysis run outside a git checkout.
func (c sonarClient) analyzedRevision(ctx context.Context, token, project string) (string, error) {
	q := url.Values{}
	q.Set("project", project)
	q.Set("ps", "1")
	body, err := c.get(ctx, token, "/api/project_analyses/search", q)
	if err != nil {
		return "", err
	}
	var doc struct {
		Analyses *[]struct {
			Revision string `json:"revision"`
		} `json:"analyses"`
	}
	if err := json.Unmarshal(body, &doc); err != nil || doc.Analyses == nil {
		return "", &sonarError{"SonarQube's answer is not a list of analyses"}
	}
	if len(*doc.Analyses) == 0 {
		return "", &sonarError{fmt.Sprintf("SonarQube has no analysis of project %s yet", project)}
	}
	return strings.TrimSpace((*doc.Analyses)[0].Revision), nil
}

// readIssues reads the project's issues with a security impact: open, confirmed, accepted and false
// positive ones. A fixed issue is SonarQube's account of a flaw that is gone, and is not read. The
// server's filter is not relied on: an issue without a security impact or type is left out and
// counted, since a server that does not know the filter answers with every issue.
func (c sonarClient) readIssues(ctx context.Context, token, project string, out *sonarFindings) error {
	q := url.Values{}
	q.Set("componentKeys", project)
	q.Set("impactSoftwareQualities", "SECURITY")
	q.Set("issueStatuses", "OPEN,CONFIRMED,ACCEPTED,FALSE_POSITIVE")
	q.Set("additionalFields", "comments")
	return c.search(ctx, token, "/api/issues/search", q, "security issues", func(body []byte) (sonarPaging, int, error) {
		var page struct {
			Paging     *sonarPaging     `json:"paging"`
			Issues     *[]sonarIssue    `json:"issues"`
			Components []sonarComponent `json:"components"`
		}
		if err := json.Unmarshal(body, &page); err != nil || page.Paging == nil || page.Issues == nil {
			return sonarPaging{}, 0, &sonarError{"SonarQube's answer is not a list of issues"}
		}
		paths := sonarPaths(page.Components)
		for _, is := range *page.Issues {
			if err := out.addIssue(is, paths); err != nil {
				return sonarPaging{}, 0, err
			}
		}
		return *page.Paging, len(*page.Issues), nil
	})
}

// latestComment is the comment written last, nil where there are none.
func latestComment(comments []sonarComment) *sonarComment {
	var latest *sonarComment
	for i := range comments {
		if latest == nil || comments[i].CreatedAt >= latest.CreatedAt {
			latest = &comments[i]
		}
	}
	return latest
}

// sonarPaths maps each component's key to its path in the project, as a search lists them.
func sonarPaths(components []sonarComponent) map[string]string {
	paths := map[string]string{}
	for _, c := range components {
		paths[c.Key] = c.Path
	}
	return paths
}

// sonarPathOf is where an issue is: the path its component has, or the part of the key after the
// project's where the search listed no path. An issue on the project as a whole has none.
func sonarPathOf(component string, paths map[string]string) string {
	if p, ok := paths[component]; ok {
		return p
	}
	if _, rest, ok := strings.Cut(component, ":"); ok {
		return rest
	}
	return ""
}

// sonarLine is the first line of an issue's range, or its line where it gives no range.
func sonarLine(line int, r *sonarTextRange) int {
	if r != nil && r.StartLine > 0 {
		return r.StartLine
	}
	return line
}

// addIssue adds an issue as a finding, or counts it as left out where it is not a security issue or
// is fixed. Its severity is its security impact's, else the legacy severity an older server gives.
func (f *sonarFindings) addIssue(is sonarIssue, paths map[string]string) error {
	if strings.TrimSpace(is.Rule) == "" {
		return &sonarError{fmt.Sprintf("SonarQube's issue %s names no rule", is.Key)}
	}
	impact := ""
	for _, im := range is.Impacts {
		if im.SoftwareQuality == "SECURITY" {
			impact = im.Severity
		}
	}
	if impact == "" && (len(is.Impacts) > 0 || is.Type != "VULNERABILITY") {
		f.skipped++
		return nil
	}
	status := sonarIssueStatus(is)
	if status == "FIXED" || status == "CLOSED" {
		return nil
	}
	var band sarif.Severity
	var rating *sarif.Rating
	rated := "SonarQube's impact severity"
	if impact != "" {
		b, ok := sonarImpactBands[impact]
		if !ok {
			return &sonarError{fmt.Sprintf("issue %s has security severity %q, not one SonarQube gives", is.Key, impact)}
		}
		band = b
		rating = newRating(band, map[string]string{"impact": impact}, "SonarQube security impact "+strings.ToLower(impact))
	} else {
		b, ok := sonarLegacyBands[is.Severity]
		if !ok {
			return &sonarError{fmt.Sprintf("issue %s has severity %q, not one SonarQube gives", is.Key, is.Severity)}
		}
		band = b
		rated = "SonarQube's severity"
		rating = newRating(band, map[string]string{"severity": is.Severity}, "SonarQube "+strings.ToLower(is.Severity))
	}
	r := sarif.Result{
		Tool:     sonarService,
		RuleID:   is.Rule,
		Level:    osvLevel(band),
		Message:  strings.TrimSpace(is.Message),
		Location: sarif.Location{URI: sonarPathOf(is.Component, paths), StartLine: sonarLine(is.Line, is.TextRange)},
		Rating:   rating,
	}
	var d *sonarDecision
	switch status {
	case "ACCEPTED":
		d = &sonarDecision{said: "accepted", key: is.Key, at: is.UpdateDate, comment: latestComment(is.Comments)}
	case "FALSE_POSITIVE":
		d = &sonarDecision{said: "marked as a false positive", key: is.Key, at: is.UpdateDate, comment: latestComment(is.Comments)}
	}
	f.add(r, d, rated, is.Organization)
	return nil
}

// sonarIssueStatus is an issue's status: IssueStatus, or on an older server the one its status and
// resolution name.
func sonarIssueStatus(is sonarIssue) string {
	if is.IssueStatus != "" {
		return is.IssueStatus
	}
	switch is.Resolution {
	case "WONTFIX":
		return "ACCEPTED"
	case "FALSE-POSITIVE":
		return "FALSE_POSITIVE"
	case "FIXED", "REMOVED":
		return "FIXED"
	}
	return cmp.Or(is.Status, "OPEN")
}

// add appends a finding, the decision about it and where its severity came from, and notes its rule.
func (f *sonarFindings) add(r sarif.Result, d *sonarDecision, rated, organization string) {
	f.results = append(f.results, r)
	f.decisions = append(f.decisions, d)
	f.rated = append(f.rated, rated)
	if !slices.Contains(f.rules, r.RuleID) {
		f.rules = append(f.rules, r.RuleID)
	}
	if f.organization == "" {
		f.organization = organization
	}
}

// sonarRule is a rule as the findings carry it: its name and help, and the CWEs it is classified
// under.
type sonarRule struct {
	rule sarif.Rule
	cwe  []string
}

// readRules looks up each rule once, for its name and the CWEs SonarQube classifies it under, so a
// finding carries its CWE as a native one does. SonarQube Cloud states a rule's CWEs in its security
// standards and looks a rule up in the organization the project belongs to; SonarQube Server's answer
// has no security standards, so its findings carry no CWE.
func (c sonarClient) readRules(ctx context.Context, token string, keys []string, organization string) (map[string]sonarRule, error) {
	out := map[string]sonarRule{}
	for _, key := range keys {
		q := url.Values{}
		q.Set("key", key)
		if organization != "" {
			q.Set("organization", organization)
		}
		body, err := c.get(ctx, token, "/api/rules/show", q)
		var status *sonarStatus
		if errors.As(err, &status) && status.code == http.StatusNotFound {
			return nil, &sonarError{fmt.Sprintf("SonarQube has no rule %s, which an issue names (HTTP 404)", key)}
		}
		if err != nil {
			return nil, err
		}
		var doc struct {
			Rule *struct {
				Name              string   `json:"name"`
				SecurityStandards []string `json:"securityStandards"`
			} `json:"rule"`
		}
		if err := json.Unmarshal(body, &doc); err != nil || doc.Rule == nil {
			return nil, &sonarError{fmt.Sprintf("SonarQube's answer for rule %s is not a rule", key)}
		}
		r := sonarRule{rule: sarif.Rule{Name: key, ShortDescription: strings.TrimSpace(doc.Rule.Name)}}
		for _, std := range doc.Rule.SecurityStandards {
			if n, ok := strings.CutPrefix(std, "cwe:"); ok {
				if _, err := strconv.Atoi(n); err == nil && !slices.Contains(r.cwe, "CWE-"+n) {
					r.cwe = append(r.cwe, "CWE-"+n)
				}
			}
		}
		out[key] = r
	}
	return out, nil
}

// settleSonarDecision sets aside or counts a finding a person accepted or marked as a false positive
// in SonarQube, as the import's suppressions setting says: set aside by default, with the latest
// comment as the reason and its writer, and counted under suppressions: count with the same in its
// detail.
func settleSonarDecision(r *sarif.Result, d *sonarDecision, ft plugin.FileTarget) {
	if d == nil {
		return
	}
	reason := d.said + " in SonarQube"
	author, at := "", d.at
	if d.comment != nil && strings.TrimSpace(d.comment.Markdown) != "" {
		reason += ": " + strings.Join(strings.Fields(d.comment.Markdown), " ")
		author = d.comment.Login
	}
	if ft.CountSuppressed {
		r.Detail = strings.TrimPrefix(r.Detail+" · "+sarif.GivenReason(reason)+
			" · counted, as the import says suppressions: count", " · ")
		return
	}
	r.Suppression = &sarif.Suppression{
		Kind:          "external",
		Origin:        sarif.OriginScanner,
		Justification: reason,
		Author:        author,
		Asserted:      at,
		Source:        d.key,
		Service:       sonarService,
	}
}

// bindSonar holds the project's findings to the commit this run reads: the commit SonarQube's latest
// analysis read, where it states one and it is this run's, binds them. Another commit, or none, leaves
// the import unbound and says why, keeping every finding, since nothing ties them to this code and
// nothing is ranked lower for an absence.
func (s sarifImport) bindSonar(ctx context.Context, repo plugin.RepositoryTarget, revision string) (commit, caveat string, err error) {
	if revision == "" {
		return notStated + " · SonarQube's analysis names no commit",
			"SonarQube's latest analysis names no commit, so nothing ties it to this code", nil
	}
	at := repo.Revision
	if repo.WorkingTree {
		at = ""
	}
	here, err := s.resolve(ctx, repo.URL, at)
	if err != nil {
		return "", "", fmt.Errorf("the commit this run reads could not be resolved, so SonarQube's findings cannot be held to it: %w", err)
	}
	if !sameCommit(revision, here) {
		return fmt.Sprintf("%s · SonarQube analyzed %s; this run reads %s", notStated, short(revision), short(here)),
			fmt.Sprintf("SonarQube analyzed %s, so its findings may not describe this commit", short(revision)), nil
	}
	return short(here), "", nil
}

// sourceRepositoryOf is the component's repository a source's findings belong to: the one the import
// names by owner/name, which has to be one of the component's, or the component's one repository.
func sourceRepositoryOf(ft plugin.FileTarget) (plugin.RepositoryTarget, error) {
	repos := ft.Repositories
	if len(repos) == 0 {
		return plugin.RepositoryTarget{}, &sonarError{fmt.Sprintf("component %s declares no repository to read findings for", ft.Component)}
	}
	if ft.Repository == "" || singleCheckout(repos) {
		if !singleCheckout(repos) {
			return plugin.RepositoryTarget{}, &sonarError{"the component has several repositories. Name one with repository"}
		}
		return repos[0], nil
	}
	for _, r := range repos {
		source := strings.TrimSuffix(strings.TrimSuffix(r.Source(), "/"), ".git")
		if strings.HasSuffix(strings.ToLower(source), "/"+strings.ToLower(ft.Repository)) {
			return r, nil
		}
	}
	return plugin.RepositoryTarget{}, &sonarError{fmt.Sprintf("%s is not one of the repositories of component %s",
		ft.Repository, ft.Component)}
}

// sonarSourceCheck says whether a sonarqube import has its token to send, for doctor, and which server
// it goes to. Nothing is sent. The detail never holds the token.
func sonarSourceCheck(ft plugin.FileTarget) (detail string, ok bool) {
	name, _, err := sonarToken(ft)
	if err != nil {
		return err.Error(), false
	}
	host := strings.TrimSuffix(cmp.Or(strings.TrimSpace(os.Getenv(sonarHostEnv)), sonarCloud), "/")
	if _, err := credential.Origin(host); err != nil {
		return "$" + sonarHostEnv + " is not an http or https address", false
	}
	return "token in $" + name + ", findings read from " + host + " by the scan", true
}

// isSonarSource reports whether ft reads SonarQube.
func isSonarSource(ft plugin.FileTarget) bool { return ft.Source == saga.ImportSourceSonarQube }
