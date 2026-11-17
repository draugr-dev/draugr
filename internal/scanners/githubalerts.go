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
	"regexp"
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

// An import may read a repository's alerts from GitHub instead of a file: its code-scanning alerts,
// or its Dependabot alerts. Both are read from GitHub's REST API with a token the descriptor names
// the variable of, and turned into findings the way a file's are: ranked by the component's exposure
// and criticality, placed in the repository they are about, and set aside where a person dismissed
// them, as the descriptor's suppressions setting says.
//
// What the two APIs carry differs, and the findings say so. A code-scanning alert carries a rule, a
// location and a severity bucket, with no score, package, aliases or fixed version. A Dependabot
// alert carries the advisory, its CVE, a CVSS score, the package and its manifest, and the first
// patched version. Dependabot's API is in public preview and subject to change.

// githubTokenEnv is the variable a source's token is read from where the import names none.
//
// #nosec G101 -- the name of an environment variable, not a credential.
const githubTokenEnv = "GITHUB_TOKEN"

// githubAPIVersion is the REST API version Draugr asks for, the one the recorded responses its tests
// read were answered in.
const githubAPIVersion = "2026-03-10"

// githubPerPage is the most alerts GitHub returns in one page.
const githubPerPage = 100

// The services as a reader is told them, by the source that names each.
var githubServices = map[string]string{
	saga.ImportSourceGitHubCodeScanning: "GitHub code scanning",
	saga.ImportSourceGitHubDependabot:   "Dependabot",
}

// githubStates are the alert states each source reads. A fixed alert is GitHub's account of a flaw
// that is gone, and is not read.
var githubStates = map[string][]string{
	saga.ImportSourceGitHubCodeScanning: {"open", "dismissed"},
	saga.ImportSourceGitHubDependabot:   {"open", "dismissed", "auto_dismissed"},
}

// githubClient reads alerts from GitHub's REST API.
type githubClient struct {
	// base is the API's address: $GITHUB_API_URL, which a GitHub Enterprise Server pipeline sets, or
	// https://api.github.com.
	base string
	// http sends the requests. It refuses to take the token to another origin on a redirect.
	http *http.Client
	// sleep waits out a rate limit, and now is the clock its reset time is read against. Injectable
	// for tests.
	sleep func(ctx context.Context, d time.Duration) error
	now   func() time.Time
}

// githubMaxWait is the longest one wait for a rate limit is allowed to be, and githubAttempts how
// many times one page is asked for. GitHub asks a client it has limited to wait at least a minute
// where it names no time, and a limit lasting longer than this is reported instead of waited out.
const (
	githubMaxWait  = 2 * time.Minute
	githubAttempts = 3
	// githubDefaultWait is the wait for a limited answer that names none, the minute GitHub's
	// documentation asks for.
	githubDefaultWait = time.Minute
)

// newGitHubClient is the client a scan uses.
func newGitHubClient() githubClient {
	return githubClient{
		base: strings.TrimSuffix(cmp.Or(os.Getenv("GITHUB_API_URL"), "https://api.github.com"), "/"),
		http: credential.Client(&http.Client{Timeout: time.Minute}),
		sleep: func(ctx context.Context, d time.Duration) error {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-t.C:
				return nil
			}
		},
		now: time.Now,
	}
}

// githubError is a refusal from GitHub, worded for the errors block: one clause, no colon inside
// it, within 80 columns.
type githubError struct{ reason string }

func (e *githubError) Error() string { return e.reason }

// scanGitHub reads the alerts a source import names and makes them findings.
func (s sarifImport) scanGitHub(ctx context.Context, ft plugin.FileTarget) (sarif.Report, error) {
	fail := func(err error) (sarif.Report, error) {
		return sarif.Report{}, fmt.Errorf("%s: %s: %w", plugin.ImportScanner, ft.Identity(), err)
	}
	service := githubServices[ft.Source]
	if service == "" {
		return fail(fmt.Errorf("source %s is not one of %s", ft.Source, strings.Join(saga.ImportSources, ", ")))
	}
	if netpolicy.Offline() {
		return fail(&githubError{"an offline run does not reach GitHub, which holds these alerts"})
	}
	ownerName, repo, err := githubRepositoryOf(ft)
	if err != nil {
		return fail(err)
	}
	variable, token, err := githubToken(ft)
	if err != nil {
		return fail(err)
	}
	var raw []json.RawMessage
	for _, state := range githubStates[ft.Source] {
		page, err := s.github.list(ctx, token, githubPath(ft.Source, ownerName), state)
		var status *githubStatus
		if errors.As(err, &status) {
			err = githubRefusal(status, githubAsked{variable: variable, source: ft.Source, repository: ownerName})
		}
		if err != nil {
			return fail(err)
		}
		raw = append(raw, page...)
	}
	read := time.Now().UTC()
	if s.github.now != nil {
		read = s.github.now().UTC()
	}

	var alerts githubAlerts
	switch ft.Source {
	case saga.ImportSourceGitHubCodeScanning:
		alerts, err = readCodeScanningAlerts(raw)
	default:
		alerts, err = readDependabotAlerts(raw)
	}
	if err != nil {
		return fail(err)
	}

	bound, err := s.bindAlerts(ctx, ft, repo, alerts)
	if err != nil {
		return fail(err)
	}
	alerts = alerts.only(bound.keep)
	revision := bound.commit

	rep := sarif.Report{Tool: service}
	for i := range alerts.results {
		r := alerts.results[i]
		r.ImportedRepository = repo.Source()
		r.ImportFormat = ft.Source
		settleDismissal(&r, alerts.dismissals[i], ft, service)
		rep.Results = append(rep.Results, r)
	}
	if strings.HasPrefix(revision, notStated) {
		undetermineAbsence(rep.Results)
	}
	keep, scoped := scopeImported(rep.Results, nil, ft.Repositories)
	rep.Results = keepOnly(rep.Results, keep)
	rated := keepOnly(alerts.rated, keep)

	fields := []sarif.Field{
		{Key: "tool", Value: cmp.Or(alertTools(alerts.meta), service)},
		{Key: "source", Value: service + " alerts for " + ownerName},
		{Key: "read", Value: read.Format("2006-01-02 15:04 UTC")},
		{Key: "severity", Value: alertSeverity(rep, rated, ft.Source)},
		{Key: "commit", Value: revision},
	}
	if len(bound.elsewhere) > 0 {
		// Named under --evidence only (pkg/report): the commit field's count is what a reader needs
		// to see, and the names are what one checking it needs.
		fields = append(fields, sarif.Field{Key: sarif.ImportAnalysesElsewhere,
			Value: english.And(bound.elsewhere) + " last ran at another commit"})
	}
	if ft.Component != "" {
		fields = append(fields, sarif.Field{Key: "component", Value: ft.Component})
	}
	if bound.stale > 0 {
		fields = append(fields, sarif.Field{Key: "left out", Value: english.Count(bound.stale, "dismissed alert") +
			" not counted: GitHub last saw " + english.Choose(bound.stale, "it", "them") + " at another commit"})
	}
	if ft.Source == saga.ImportSourceGitHubDependabot {
		fields = append(fields, sarif.Field{Key: "api", Value: "Dependabot's alerts API is in public preview and subject to change"})
	}
	fields = append(fields, scoped.fields()...)
	detail := scoped.detail()
	if bound.caveat != "" {
		detail = append(detail, sarif.Field{Key: sarif.ImportUnbound, Value: bound.caveat})
	}
	rep.Provenance = append(rep.Provenance, sarif.Provenance{Tool: plugin.ImportScanner, Fields: fields, Detail: detail})
	return rep, nil
}

// alertTools names the tools whose analyses raised the alerts, each once with its versions, in the
// order the alerts name them: `Draugr 0.181.1, Scorecard v5.6.0, Semgrep OSS`. A tool some of whose
// alerts name no version is not listed again without one.
func alertTools(meta importLog) string {
	var names []string
	versions := map[string][]string{}
	for _, run := range meta.Runs {
		d := run.Tool.Driver
		name := cmp.Or(d.Name, "an unnamed tool")
		if !slices.Contains(names, name) {
			names = append(names, name)
		}
		if v := cmp.Or(d.Version, d.SemanticVersion); v != "" && !slices.Contains(versions[name], v) {
			versions[name] = append(versions[name], v)
		}
	}
	out := make([]string, 0, len(names))
	for _, name := range names {
		if vs := versions[name]; len(vs) > 0 {
			name += " " + strings.Join(vs, " and ")
		}
		out = append(out, name)
	}
	return strings.Join(out, ", ")
}

// SourceCheck says whether an import of a service's alerts has its token to send, for doctor: the
// variable it names may be read and is set. Nothing is sent, so the token's scope and the
// repository's settings are left to the scan, which names what GitHub refused. The detail never holds
// the token.
func SourceCheck(ft plugin.FileTarget) (detail string, ok bool) {
	name, _, err := githubToken(ft)
	if err != nil {
		return err.Error(), false
	}
	return "token in $" + name + ", alerts read by the scan", true
}

// githubPath is the API path of a repository's alerts for a source.
func githubPath(source, ownerName string) string {
	if source == saga.ImportSourceGitHubCodeScanning {
		return "/repos/" + ownerName + "/code-scanning/alerts"
	}
	return "/repos/" + ownerName + "/dependabot/alerts"
}

// githubToken reads the token from the variable the import names, or GITHUB_TOKEN. A name the
// pipeline has not listed in $DRAUGR_TOKEN_ENVS is refused before anything is read, and an empty
// variable is an error rather than a request GitHub would answer with less.
func githubToken(ft plugin.FileTarget) (variable, token string, err error) {
	name, value, err := credential.Token(ft.TokenEnv, githubTokenEnv)
	var refused *credential.RefusedVariableError
	if errors.As(err, &refused) {
		return name, "", &githubError{fmt.Sprintf("$%s is not listed in $%s. List it there, or use $%s",
			refused.Name, credential.TokenEnvsVar, githubTokenEnv)}
	}
	if err != nil {
		return name, "", err
	}
	if strings.TrimSpace(value) == "" {
		return name, "", &githubError{fmt.Sprintf("$%s is empty. Set it to a token that can read security alerts", name)}
	}
	return name, strings.TrimSpace(value), nil
}

// githubRepositoryOf is the repository a source reads, as owner/name, and the component's repository
// it is.
//
// Named by the import where it names one, which has to be one of the component's repositories, and
// otherwise by the address of the component's one repository, which has to be on github.com. A
// component of several repositories has to name one, which validate already asks for: the alerts of
// one would otherwise be read as another's.
func githubRepositoryOf(ft plugin.FileTarget) (string, plugin.RepositoryTarget, error) {
	repos := ft.Repositories
	if len(repos) == 0 {
		return "", plugin.RepositoryTarget{}, &githubError{fmt.Sprintf("component %s declares no repository to read alerts for", ft.Component)}
	}
	if ft.Repository != "" {
		if singleCheckout(repos) {
			return ft.Repository, repos[0], nil
		}
		for _, r := range repos {
			if name, ok := githubName(r.Source()); ok && strings.EqualFold(name, ft.Repository) {
				return name, r, nil
			}
		}
		return "", plugin.RepositoryTarget{}, &githubError{fmt.Sprintf("%s is not one of the repositories of component %s",
			ft.Repository, ft.Component)}
	}
	if !singleCheckout(repos) {
		return "", plugin.RepositoryTarget{}, &githubError{"the component has several repositories. Name one with repository"}
	}
	name, ok := githubName(repos[0].Source())
	if !ok {
		return "", plugin.RepositoryTarget{}, &githubError{"its address names no github.com repository. Name one with repository"}
	}
	return name, repos[0], nil
}

// githubName is the owner/name of a repository source on github.com.
func githubName(source string) (string, bool) {
	rest, ok := strings.CutPrefix(source, "https://github.com/")
	if !ok {
		return "", false
	}
	parts := strings.Split(rest, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", false
	}
	return rest, true
}

// list reads every page of a repository's alerts in one state.
//
// No ref is asked for. GitHub answers a ref it has no analysis of with an empty list, the same answer
// as a repository with no alerts, so the default branch's alerts are read and held to the commit this
// run reads instead (bindAlerts).
func (c githubClient) list(ctx context.Context, token, path, state string) ([]json.RawMessage, error) {
	q := url.Values{}
	q.Set("state", state)
	q.Set("per_page", strconv.Itoa(githubPerPage))
	next := c.base + path + "?" + q.Encode()
	origin, err := credential.Origin(c.base)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []json.RawMessage
	for next != "" {
		// A page's next link is followed only on the API's own origin, since the token goes with it.
		if o, err := credential.Origin(next); err != nil || o != origin {
			return nil, &githubError{"GitHub's next page is on another host, so the token is not sent there"}
		}
		if seen[next] {
			return nil, &githubError{"GitHub's next page repeats a page already read"}
		}
		seen[next] = true
		body, link, err := c.get(ctx, token, next)
		if err != nil {
			return nil, err
		}
		var page []json.RawMessage
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, &githubError{"GitHub's answer is not a list of alerts"}
		}
		out = append(out, page...)
		next = nextLink(link)
	}
	return out, nil
}

// get asks for one page, waiting out a rate limit GitHub names where it is short enough, and returns
// the body and the Link header.
func (c githubClient) get(ctx context.Context, token, target string) ([]byte, string, error) {
	for attempt := 1; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			return nil, "", err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", githubAPIVersion)
		if err := credential.Guard(req); err != nil {
			return nil, "", err
		}
		resp, err := c.http.Do(req)
		if err != nil {
			// The URL without its query, which holds nothing secret but makes a long line.
			return nil, "", &githubError{"GitHub did not answer. " + strings.TrimSpace(transportReason(err))}
		}
		body, rerr := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
		_ = resp.Body.Close()
		if rerr != nil {
			return nil, "", rerr
		}
		if resp.StatusCode == http.StatusOK {
			return body, resp.Header.Get("Link"), nil
		}
		wait, limited := c.rateLimitWait(resp)
		if !limited {
			var msg struct {
				Message string `json:"message"`
			}
			_ = json.Unmarshal(body, &msg)
			return nil, "", &githubStatus{code: resp.StatusCode, message: msg.Message}
		}
		if attempt >= githubAttempts {
			return nil, "", &githubError{fmt.Sprintf("GitHub kept limiting requests after %d tries (HTTP %d)", attempt, resp.StatusCode)}
		}
		if wait > githubMaxWait {
			return nil, "", &githubError{fmt.Sprintf("GitHub's rate limit lasts until %s (HTTP %d)",
				c.clock().Add(wait).UTC().Format("15:04 UTC"), resp.StatusCode)}
		}
		slog.DebugContext(ctx, "waiting out GitHub's rate limit", "wait", wait, "attempt", attempt)
		if err := c.sleep(ctx, wait); err != nil {
			return nil, "", err
		}
	}
}

// clock is the client's now.
func (c githubClient) clock() time.Time {
	if c.now == nil {
		return time.Now()
	}
	return c.now()
}

// rateLimitWait reads how long a refused answer asks the client to wait, and whether it is a rate
// limit at all: retry-after where GitHub sends it, else the reset time it sends with
// x-ratelimit-remaining 0, else a minute for a 429. A 403 with neither is a permission refusal.
func (c githubClient) rateLimitWait(resp *http.Response) (time.Duration, bool) {
	if resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusTooManyRequests {
		return 0, false
	}
	if d, ok := retryAfter(resp.Header.Get("Retry-After"), c.clock()); ok {
		return d, true
	}
	if resp.Header.Get("X-Ratelimit-Remaining") == "0" {
		if reset, err := strconv.ParseInt(resp.Header.Get("X-Ratelimit-Reset"), 10, 64); err == nil {
			return max(time.Unix(reset, 0).Sub(c.clock()), 0), true
		}
		return githubDefaultWait, true
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		return githubDefaultWait, true
	}
	return 0, false
}

// retryAfter reads the header in both forms HTTP allows: a count of seconds, or a date.
func retryAfter(v string, now time.Time) (time.Duration, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, false
	}
	if secs, err := strconv.Atoi(v); err == nil {
		return time.Duration(max(secs, 0)) * time.Second, true
	}
	if when, err := http.ParseTime(v); err == nil {
		return max(when.Sub(now), 0), true
	}
	return 0, false
}

// githubStatus is a status GitHub answered with in place of the alerts, and its message, which
// scanGitHub words as an error naming the variable and the repository (githubRefusal).
type githubStatus struct {
	code    int
	message string
}

func (e *githubStatus) Error() string {
	return fmt.Sprintf("GitHub answered HTTP %d in place of the alerts", e.code)
}

// githubAsked is what a request for alerts was about, which an error names.
type githubAsked struct {
	// variable holds the token, source is the import's, and repository is owner/name.
	variable, source, repository string
}

// githubRefusal is the error for a status GitHub answered with in place of the alerts, naming what a
// reader can do about it. None is an empty import: each would otherwise read as a repository with no
// alerts, a missing analysis included.
//
// A 403 is read by its message only for the source whose page states it: "Code Security must be
// enabled" for code scanning, recorded from GitHub, and "Dependabot alerts are disabled" for
// Dependabot. Any other 403 is the token lacking access.
func githubRefusal(s *githubStatus, asked githubAsked) error {
	text := strings.ToLower(s.message)
	codeScanning := asked.source == saga.ImportSourceGitHubCodeScanning
	switch {
	case s.code == http.StatusUnauthorized:
		return &githubError{fmt.Sprintf("GitHub refused $%s as invalid or expired. Create a new one", asked.variable)}
	case s.code == http.StatusForbidden && !codeScanning && strings.Contains(text, "dependabot alerts are disabled"):
		return &githubError{"Dependabot alerts are off. Turn them on in Settings, Code security (HTTP 403)"}
	case s.code == http.StatusForbidden && codeScanning && strings.Contains(text, "must be enabled") &&
		(strings.Contains(text, "code security") || strings.Contains(text, "advanced security")):
		return &githubError{"Code Security is off. Turn it on in the repository's settings (HTTP 403)"}
	case s.code == http.StatusForbidden:
		return &githubError{"a classic token needs security_events, or public_repo if public (HTTP 403)"}
	case s.code == http.StatusNotFound && codeScanning && strings.Contains(text, "no analysis"):
		return &githubError{fmt.Sprintf("GitHub has no code-scanning analysis of %s (HTTP 404)", asked.repository)}
	case s.code == http.StatusNotFound:
		return &githubError{fmt.Sprintf("no repository %s, or the token cannot see it (HTTP 404)", asked.repository)}
	}
	return s
}

// transportReason is why a request got no answer, without the URL, which net/http puts in front.
func transportReason(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "No answer before the timeout"
	}
	msg := err.Error()
	if i := strings.LastIndex(msg, ": "); i >= 0 {
		msg = msg[i+2:]
	}
	return msg
}

// linkNext finds the next page in a Link header.
var linkNext = regexp.MustCompile(`<([^>]+)>\s*;\s*rel="next"`)

// nextLink is the next page's address in a Link header, empty on the last page.
func nextLink(header string) string {
	for _, part := range strings.Split(header, ",") {
		if m := linkNext.FindStringSubmatch(part); m != nil {
			return m[1]
		}
	}
	return ""
}

// githubAlerts are a source's alerts as findings, each with what dismissed it and the commit GitHub
// last saw it at.
type githubAlerts struct {
	results    []sarif.Result
	dismissals []*githubDismissal
	// commits is the commit each alert was last seen at, empty for a source that names none, and
	// analyses the analysis that saw it, its tool and category, which GitHub runs and keeps apart.
	commits, analyses []string
	// open marks the alerts that are open.
	open []bool
	// rated names the rating each result's severity was read from.
	rated []string
	// meta names the tools that wrote the alerts, for the provenance's tool field.
	meta importLog
}

// only is the alerts whose keep entry is true.
func (a githubAlerts) only(keep []bool) githubAlerts {
	return githubAlerts{
		results: keepOnly(a.results, keep), dismissals: keepOnly(a.dismissals, keep),
		commits: keepOnly(a.commits, keep), analyses: keepOnly(a.analyses, keep),
		open: keepOnly(a.open, keep), rated: keepOnly(a.rated, keep),
		meta: a.meta,
	}
}

// githubDismissal is what GitHub recorded about an alert it lists as dismissed: by a person, with
// their reason and comment, by an account that is not one, or by one of GitHub's own rules.
type githubDismissal struct {
	by, reason, comment, at, alert string
	// auto marks an alert GitHub dismissed by a rule, which no person looked at.
	auto bool
	// person marks a dismissal by an account GitHub types User. A bot's, a workflow's, or one whose
	// account states no type is not a person's decision about the finding.
	person bool
}

// githubUser is the account an alert names.
type githubUser struct {
	Login string `json:"login"`
	// Type is the account's kind, User for a person and Bot for an app such as github-actions[bot].
	Type string `json:"type"`
}

// githubDismissed is the dismissal fields both kinds of alert share.
type githubDismissed struct {
	State            string      `json:"state"`
	HTMLURL          string      `json:"html_url"`
	DismissedBy      *githubUser `json:"dismissed_by"`
	DismissedAt      *string     `json:"dismissed_at"`
	DismissedReason  *string     `json:"dismissed_reason"`
	DismissedComment *string     `json:"dismissed_comment"`
}

// dismissal is what the alert records about being dismissed, nil for an open one.
func (d githubDismissed) dismissal() *githubDismissal {
	switch d.State {
	case "dismissed":
	case "auto_dismissed":
		return &githubDismissal{auto: true, alert: d.HTMLURL}
	default:
		return nil
	}
	out := &githubDismissal{alert: d.HTMLURL}
	if d.DismissedBy != nil {
		// Only an account GitHub types User is a person. No type is not assumed to be one.
		out.by, out.person = d.DismissedBy.Login, d.DismissedBy.Type == "User"
	}
	if d.DismissedReason != nil {
		out.reason = strings.ReplaceAll(*d.DismissedReason, "_", " ")
	}
	if d.DismissedComment != nil {
		out.comment = strings.TrimSpace(*d.DismissedComment)
	}
	if d.DismissedAt != nil {
		if t, err := time.Parse(time.RFC3339, *d.DismissedAt); err == nil {
			out.at = t.UTC().Format("2006-01-02")
		}
	}
	return out
}

// justification is the reason and the comment, as one reason a reader is shown.
func (d githubDismissal) justification() string {
	switch {
	case d.reason != "" && d.comment != "":
		return d.reason + " (" + d.comment + ")"
	case d.reason != "":
		return d.reason
	}
	return d.comment
}

// codeScanningAlert is the part of a code-scanning alert the import reads.
type codeScanningAlert struct {
	githubDismissed
	Rule struct {
		ID                    string `json:"id"`
		Severity              string `json:"severity"`
		SecuritySeverityLevel string `json:"security_severity_level"`
		Description           string `json:"description"`
	} `json:"rule"`
	Tool struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"tool"`
	MostRecentInstance struct {
		CommitSHA string `json:"commit_sha"`
		Category  string `json:"category"`
		Message   struct {
			Text string `json:"text"`
		} `json:"message"`
		Location struct {
			Path      string `json:"path"`
			StartLine int    `json:"start_line"`
		} `json:"location"`
	} `json:"most_recent_instance"`
}

// githubNoFile is the path a code-scanning alert carries where its tool named no file, as GitHub
// returns an OpenSSF Scorecard alert about the whole repository. Read as no location: as a path it
// would be placed outside every component's paths and left out.
const githubNoFile = "no file associated with this alert"

// codeScanningLevels is the SARIF level each of a rule's severities is, the values GitHub lists for
// rule.severity.
var codeScanningLevels = map[string]sarif.Level{
	"error":   sarif.LevelError,
	"warning": sarif.LevelWarning,
	"note":    sarif.LevelNote,
	"none":    sarif.LevelNote,
}

// The ratings an alert's severity is read from, as the provenance names them.
const (
	ratedSecuritySeverity = "security_severity_level"
	ratedRuleSeverity     = "rule.severity"
	ratedAdvisorySeverity = "the advisory's severity"
)

// readCodeScanningAlerts makes a finding of each code-scanning alert.
//
// Its severity is the alert's security_severity_level where the rule has one, the bucket GitHub reads
// from the security-severity score the tool uploaded, and otherwise the rule's severity as a SARIF
// level. Neither is a score: GitHub returns the bucket, not the number.
func readCodeScanningAlerts(raw []json.RawMessage) (githubAlerts, error) {
	var out githubAlerts
	run := map[string]bool{}
	for _, msg := range raw {
		var a codeScanningAlert
		if err := json.Unmarshal(msg, &a); err != nil {
			return githubAlerts{}, &githubError{"GitHub's answer is not a list of code-scanning alerts"}
		}
		inst := a.MostRecentInstance
		if inst.Location.Path == githubNoFile {
			inst.Location.Path, inst.Location.StartLine = "", 0
		}
		r := sarif.Result{
			Tool:     a.Tool.Name,
			RuleID:   a.Rule.ID,
			Level:    cmp.Or(codeScanningLevels[strings.ToLower(a.Rule.Severity)], sarif.LevelWarning),
			Message:  cmp.Or(strings.TrimSpace(inst.Message.Text), a.Rule.Description),
			Location: sarif.Location{URI: inst.Location.Path, StartLine: inst.Location.StartLine},
		}
		rated := ratedRuleSeverity
		if word := strings.ToLower(a.Rule.SecuritySeverityLevel); cvssRating[word] != "" {
			r.Rating = newRating(cvssRating[word], map[string]string{ratedSecuritySeverity: word}, ratedSecuritySeverity+" "+word)
			rated = ratedSecuritySeverity
		}
		out.results = append(out.results, r)
		out.dismissals = append(out.dismissals, a.dismissal())
		out.commits = append(out.commits, inst.CommitSHA)
		out.analyses = append(out.analyses, a.Tool.Name+"\x00"+inst.Category)
		out.open = append(out.open, a.State == "open")
		out.rated = append(out.rated, rated)
		tool := a.Tool.Name + "\x00" + a.Tool.Version
		if !run[tool] {
			run[tool] = true
			var ir importRun
			ir.Tool.Driver = importDriver{Name: a.Tool.Name, Version: a.Tool.Version}
			out.meta.Runs = append(out.meta.Runs, ir)
		}
	}
	return out, nil
}

// dependabotAlert is the part of a Dependabot alert the import reads.
type dependabotAlert struct {
	githubDismissed
	Dependency struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		ManifestPath string `json:"manifest_path"`
	} `json:"dependency"`
	SecurityAdvisory struct {
		GHSAID      string  `json:"ghsa_id"`
		CVEID       *string `json:"cve_id"`
		Summary     string  `json:"summary"`
		Severity    string  `json:"severity"`
		Identifiers []struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"identifiers"`
		CVSS           *cvssScore `json:"cvss"`
		CVSSSeverities struct {
			V3 *cvssScore `json:"cvss_v3"`
			V4 *cvssScore `json:"cvss_v4"`
		} `json:"cvss_severities"`
	} `json:"security_advisory"`
	SecurityVulnerability struct {
		FirstPatchedVersion *struct {
			Identifier string `json:"identifier"`
		} `json:"first_patched_version"`
	} `json:"security_vulnerability"`
}

// cvssScore is a CVSS score and the vector it was computed from.
type cvssScore struct {
	Score        float64 `json:"score"`
	VectorString *string `json:"vector_string"`
}

// scored reports whether the advisory states this score: GitHub writes a zero with no vector where
// it has none.
func (c *cvssScore) scored() bool {
	return c != nil && (c.Score > 0 || (c.VectorString != nil && *c.VectorString != ""))
}

// advisoryLevels is the SARIF level each advisory severity is, so a finding with no score still
// carries the band GitHub gave it.
var advisoryLevels = map[string]sarif.Level{
	"critical": sarif.LevelError,
	"high":     sarif.LevelError,
	"medium":   sarif.LevelWarning,
	"moderate": sarif.LevelWarning,
	"low":      sarif.LevelNote,
}

// readDependabotAlerts makes a dependency finding of each Dependabot alert: the advisory's GHSA id as
// its rule, its CVE as an alias so KEV and EPSS reach it, the CVSS score, the package and its
// manifest, and the first patched version as the fix.
//
// The score is CVSS v3 where the advisory states one, as Draugr's bands are read from v3 scores, and
// else v4, else the older single score. The EPSS the alert carries is not read: the CVE alias reaches
// Draugr's own EPSS data, so a finding is not ranked by two copies of the feed from different days.
// The alert names no installed version, so its package is never keyed for correlation with a native
// copy, which needs one.
func readDependabotAlerts(raw []json.RawMessage) (githubAlerts, error) {
	var out githubAlerts
	for _, msg := range raw {
		var a dependabotAlert
		if err := json.Unmarshal(msg, &a); err != nil {
			return githubAlerts{}, &githubError{"GitHub's answer is not a list of Dependabot alerts"}
		}
		adv := a.SecurityAdvisory
		r := sarif.Result{
			Tool:     githubServices[saga.ImportSourceGitHubDependabot],
			RuleID:   adv.GHSAID,
			Level:    cmp.Or(advisoryLevels[strings.ToLower(adv.Severity)], sarif.LevelWarning),
			Message:  cmp.Or(strings.TrimSpace(adv.Summary), adv.GHSAID),
			Location: sarif.Location{URI: a.Dependency.ManifestPath},
			Package: &sarif.Package{
				Name:      a.Dependency.Package.Name,
				Ecosystem: a.Dependency.Package.Ecosystem,
			},
		}
		if fix := a.SecurityVulnerability.FirstPatchedVersion; fix != nil {
			r.Package.FixedVersion = fix.Identifier
		}
		if adv.CVEID != nil && *adv.CVEID != "" {
			r.Aliases = append(r.Aliases, *adv.CVEID)
		}
		for _, id := range adv.Identifiers {
			if id.Value != "" && id.Value != r.RuleID && !slices.Contains(r.Aliases, id.Value) {
				r.Aliases = append(r.Aliases, id.Value)
			}
		}
		rated := ratedAdvisorySeverity
		for _, s := range []*cvssScore{adv.CVSSSeverities.V3, adv.CVSSSeverities.V4, adv.CVSS} {
			if s.scored() {
				r.Score, r.HasScore, rated = s.Score, true, ""
				break
			}
		}
		out.results = append(out.results, r)
		out.dismissals = append(out.dismissals, a.dismissal())
		out.commits = append(out.commits, "")
		out.analyses = append(out.analyses, "")
		out.open = append(out.open, a.State == "open")
		out.rated = append(out.rated, rated)
	}
	if len(out.results) > 0 {
		var ir importRun
		ir.Tool.Driver = importDriver{Name: githubServices[saga.ImportSourceGitHubDependabot]}
		out.meta.Runs = append(out.meta.Runs, ir)
	}
	return out, nil
}

// bindAlerts holds a source's alerts to the commit this run reads, as a file's provenance is held,
// and returns the commit field, which alerts to keep, and how many dismissed alerts it left out.
//
// A code-scanning alert names the commit GitHub last saw it at, and each tool's analysis, a tool and
// a category, runs on its own schedule: a weekly Scorecard analysis names an older commit than a
// scanner run on every push. So each analysis is held to this commit apart, as each run of a SARIF
// file is. An analysis with an alert seen at this commit describes this commit, and a dismissed
// alert of it last seen at another commit is one that analysis did not find here: it is left out and
// counted in the provenance. An analysis with no alert seen at this commit describes other code. Its
// alerts are kept whole, open ones counting as they are, and the import is reported unbound, since
// nothing ties them to this code; nothing in it is ranked lower for an absence.
//
// Dependabot names no commit. Its alerts describe the default branch's manifests when GitHub last
// read them, which need not be the commit this run reads, so the import is unbound and reported as
// such.
func (s sarifImport) bindAlerts(ctx context.Context, ft plugin.FileTarget, repo plugin.RepositoryTarget, a githubAlerts) (alertBinding, error) {
	b := alertBinding{keep: make([]bool, len(a.results))}
	for i := range b.keep {
		b.keep[i] = true
	}
	if ft.Source != saga.ImportSourceGitHubCodeScanning {
		b.commit = notStated + " · Dependabot alerts name no commit"
		b.caveat = "Dependabot alerts describe the default branch, not this commit"
		return b, nil
	}
	if len(a.results) == 0 {
		b.commit = notStated + " · GitHub lists no alerts"
		b.caveat = "GitHub lists no alerts, so nothing shows this commit was analyzed"
		return b, nil
	}
	revision := repo.Revision
	if repo.WorkingTree {
		revision = ""
	}
	commit, err := s.resolve(ctx, repo.URL, revision)
	if err != nil {
		return alertBinding{}, fmt.Errorf("the commit this run reads could not be resolved, so GitHub's alerts cannot be held to it: %w", err)
	}
	here := map[string]bool{}
	var analyses []string
	for i, at := range a.commits {
		if !slices.Contains(analyses, a.analyses[i]) {
			analyses = append(analyses, a.analyses[i])
		}
		if sameCommit(at, commit) {
			here[a.analyses[i]] = true
		}
	}
	for i, at := range a.commits {
		switch {
		case !here[a.analyses[i]]:
			name := analysisName(a.analyses[i])
			if !slices.Contains(b.elsewhere, name) {
				b.elsewhere = append(b.elsewhere, name)
			}
		case !sameCommit(at, commit) && !a.open[i]:
			b.keep[i] = false
			b.stale++
		}
	}
	if n := len(b.elsewhere); n > 0 {
		total := fmt.Sprintf("%d %s", len(analyses), english.Choose(len(analyses), "analysis", "analyses"))
		b.commit = fmt.Sprintf("%s · %d of %s last ran at another commit; this run reads %s",
			notStated, n, total, short(commit))
		// Within the 80 columns a caveat's reason is shown in.
		b.caveat = fmt.Sprintf("%d of %s ran at another commit; some alerts may not describe this code", n, total)
		return b, nil
	}
	b.commit = short(commit)
	return b, nil
}

// alertBinding is what holding a source's alerts to the commit this run reads made of them.
type alertBinding struct {
	// commit is the provenance's commit field: the commit, or notStated and why.
	commit string
	// caveat is the unbound-imports caveat's sentence for an unbound import, empty for a bound one.
	caveat string
	// elsewhere names the analyses GitHub last ran at another commit, which --evidence lists.
	elsewhere []string
	// keep marks the alerts kept, and stale counts the dismissed ones left out.
	keep  []bool
	stale int
}

// analysisName is an analysis as a reader is told it: the tool, and the category where it has one.
func analysisName(key string) string {
	tool, category, _ := strings.Cut(key, "\x00")
	tool = cmp.Or(tool, "an unnamed tool")
	if category == "" {
		return tool
	}
	return tool + " (" + category + ")"
}

// settleDismissal sets aside or counts an alert GitHub lists as dismissed, as the import's
// suppressions setting and the decision recorded for alerts say.
//
// A person's dismissal is honored by default, set aside with who dismissed it, their reason and
// comment, and the alert, and counted under suppressions: count with the same in its detail. An alert
// GitHub dismissed by its own rule, or one a bot or an account of no stated type dismissed, always
// counts: a rule or a workflow is not a person's decision about the finding. Its detail names who
// dismissed it, so a team sees which workflow did, and gives the config.exclude entry that sets it
// aside here, for a reader who has looked.
func settleDismissal(r *sarif.Result, d *githubDismissal, ft plugin.FileTarget, service string) {
	if d == nil {
		return
	}
	setAside := ". To set it aside, add to config.exclude " + excludeFlow(r.RuleID, r.Location.URI)
	if d.auto {
		r.Detail = strings.TrimPrefix(r.Detail+" · dismissed automatically by a GitHub rule · counted"+setAside, " · ")
		return
	}
	if !d.person {
		by := cmp.Or(d.by, "an unnamed account")
		said := fmt.Sprintf("dismissed by %s in %s · %s · counted%s", by, service, sarif.GivenReason(d.justification()), setAside)
		r.Detail = strings.TrimPrefix(r.Detail+" · "+said, " · ")
		return
	}
	if ft.CountSuppressed {
		who := "the alert was"
		if d.by != "" {
			who = d.by
		}
		said := fmt.Sprintf("%s dismissed it in %s · %s · counted, as the import says suppressions: count",
			who, service, sarif.GivenReason(d.justification()))
		r.Detail = strings.TrimPrefix(r.Detail+" · "+said, " · ")
		return
	}
	r.Suppression = &sarif.Suppression{
		Kind:          "external",
		Origin:        sarif.OriginScanner,
		Justification: d.justification(),
		Author:        d.by,
		Asserted:      d.at,
		Source:        d.alert,
		Service:       service,
	}
}

// excludeFlow is a config.exclude entry for one rule in one file, on one line, with the fields TRY's
// entry shows: rules, the file as paths, and a reason and date for the reader to fill in.
func excludeFlow(rule, path string) string {
	entry := "{rules: [" + flowScalar(rule) + "]"
	if path != "" {
		entry += ", paths: [" + flowScalar(path) + "]"
	}
	return entry + ", reason: <why it is set aside>, expires: <YYYY-MM-DD>}"
}

// plainFlowScalar is what YAML reads as itself inside a flow sequence without quoting.
var plainFlowScalar = regexp.MustCompile(`^[A-Za-z0-9_./@+-]+$`)

// flowScalar is a value as a flow sequence holds it, quoted where YAML would read it otherwise.
func flowScalar(s string) string {
	if plainFlowScalar.MatchString(s) {
		return s
	}
	return strconv.Quote(s)
}

// alertSeverity says where the findings' severities came from, and for code scanning that the alerts
// carry less than a score: a reader ranking them should know what they were ranked from.
func alertSeverity(rep sarif.Report, rated []string, source string) string {
	from := severitySource(rep, rated, "CVSS score")
	if source == saga.ImportSourceGitHubCodeScanning && len(rep.Results) > 0 {
		from += "; alerts carry no score, package, aliases or fix"
	}
	return from
}
