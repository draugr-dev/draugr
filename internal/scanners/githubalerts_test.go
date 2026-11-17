package scanners

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/draugr-dev/draugr/internal/credential"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// The responses under testdata/github-alerts were recorded once from GitHub's REST API, answered at
// API version 2026-03-10, for the public repository draugr-dev/draugr: two pages of its open
// code-scanning alerts, five per page, five of its dismissed ones, and the answers GitHub gave for a
// repository with code scanning off, one with Dependabot alerts off, and one that does not exist.
// The dismissed alerts were dismissed by the GitHub Actions bot, a published app rather than a
// person, and are kept as recorded.
//
// draugr-dev/draugr had no Dependabot alerts to record (GitHub answered an empty list, kept as
// dependabot-none.json), so dependabot-alerts-constructed.json is written in the shape GitHub's
// documentation gives an alert, with octocat standing for the person who dismissed one. The 401 is
// constructed too, since recording one needs a token GitHub refuses. Nothing here calls GitHub.

// githubAlertsCommit is the commit GitHub last saw the recorded alerts of the Draugr analysis at.
const githubAlertsCommit = "cc4899689bce4932685ea19cf8a61ce69ac6db56"

// testToken is shaped like a GitHub token and is not one.
var testToken = "ghp_" + strings.Repeat("a", 36)

// fakeGitHub answers as GitHub's alerts API does, from the recorded responses: each state's alerts
// in pages linked by a Link header, or a refusal.
type fakeGitHub struct {
	t *testing.T
	// pages are the pages served for a path and state, the first first.
	pages map[string][][]byte
	// refuse, where set, answers every request with this status, headers and body.
	refuse func(w http.ResponseWriter, r *http.Request) bool

	mu       sync.Mutex
	requests []*http.Request
}

func newFakeGitHub(t *testing.T) (*fakeGitHub, *httptest.Server) {
	f := &fakeGitHub{t: t, pages: map[string][][]byte{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, srv
}

func (f *fakeGitHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.requests = append(f.requests, r.Clone(context.Background()))
	f.mu.Unlock()
	if f.refuse != nil && f.refuse(w, r) {
		return
	}
	key := r.URL.Path + "?" + r.URL.Query().Get("state")
	pages := f.pages[key]
	page := 0
	if p := r.URL.Query().Get("page"); p != "" {
		_, _ = fmt.Sscanf(p, "%d", &page)
		page--
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if page < 0 || page >= len(pages) {
		_, _ = w.Write([]byte("[]"))
		return
	}
	if page+1 < len(pages) {
		q := r.URL.Query()
		q.Set("page", fmt.Sprint(page+2))
		w.Header().Set("Link", fmt.Sprintf(`<http://%s%s?%s>; rel="next"`, r.Host, r.URL.Path, q.Encode()))
	}
	_, _ = w.Write(pages[page])
}

// serve answers path's alerts in state with the given recorded pages.
func (f *fakeGitHub) serve(path, state string, files ...string) {
	for _, file := range files {
		f.pages[path+"?"+state] = append(f.pages[path+"?"+state], recorded(f.t, file))
	}
}

// serveByState answers path's alerts from one file, each state with the alerts in that state, as
// GitHub filters by state.
func (f *fakeGitHub) serveByState(path, file string, states ...string) {
	var all []map[string]any
	if err := json.Unmarshal(recorded(f.t, file), &all); err != nil {
		f.t.Fatal(err)
	}
	for _, state := range states {
		var in []map[string]any
		for _, a := range all {
			if a["state"] == state {
				in = append(in, a)
			}
		}
		data, err := json.Marshal(in)
		if err != nil {
			f.t.Fatal(err)
		}
		if in == nil {
			data = []byte("[]")
		}
		f.pages[path+"?"+state] = append(f.pages[path+"?"+state], data)
	}
}

// recorded reads a response under testdata/github-alerts.
func recorded(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "github-alerts", name)) // #nosec G304 -- a fixture this package holds
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// githubImport is the import scanner reading from srv, with the run reading commit and no wait for a
// rate limit actually taken: each wait is recorded instead.
func githubImport(srv *httptest.Server, commit string, waits *[]time.Duration) sarifImport {
	return sarifImport{
		resolve: func(context.Context, string, string) (string, error) { return commit, nil },
		github: githubClient{
			base: srv.URL,
			http: credential.Client(srv.Client()),
			sleep: func(_ context.Context, d time.Duration) error {
				if waits != nil {
					*waits = append(*waits, d)
				}
				return nil
			},
			now: func() time.Time { return time.Date(2026, 11, 17, 15, 0, 0, 0, time.UTC) },
		},
	}
}

// draugrRepo is a component of the one repository the recordings are of.
func draugrRepo() []plugin.RepositoryTarget {
	return []plugin.RepositoryTarget{{URL: "https://github.com/draugr-dev/draugr"}}
}

const (
	codeScanningPath = "/repos/draugr-dev/draugr/code-scanning/alerts"
	dependabotPath   = "/repos/octo-org/octo-repo/dependabot/alerts"
)

// fieldOf is the value of a provenance field the import recorded.
func fieldOf(rep sarif.Report, key string) string {
	for _, p := range rep.Provenance {
		for _, f := range p.Fields {
			if f.Key == key {
				return f.Value
			}
		}
	}
	return ""
}

// byRuleAt indexes findings by rule and line, which tell the recorded alerts apart.
func byRuleAt(rep sarif.Report) map[string]sarif.Result {
	out := map[string]sarif.Result{}
	for _, r := range rep.Results {
		out[fmt.Sprintf("%s@%s:%d", r.RuleID, r.Location.URI, r.Location.StartLine)] = r
	}
	return out
}

// Each open code-scanning alert is a finding, read across both pages GitHub links: the tool's name
// as its tool, the rule, the location of its most recent instance, and its severity from
// security_severity_level where the rule has one and from the rule's severity otherwise. Each
// dismissed alert is set aside by default, naming who dismissed it, why, and the alert. An analysis
// GitHub last ran at another commit, Scorecard's weekly one here, is kept whole, counted, and makes
// the import unbound; nothing tells a reader its alerts describe this code.
func TestCodeScanningAlertsAreFindings(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", testToken)
	f, srv := newFakeGitHub(t)
	f.serve(codeScanningPath, "open", "code-scanning-open-page1.json", "code-scanning-open-page2.json")
	f.serve(codeScanningPath, "dismissed", "code-scanning-dismissed.json")
	ft := plugin.FileTarget{Source: saga.ImportSourceGitHubCodeScanning, Component: "draugr", Repositories: draugrRepo()}

	rep, err := githubImport(srv, githubAlertsCommit, nil).Scan(context.Background(), ft, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 11 {
		t.Fatalf("got %d findings, want 6 open and 5 dismissed", len(rep.Results))
	}
	got := byRuleAt(rep)
	if r := got["CVE-2026-78661@go.mod:28"]; r.Tool != "Draugr" || r.Severity("") != sarif.SeverityHigh ||
		r.Rating == nil || r.Rating.Detail != "security_severity_level high" || r.Suppressed() || r.HasScore {
		t.Errorf("CVE-2026-78661 = %+v, want Draugr's, rated high by security_severity_level, counted, no score", r)
	}
	if r := got["GO-2026-5932@go.mod:100"]; r.Level != sarif.LevelNote || r.Rating != nil {
		t.Errorf("GO-2026-5932 = %+v, want its rule's severity note as the level", r)
	}
	// The engine stamps the scanner on every finding a job returns; stamped here as it would be.
	for k, r := range got {
		r.Scanner = plugin.ImportScanner
		got[k] = r
	}
	if r := got["go.lang.security.audit.dangerous-exec-command.dangerous-exec-command@internal/cli/configedit.go:173"]; r.Level != sarif.LevelError ||
		r.Package != nil || len(r.Aliases) != 0 || r.ImportedRepository != "https://github.com/draugr-dev/draugr" ||
		r.Reporter() != "imported Draugr (github-code-scanning)" {
		t.Errorf("semgrep alert = %+v, want error level, no package or aliases, placed in the repository", r)
	}
	if r := got["VulnerabilitiesID@:0"]; r.Tool != "Scorecard" || r.Suppressed() {
		t.Errorf("Scorecard alert = %+v, want counted with no location", r)
	}
	g := got["G304@internal/inventory/sarif.go:118"]
	if s := g.Suppression; s == nil || s.Author != "github-actions[bot]" || s.Service != "GitHub code scanning" ||
		s.Justification != "won't fix (Accepted in Draugr: a file under the tree being initialized)" ||
		s.Source != "https://github.com/draugr-dev/draugr/security/code-scanning/690" || s.Asserted != "2026-11-17" ||
		s.Origin != sarif.OriginScanner || !g.SetAsideInImport() {
		t.Errorf("G304 suppression = %+v, want set aside naming who, why, when and the alert", s)
	}
	if c := rep.Counts(); c.Error+c.Warning+c.Note != 6 {
		t.Errorf("counted %+v, want the six open alerts", c)
	}
	if v := fieldOf(rep, "commit"); v != "not stated, Scorecard (supply-chain/local) did not analyze cc4899689bce" {
		t.Errorf("commit = %q, want unbound naming the analysis of another commit", v)
	}
	if v := fieldOf(rep, "severity"); v != "rule.severity for 8, security_severity_level for 3; alerts carry no score, package, aliases or fix" ||
		!strings.HasSuffix(v, "alerts carry no score, package, aliases or fix") {
		t.Errorf("severity = %q, want where each rating came from and that alerts carry less", v)
	}
	if v := fieldOf(rep, "source"); v != "GitHub code scanning alerts for draugr-dev/draugr" {
		t.Errorf("source = %q", v)
	}
	if v := fieldOf(rep, "tool"); v != "Draugr 0.181.1, Scorecard v5.6.0" {
		t.Errorf("tool = %q", v)
	}

	var openPages int
	for _, r := range f.requests {
		if r.URL.Query().Get("state") == "open" {
			openPages++
		}
		if r.URL.Query().Get("ref") != "" || r.URL.Query().Get("per_page") != "100" {
			t.Errorf("asked %s, want 100 a page and no ref", r.URL)
		}
		if r.Header.Get("Authorization") != "Bearer "+testToken || r.Header.Get("X-GitHub-Api-Version") != githubAPIVersion {
			t.Errorf("request headers %v", r.Header)
		}
	}
	if openPages != 2 {
		t.Errorf("read %d pages of open alerts, want both pages GitHub links", openPages)
	}
}

// Where every analysis was last run at the commit this run reads, the import is bound to it, and a
// dismissed alert GitHub last saw at another commit is one this commit's analysis did not find: left
// out, and counted in the provenance. The recorded dismissed alerts are all at the analyzed commit,
// so one is moved to another commit here.
func TestCodeScanningAlertsBindToTheCommitRead(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", testToken)
	f, srv := newFakeGitHub(t)
	f.serve(codeScanningPath, "open", "code-scanning-open-page1.json")
	var dismissed []map[string]any
	if err := json.Unmarshal(recorded(t, "code-scanning-dismissed.json"), &dismissed); err != nil {
		t.Fatal(err)
	}
	dismissed[0]["most_recent_instance"].(map[string]any)["commit_sha"] = "e1cbec97985ba162effb93b8855c2b67ecb7e32d"
	moved, err := json.Marshal(dismissed)
	if err != nil {
		t.Fatal(err)
	}
	f.pages[codeScanningPath+"?dismissed"] = [][]byte{moved}
	ft := plugin.FileTarget{Source: saga.ImportSourceGitHubCodeScanning, Component: "draugr", Repositories: draugrRepo()}

	rep, err := githubImport(srv, githubAlertsCommit, nil).Scan(context.Background(), ft, nil)
	if err != nil {
		t.Fatal(err)
	}
	if v := fieldOf(rep, "commit"); v != "cc4899689bce" {
		t.Errorf("commit = %q, want bound", v)
	}
	if v := fieldOf(rep, "left out"); v != "1 dismissed alert GitHub last saw at another commit, not this one" {
		t.Errorf("left out = %q", v)
	}
	if len(rep.Results) != 9 {
		t.Errorf("got %d findings, want 5 open and 4 dismissed", len(rep.Results))
	}
	if _, ok := byRuleAt(rep)["G304@internal/inventory/sarif.go:118"]; ok {
		t.Error("the alert last seen at another commit was kept")
	}
}

// Under suppressions: count every dismissed alert counts, and its detail keeps who dismissed it, in
// which service and why, so nothing GitHub recorded is lost.
func TestCodeScanningDismissalsCountWhenAsked(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", testToken)
	f, srv := newFakeGitHub(t)
	f.serve(codeScanningPath, "open", "code-scanning-open-page1.json")
	f.serve(codeScanningPath, "dismissed", "code-scanning-dismissed.json")
	ft := plugin.FileTarget{Source: saga.ImportSourceGitHubCodeScanning, Repositories: draugrRepo(), CountSuppressed: true}

	rep, err := githubImport(srv, githubAlertsCommit, nil).Scan(context.Background(), ft, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c := rep.Counts(); c.Error+c.Warning+c.Note != 10 {
		t.Errorf("counted %+v, want all ten", c)
	}
	r := byRuleAt(rep)["G304@internal/scanners/govulncheck.go:732"]
	want := "github-actions[bot] dismissed it in GitHub code scanning · reason: won't fix (Accepted in Draugr: a go.mod " +
		"inside the checkout) · counted, as the import says suppressions: count"
	if r.Suppression != nil || r.Detail != want {
		t.Errorf("detail = %q, suppression %+v, want %q", r.Detail, r.Suppression, want)
	}
}

// Each Dependabot alert is a dependency finding: the advisory's GHSA id, its CVE as an alias so KEV
// and EPSS reach it, the CVSS score, the package and its manifest, and the first patched version as
// the fix. A person's dismissal is set aside with who and why. An alert GitHub dismissed by its own
// rule counts, and says how to set it aside here. Dependabot names no commit, so the import is
// unbound, and its API is in preview, which the provenance says.
func TestDependabotAlertsAreDependencyFindings(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", testToken)
	f, srv := newFakeGitHub(t)
	f.serveByState(dependabotPath, "dependabot-alerts-constructed.json", "open", "dismissed", "auto_dismissed")
	ft := plugin.FileTarget{Source: saga.ImportSourceGitHubDependabot, Component: "shop",
		Repositories: []plugin.RepositoryTarget{{URL: "https://github.com/octo-org/octo-repo"}}}

	rep, err := githubImport(srv, githubAlertsCommit, nil).Scan(context.Background(), ft, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := resultsByRule(rep)
	log4j := got["GHSA-jfh8-c2jp-5v3q"]
	if log4j.Tool != "Dependabot" || !log4j.HasScore || log4j.Score != 10 || log4j.Package == nil ||
		log4j.Package.Name != "org.apache.logging.log4j:log4j-core" || log4j.Package.Ecosystem != "maven" ||
		log4j.Package.FixedVersion != "2.15.0" || log4j.Location.URI != "pom.xml" ||
		len(log4j.Aliases) != 1 || log4j.Aliases[0] != "CVE-2021-44228" || log4j.Suppressed() ||
		log4j.Remediation() != sarif.RemediationUpgrade {
		t.Errorf("log4j = %+v, want the advisory, CVE alias, score, package, manifest and fix, counted", log4j)
	}
	if s := got["GHSA-35jh-r3h4-6jhm"].Suppression; s == nil || s.Author != "octocat" || s.Service != "Dependabot" ||
		s.Justification != "tolerable risk (Only the build uses this template helper)" || s.Asserted != "2026-10-02" {
		t.Errorf("lodash suppression = %+v, want octocat's dismissal with reason and comment", s)
	}
	auto := got["GHSA-xvch-5gv4-984h"]
	wantAuto := "dismissed automatically by a GitHub rule · counted. To set it aside, add to config.exclude " +
		"{rules: [GHSA-xvch-5gv4-984h], paths: [web/package-lock.json], reason: <why it is set aside>, expires: <YYYY-MM-DD>}"
	if auto.Suppressed() || auto.Detail != wantAuto {
		t.Errorf("minimist = %q (suppression %+v), want counted with %q", auto.Detail, auto.Suppression, wantAuto)
	}
	if v := fieldOf(rep, "commit"); v != "not stated, Dependabot alerts name no commit" {
		t.Errorf("commit = %q, want unbound", v)
	}
	if v := fieldOf(rep, "api"); !strings.Contains(v, "public preview") {
		t.Errorf("api = %q, want the preview named", v)
	}
	if v := fieldOf(rep, "severity"); v != "CVSS score" {
		t.Errorf("severity = %q", v)
	}
	if c := rep.Counts(); c.Error+c.Warning+c.Note != 2 {
		t.Errorf("counted %+v, want the open alert and the one GitHub dismissed itself", c)
	}
}

// The config.exclude entry an automatically dismissed alert gives is one the descriptor reads, and
// it sets that finding aside and no other.
func TestTheExcludeEntryAnAutoDismissalGivesSetsItAside(t *testing.T) {
	entry := excludeFlow("GHSA-xvch-5gv4-984h", "web/package-lock.json")
	entry = strings.NewReplacer("<why it is set aside>", "dev-only", "<YYYY-MM-DD>", "2027-01-01").Replace(entry)
	var rule saga.ExcludeRule
	if err := yaml.Unmarshal([]byte(entry), &rule); err != nil {
		t.Fatalf("%s: %v", entry, err)
	}
	if !rule.Matches("web/package-lock.json", "GHSA-xvch-5gv4-984h") || rule.Matches("package-lock.json", "GHSA-xvch-5gv4-984h") {
		t.Errorf("%+v matches the wrong findings", rule)
	}
	if got := excludeFlow("R", "dir with space/x.json"); !strings.Contains(got, `paths: ["dir with space/x.json"]`) {
		t.Errorf("%s, want a path YAML would split quoted", got)
	}
}

// Under suppressions: count a person's dismissal counts too, and the one GitHub's rule made is no
// different from the default.
func TestDependabotDismissalsCountWhenAsked(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", testToken)
	f, srv := newFakeGitHub(t)
	f.serveByState(dependabotPath, "dependabot-alerts-constructed.json", "open", "dismissed", "auto_dismissed")
	ft := plugin.FileTarget{Source: saga.ImportSourceGitHubDependabot, CountSuppressed: true,
		Repositories: []plugin.RepositoryTarget{{URL: "https://github.com/octo-org/octo-repo"}}}
	rep, err := githubImport(srv, githubAlertsCommit, nil).Scan(context.Background(), ft, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c := rep.Counts(); c.Error+c.Warning+c.Note != 3 {
		t.Errorf("counted %+v, want all three", c)
	}
	if d := resultsByRule(rep)["GHSA-35jh-r3h4-6jhm"].Detail; d != "octocat dismissed it in Dependabot · reason: tolerable risk "+
		"(Only the build uses this template helper) · counted, as the import says suppressions: count" {
		t.Errorf("detail = %q", d)
	}
}

// A repository with no alerts is read as one, and is unbound, since nothing names a commit.
func TestNoAlertsIsAnEmptyUnboundImport(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", testToken)
	f, srv := newFakeGitHub(t)
	for _, state := range []string{"open", "dismissed", "auto_dismissed"} {
		f.serve(dependabotPath, state, "dependabot-none.json")
	}
	ft := plugin.FileTarget{Source: saga.ImportSourceGitHubDependabot,
		Repositories: []plugin.RepositoryTarget{{URL: "https://github.com/octo-org/octo-repo"}}}
	rep, err := githubImport(srv, githubAlertsCommit, nil).Scan(context.Background(), ft, nil)
	if err != nil || len(rep.Results) != 0 || fieldOf(rep, "severity") != "no findings" {
		t.Errorf("rep %+v, err %v, want no findings", rep, err)
	}
}

// Every refusal is an error naming what to do, never an empty import, and each reason is one clause
// within the errors block's 80 columns with no colon inside it.
func TestGitHubRefusalsAreErrors(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", testToken)
	for _, c := range []struct {
		name   string
		source string
		status int
		body   string
		want   string
	}{
		{"401", saga.ImportSourceGitHubCodeScanning, 401, "unauthorized-401-constructed.json", "GitHub refused the token as invalid or expired (HTTP 401)"},
		{"403 code security", saga.ImportSourceGitHubCodeScanning, 403, "code-scanning-403-code-security.json",
			"needs GitHub Code Security (Advanced Security) turned on (HTTP 403)"},
		{"403 dependabot", saga.ImportSourceGitHubDependabot, 403, "dependabot-403-disabled.json",
			"Dependabot alerts are off for this repository (HTTP 403)"},
		{"404", saga.ImportSourceGitHubCodeScanning, 404, "code-scanning-404.json", "no such repository, or the token cannot see it (HTTP 404)"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f, srv := newFakeGitHub(t)
			body := recorded(t, c.body)
			f.refuse = func(w http.ResponseWriter, _ *http.Request) bool {
				w.WriteHeader(c.status)
				_, _ = w.Write(body)
				return true
			}
			ft := plugin.FileTarget{Source: c.source, Repositories: draugrRepo()}
			_, err := githubImport(srv, githubAlertsCommit, nil).Scan(context.Background(), ft, nil)
			if err == nil {
				t.Fatal("no error")
			}
			reason := strings.TrimPrefix(err.Error(), plugin.ImportScanner+": "+ft.Identity()+": ")
			if reason != c.want || len(reason) > 80 || strings.Contains(reason, ": ") {
				t.Errorf("err = %q, want %q within 80 columns and no colon", err, c.want)
			}
			if strings.Contains(err.Error(), testToken) {
				t.Error("the token is in the error")
			}
		})
	}
}

// A 403 GitHub's rate limit sent is waited out for as long as its reset says, where that is short
// enough, and a 429 as long as retry-after says; one that lasts longer is an error naming when it
// ends, and one that keeps coming is an error after the last try.
func TestGitHubRateLimitsAreWaitedOut(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", testToken)
	ft := plugin.FileTarget{Source: saga.ImportSourceGitHubCodeScanning, Repositories: draugrRepo()}
	now := time.Date(2026, 11, 17, 15, 0, 0, 0, time.UTC)

	f, srv := newFakeGitHub(t)
	f.serve(codeScanningPath, "open", "code-scanning-open-page1.json")
	f.serve(codeScanningPath, "dismissed", "code-scanning-dismissed.json")
	limited := 0
	f.refuse = func(w http.ResponseWriter, _ *http.Request) bool {
		limited++
		switch limited {
		case 1:
			w.Header().Set("Retry-After", "7")
			w.WriteHeader(http.StatusTooManyRequests)
			return true
		case 2:
			w.Header().Set("X-Ratelimit-Remaining", "0")
			w.Header().Set("X-Ratelimit-Reset", fmt.Sprint(now.Add(90*time.Second).Unix()))
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"message":"API rate limit exceeded"}`))
			return true
		}
		return false
	}
	var waits []time.Duration
	rep, err := githubImport(srv, githubAlertsCommit, &waits).Scan(context.Background(), ft, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(waits) != 2 || waits[0] != 7*time.Second || waits[1] != 90*time.Second || len(rep.Results) != 10 {
		t.Errorf("waited %v and read %d findings, want 7s then 90s, then every alert", waits, len(rep.Results))
	}

	f2, srv2 := newFakeGitHub(t)
	f2.refuse = func(w http.ResponseWriter, _ *http.Request) bool {
		w.Header().Set("X-Ratelimit-Remaining", "0")
		w.Header().Set("X-Ratelimit-Reset", fmt.Sprint(now.Add(40*time.Minute).Unix()))
		w.WriteHeader(http.StatusForbidden)
		return true
	}
	_, err = githubImport(srv2, githubAlertsCommit, nil).Scan(context.Background(), ft, nil)
	if err == nil || !strings.HasSuffix(err.Error(), "GitHub's rate limit lasts until 15:40 UTC (HTTP 403)") {
		t.Errorf("err = %v, want the time the limit ends", err)
	}

	f3, srv3 := newFakeGitHub(t)
	f3.refuse = func(w http.ResponseWriter, _ *http.Request) bool {
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusTooManyRequests)
		return true
	}
	_, err = githubImport(srv3, githubAlertsCommit, nil).Scan(context.Background(), ft, nil)
	if err == nil || !strings.HasSuffix(err.Error(), "GitHub kept limiting requests after 3 tries (HTTP 429)") {
		t.Errorf("err = %v, want it given up after the last try", err)
	}
	if n := len(f3.requests); n != githubAttempts {
		t.Errorf("asked %d times, want %d", n, githubAttempts)
	}
}

// A 403 with no rate limit about it is the token lacking access, and says which scope it needs.
func TestAForbiddenAnswerNamesTheScope(t *testing.T) {
	err := githubRefusal(http.StatusForbidden, []byte(`{"message":"Resource not accessible by integration"}`))
	if err.Error() != "the token may not read these alerts. It needs security_events (HTTP 403)" {
		t.Errorf("err = %v", err)
	}
	if err := githubRefusal(http.StatusNotFound, []byte(`{"message":"no analysis found"}`)); !strings.Contains(err.Error(), "no code-scanning analysis") {
		t.Errorf("err = %v", err)
	}
	if err := githubRefusal(http.StatusInternalServerError, nil); err.Error() != "GitHub answered HTTP 500 in place of the alerts" {
		t.Errorf("err = %v", err)
	}
}

// The token is sent to GitHub and nowhere else: never in a finding, the provenance or an error, and
// never to a next page on another host.
func TestTheTokenNeverReachesTheOutput(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", testToken)
	f, srv := newFakeGitHub(t)
	f.serve(codeScanningPath, "open", "code-scanning-open-page1.json", "code-scanning-open-page2.json")
	f.serve(codeScanningPath, "dismissed", "code-scanning-dismissed.json")
	ft := plugin.FileTarget{Source: saga.ImportSourceGitHubCodeScanning, Repositories: draugrRepo()}
	rep, err := githubImport(srv, githubAlertsCommit, nil).Scan(context.Background(), ft, nil)
	if err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), testToken) || strings.Contains(ft.CacheDetail()+ft.Identity(), testToken) {
		t.Error("the token is in the report")
	}

	elsewhere, srv2 := newFakeGitHub(t)
	elsewhere.refuse = func(w http.ResponseWriter, _ *http.Request) bool {
		w.Header().Set("Link", `<https://attacker.example/page2>; rel="next"`)
		_, _ = w.Write([]byte("[]"))
		return true
	}
	_, err = githubImport(srv2, githubAlertsCommit, nil).Scan(context.Background(), ft, nil)
	if err == nil || !strings.HasSuffix(err.Error(), "GitHub's next page is on another host, so the token is not sent there") {
		t.Errorf("err = %v, want the next page on another host refused", err)
	}
}

// The token comes from GITHUB_TOKEN, or from a variable the pipeline lists in $DRAUGR_TOKEN_ENVS; any
// other name is refused before anything is sent, and an empty one is an error.
func TestTheTokenVariableIsHeldToThePipelinesList(t *testing.T) {
	_, srv := newFakeGitHub(t)
	ft := plugin.FileTarget{Source: saga.ImportSourceGitHubCodeScanning, Repositories: draugrRepo(), TokenEnv: "GH_TOKEN"}
	t.Setenv("GH_TOKEN", testToken)
	t.Setenv(credential.TokenEnvsVar, "")
	_, err := githubImport(srv, githubAlertsCommit, nil).Scan(context.Background(), ft, nil)
	if err == nil || !strings.HasSuffix(err.Error(), "$GH_TOKEN is not listed in $DRAUGR_TOKEN_ENVS. List it there, or use $GITHUB_TOKEN") {
		t.Errorf("err = %v, want the variable refused", err)
	}
	t.Setenv(credential.TokenEnvsVar, "GH_TOKEN")
	t.Setenv("GH_TOKEN", "")
	_, err = githubImport(srv, githubAlertsCommit, nil).Scan(context.Background(), ft, nil)
	if err == nil || !strings.HasSuffix(err.Error(), "$GH_TOKEN is empty. Set it to a token that can read security alerts") {
		t.Errorf("err = %v, want the empty variable named", err)
	}
	if detail, ok := SourceCheck(ft); ok || !strings.Contains(detail, "$GH_TOKEN is empty") {
		t.Errorf("SourceCheck = %q, %v", detail, ok)
	}
	t.Setenv("GH_TOKEN", testToken)
	if detail, ok := SourceCheck(ft); !ok || detail != "token in $GH_TOKEN, alerts read by the scan" {
		t.Errorf("SourceCheck = %q, %v", detail, ok)
	}
}

// An offline run does not reach GitHub, and says so rather than reading no alerts.
func TestAnOfflineRunReadsNoAlerts(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", testToken)
	t.Setenv("DRAUGR_OFFLINE", "1")
	f, srv := newFakeGitHub(t)
	ft := plugin.FileTarget{Source: saga.ImportSourceGitHubCodeScanning, Repositories: draugrRepo()}
	_, err := githubImport(srv, githubAlertsCommit, nil).Scan(context.Background(), ft, nil)
	if err == nil || !strings.Contains(err.Error(), "an offline run does not reach GitHub") || len(f.requests) != 0 {
		t.Errorf("err = %v after %d requests, want an error and none sent", err, len(f.requests))
	}
}

// In a component of two repositories the import reads the one it names, places its findings there,
// and is refused where it names none or one the component does not have. Two components, one
// repository each, read their own.
func TestTwoRepositoriesReadTheOneNamed(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", testToken)
	f, srv := newFakeGitHub(t)
	f.serveByState(dependabotPath, "dependabot-alerts-constructed.json", "open", "dismissed", "auto_dismissed")
	repos := []plugin.RepositoryTarget{{URL: "https://github.com/draugr-dev/draugr"}, {URL: "https://github.com/octo-org/octo-repo"}}
	scan := func(repository string) (sarif.Report, error) {
		ft := plugin.FileTarget{Source: saga.ImportSourceGitHubDependabot, Component: "shop", Repositories: repos, Repository: repository}
		return githubImport(srv, githubAlertsCommit, nil).Scan(context.Background(), ft, nil)
	}
	rep, err := scan("Octo-Org/octo-repo")
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rep.Results {
		if r.ImportedRepository != "https://github.com/octo-org/octo-repo" {
			t.Errorf("%s placed in %q", r.RuleID, r.ImportedRepository)
		}
	}
	if len(rep.Results) != 3 {
		t.Errorf("got %d findings, want the named repository's three", len(rep.Results))
	}
	if _, err := scan(""); err == nil || !strings.HasSuffix(err.Error(), "the component has several repositories. Name one with repository") {
		t.Errorf("err = %v, want the repository asked for", err)
	}
	if _, err := scan("acme/other"); err == nil || !strings.HasSuffix(err.Error(), "acme/other is not one of the repositories of component shop") {
		t.Errorf("err = %v, want a repository outside the component refused", err)
	}
	for _, r := range f.requests {
		if !strings.HasPrefix(r.URL.Path, dependabotPath) {
			t.Errorf("asked for %s", r.URL.Path)
		}
	}
}

// A component whose one repository is a local checkout with no remote on github.com has no
// repository to read, and asks for one rather than guessing; naming it reads that one.
func TestALocalCheckoutNamesItsRepository(t *testing.T) {
	ft := plugin.FileTarget{Source: saga.ImportSourceGitHubCodeScanning, Repositories: []plugin.RepositoryTarget{{URL: t.TempDir()}}}
	if _, _, err := githubRepositoryOf(ft); err == nil || err.Error() != "its address names no github.com repository. Name one with repository" {
		t.Errorf("err = %v", err)
	}
	ft.Repository = "draugr-dev/draugr"
	if name, _, err := githubRepositoryOf(ft); err != nil || name != "draugr-dev/draugr" {
		t.Errorf("name %q, err %v", name, err)
	}
	ft.Repositories[0].Remote = "git@github.com:draugr-dev/draugr.git"
	ft.Repository = ""
	if name, _, err := githubRepositoryOf(ft); err != nil || name != "draugr-dev/draugr" {
		t.Errorf("from the remote: name %q, err %v", name, err)
	}
	if _, _, err := githubRepositoryOf(plugin.FileTarget{Component: "c"}); err == nil {
		t.Error("a component with no repository was read")
	}
}

// A run that reads a source declares the effect of asking GitHub for its alerts, and a run that reads
// a file does not: reading a file sends nothing anywhere.
func TestOnlyASourceHasTheNetworkEffect(t *testing.T) {
	info := NewSARIFImport().Info()
	for _, c := range []struct {
		target plugin.FileTarget
		want   int
	}{
		{plugin.FileTarget{Path: "a.sarif"}, 0},
		{plugin.FileTarget{Source: saga.ImportSourceGitHubCodeScanning}, 1},
		{plugin.FileTarget{Source: saga.ImportSourceGitHubDependabot}, 1},
	} {
		got := plugin.EffectsForJob(info, plugin.ScanJob{Target: c.target})
		if len(got) != c.want || (c.want == 1 && (got[0].Kind != plugin.EffectNetwork || got[0].Source != c.target.Source)) {
			t.Errorf("%+v has effects %+v", c.target, got)
		}
	}
	if got := plugin.EffectsFor(info, nil); len(got) != 0 {
		t.Errorf("EffectsFor = %+v, want none without a target", got)
	}
}

// A GitHub that does not answer is an error naming why, without the address it was asked at.
func TestGitHubNotAnsweringIsAnError(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", testToken)
	_, srv := newFakeGitHub(t)
	s := githubImport(srv, githubAlertsCommit, nil)
	srv.Close()
	ft := plugin.FileTarget{Source: saga.ImportSourceGitHubCodeScanning, Repositories: draugrRepo()}
	_, err := s.Scan(context.Background(), ft, nil)
	if err == nil || !strings.Contains(err.Error(), "GitHub did not answer. ") || strings.Contains(err.Error(), srv.URL) {
		t.Errorf("err = %v", err)
	}
	if got := transportReason(context.DeadlineExceeded); got != "No answer before the timeout" {
		t.Errorf("reason = %q", got)
	}
}

// The client a scan uses asks api.github.com unless the pipeline names GitHub Enterprise Server's
// API, and its wait for a rate limit ends early when the run is canceled.
func TestTheGitHubClientAScanUses(t *testing.T) {
	t.Setenv("GITHUB_API_URL", "")
	if c := newGitHubClient(); c.base != "https://api.github.com" || c.http.CheckRedirect == nil {
		t.Errorf("base %q, redirect check set %v", c.base, c.http.CheckRedirect != nil)
	}
	t.Setenv("GITHUB_API_URL", "https://ghes.example/api/v3/")
	c := newGitHubClient()
	if c.base != "https://ghes.example/api/v3" {
		t.Errorf("base %q", c.base)
	}
	if err := c.sleep(context.Background(), time.Millisecond); err != nil {
		t.Errorf("sleep: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := c.sleep(ctx, time.Hour); err == nil {
		t.Error("a canceled wait did not end")
	}
	if (githubClient{}).clock().IsZero() {
		t.Error("no clock")
	}
}

// A dismissal is described by its reason and comment, either alone, and an analysis by its tool and
// category, either alone.
func TestDismissalAndAnalysisNames(t *testing.T) {
	for d, want := range map[githubDismissal]string{
		{reason: "false positive"}: "false positive",
		{comment: "test fixture"}:  "test fixture",
		{}:                         "",
	} {
		if got := d.justification(); got != want {
			t.Errorf("%+v = %q, want %q", d, got, want)
		}
	}
	if got := analysisName("CodeQL\x00"); got != "CodeQL" {
		t.Errorf("%q", got)
	}
	if got := analysisName("\x00cat"); got != "an unnamed tool (cat)" {
		t.Errorf("%q", got)
	}
}

// The Link header's next page is read wherever GitHub puts it, and the last page has none.
func TestNextLink(t *testing.T) {
	h := `<https://api.github.com/repositories/1/code-scanning/alerts?page=1>; rel="prev", ` +
		`<https://api.github.com/repositories/1/code-scanning/alerts?page=3>; rel="next"`
	if got := nextLink(h); got != "https://api.github.com/repositories/1/code-scanning/alerts?page=3" {
		t.Errorf("next = %q", got)
	}
	if got := nextLink(`<https://x/?page=1>; rel="first"`); got != "" {
		t.Errorf("next = %q on the last page", got)
	}
	if d, ok := retryAfter("Tue, 17 Nov 2026 15:01:00 GMT", time.Date(2026, 11, 17, 15, 0, 0, 0, time.UTC)); !ok || d != time.Minute {
		t.Errorf("retry-after date = %v, %v", d, ok)
	}
	if _, ok := retryAfter("soon", time.Now()); ok {
		t.Error("an unreadable retry-after was read")
	}
}
