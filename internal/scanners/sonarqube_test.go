package scanners

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/draugr-dev/draugr/internal/credential"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// The answers below are written in the shapes SonarQube Cloud's Web API gave on 2026-11-26 for public
// projects, read without a token: api/issues/search with additionalFields=comments,
// api/project_analyses/search and api/rules/show. Their keys and paths are made up.

// sonarCommit is the commit the fake server's latest analysis read.
const sonarCommit = "2d39fe0fbd1376508e5a4815fbaed71e9071d881"

// fakeSonar answers as SonarQube's Web API does, from pages of issues, an analysis and rules.
type fakeSonar struct {
	t *testing.T
	// issues are the pages of api/issues/search, the first first.
	issues []string
	// revision is the latest analysis's commit, and noAnalysis answers with none.
	revision   string
	noAnalysis bool
	// rules are the answers of api/rules/show by key.
	rules map[string]string
	// refuse, where set, answers every request with this status and body.
	refuseCode int
	refuseBody string
	// limited answers this many requests with 429 first.
	limited int

	requests []*http.Request
}

func (f *fakeSonar) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.requests = append(f.requests, r)
	if got := r.Header.Get("Authorization"); got != "Bearer "+sonarTestToken {
		f.t.Errorf("Authorization = %q, want the token as a bearer", got)
	}
	if f.limited > 0 {
		f.limited--
		w.Header().Set("Retry-After", "7")
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}
	if f.refuseCode != 0 {
		w.WriteHeader(f.refuseCode)
		_, _ = w.Write([]byte(f.refuseBody))
		return
	}
	q := r.URL.Query()
	switch r.URL.Path {
	case "/api/project_analyses/search":
		if f.noAnalysis {
			_, _ = w.Write([]byte(`{"paging":{"pageIndex":1,"pageSize":1,"total":0},"analyses":[]}`))
			return
		}
		_, _ = fmt.Fprintf(w, `{"paging":{"pageIndex":1,"pageSize":1,"total":3},"analyses":[{"key":"a1","date":"2026-11-25T08:39:54+0000","revision":%q}]}`, f.revision)
	case "/api/issues/search":
		if q.Get("componentKeys") != "acme_api" || q.Get("impactSoftwareQualities") != "SECURITY" {
			f.t.Errorf("issues asked with %s", r.URL.RawQuery)
		}
		page := 1
		_, _ = fmt.Sscanf(q.Get("p"), "%d", &page)
		if page > len(f.issues) {
			f.t.Errorf("page %d asked for, %d served", page, len(f.issues))
			_, _ = w.Write([]byte(`{"paging":{"pageIndex":9,"pageSize":500,"total":0},"issues":[],"components":[]}`))
			return
		}
		_, _ = w.Write([]byte(f.issues[page-1]))
	case "/api/rules/show":
		body, ok := f.rules[q.Get("key")]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"errors":[{"msg":"Rule not found"}]}`))
			return
		}
		_, _ = w.Write([]byte(body))
	default:
		f.t.Errorf("unexpected request %s", r.URL)
		w.WriteHeader(http.StatusNotFound)
	}
}

// sonarTestToken is shaped like a SonarQube token and is not one.
var sonarTestToken = "sqp_" + strings.Repeat("b", 40)

// sonarIssuePage is one page of issues: the total, and the issues as JSON objects.
func sonarIssuePage(total int, issues ...string) string {
	return fmt.Sprintf(`{"total":%d,"p":1,"ps":500,"paging":{"pageIndex":1,"pageSize":500,"total":%d},
"issues":[%s],
"components":[{"key":"acme_api","qualifier":"TRK","name":"api"},
 {"key":"acme_api:src/main/java/Login.java","qualifier":"FIL","name":"Login.java","path":"src/main/java/Login.java"}],
"organizations":[{"key":"acme","name":"Acme"}],"facets":[]}`, total, total, strings.Join(issues, ","))
}

// sonarIssueJSON is an issue of a rule at a line, with its status and security impact.
func sonarIssueJSON(key, rule string, line int, status, impact string) string {
	impacts := `[{"softwareQuality":"SECURITY","severity":"` + impact + `"}]`
	if impact == "" {
		impacts = `[{"softwareQuality":"MAINTAINABILITY","severity":"MEDIUM"}]`
	}
	return fmt.Sprintf(`{"key":%q,"rule":%q,"severity":"MINOR","component":"acme_api:src/main/java/Login.java",
"project":"acme_api","line":%d,"textRange":{"startLine":%d,"endLine":%d,"startOffset":4,"endOffset":40},
"status":"OPEN","message":"Change this code to not construct the path from user-controlled data.","tags":["cwe"],
"type":"VULNERABILITY","organization":"acme","impacts":%s,"issueStatus":%q,"updateDate":"2026-11-08T16:28:39+0000"}`,
		key, rule, line, line, line, impacts, status)
}

const sonarRuleS2083 = `{"rule":{"key":"javasecurity:S2083","name":"I/O function calls should not be vulnerable to path injection attacks",
"securityStandards":["cwe:22","owaspTop10-2021:a1"],"type":"VULNERABILITY","lang":"java"}}`

const sonarRuleS4507 = `{"rule":{"key":"java:S4507","name":"Debugging features should not be enabled in production",
"securityStandards":["cwe:215","cwe:489"],"type":"VULNERABILITY"}}`

// sonarImport is the import scanner reading from srv, the run reading commit, no wait for a rate limit
// taken: each is recorded in waits.
func sonarImportOf(srv *httptest.Server, commit string, waits *[]time.Duration) sarifImport {
	return sarifImport{
		resolve: func(context.Context, string, string) (string, error) { return commit, nil },
		sonar: sonarClient{
			base: srv.URL,
			http: credential.Client(srv.Client()),
			sleep: func(_ context.Context, d time.Duration) error {
				if waits != nil {
					*waits = append(*waits, d)
				}
				return nil
			},
			now: func() time.Time { return time.Date(2026, 11, 26, 9, 0, 0, 0, time.UTC) },
		},
	}
}

func newFakeSonar(t *testing.T) (*fakeSonar, *httptest.Server) {
	f := &fakeSonar{t: t, revision: sonarCommit,
		rules: map[string]string{"javasecurity:S2083": sonarRuleS2083, "java:S4507": sonarRuleS4507}}
	srv := httptest.NewTLSServer(f)
	t.Cleanup(srv.Close)
	return f, srv
}

// sonarTarget is a sonarqube import of acme_api for a component of one repository.
func sonarTarget() plugin.FileTarget {
	return plugin.FileTarget{Source: saga.ImportSourceSonarQube, Project: "acme_api", Component: "api", Control: "sast",
		Repositories: []plugin.RepositoryTarget{{URL: "https://github.com/acme/api"}}}
}

// Each open security issue is a finding at its file and line, under its rule with the rule's CWEs,
// rated by its security impact; an issue a person accepted is set aside with their latest comment as
// the reason; and the analysis's commit, being this run's, binds the import.
func TestSonarQubeSecurityIssuesAreFindings(t *testing.T) {
	t.Setenv("SONAR_TOKEN", sonarTestToken)
	f, srv := newFakeSonar(t)
	accepted := strings.Replace(sonarIssueJSON("k3", "java:S4507", 57, "ACCEPTED", "LOW"), `"issueStatus"`,
		`"comments":[{"key":"c1","login":"old@github","markdown":"first","createdAt":"2026-10-01T07:52:14+0000"},`+
			`{"key":"c2","login":"reviewer@github","markdown":"Only runs\non the debug build.","createdAt":"2026-10-24T07:52:14+0000"}],"issueStatus"`, 1)
	f.issues = []string{sonarIssuePage(3,
		sonarIssueJSON("k1", "javasecurity:S2083", 12, "OPEN", "BLOCKER"),
		sonarIssueJSON("k2", "javasecurity:S2083", 30, "CONFIRMED", "MEDIUM"),
		accepted)}

	rep, err := sonarImportOf(srv, sonarCommit, nil).Scan(context.Background(), sonarTarget(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 3 {
		t.Fatalf("got %d findings, want 3: %+v", len(rep.Results), rep.Results)
	}
	first := rep.Results[0]
	if first.Tool != "SonarQube" || first.RuleID != "javasecurity:S2083" || first.Location.URI != "src/main/java/Login.java" ||
		first.Location.StartLine != 12 || first.Severity("") != sarif.SeverityCritical {
		t.Errorf("first finding = %+v (severity %s)", first, first.Severity(""))
	}
	if strings.Join(first.CWE, ",") != "CWE-22" {
		t.Errorf("CWE = %v, want the rule's CWE-22", first.CWE)
	}
	if rep.Results[1].Severity("") != sarif.SeverityMedium || rep.Results[1].Suppression != nil {
		t.Errorf("confirmed issue = %+v", rep.Results[1])
	}
	s := rep.Results[2].Suppression
	if s == nil || s.Author != "reviewer@github" || s.Service != "SonarQube" || s.Source != "k3" ||
		s.Justification != "accepted in SonarQube: Only runs on the debug build." {
		t.Errorf("accepted issue's suppression = %+v", s)
	}
	if r := rep.Rules["javasecurity:S2083"]; r.ShortDescription == "" {
		t.Errorf("rule = %+v, want its name", r)
	}
	if got := fieldOf(rep, "commit"); got != short(sonarCommit) {
		t.Errorf("commit = %q, want the analysis's", got)
	}
	if got := fieldOf(rep, "source"); !strings.Contains(got, "acme_api") {
		t.Errorf("source = %q", got)
	}
	// One rule lookup per rule, however many issues name it.
	n := 0
	for _, r := range f.requests {
		if r.URL.Path == "/api/rules/show" {
			n++
			if r.URL.Query().Get("organization") != "acme" {
				t.Errorf("rule looked up outside the project's organization: %s", r.URL.RawQuery)
			}
		}
	}
	if n != 2 {
		t.Errorf("rules looked up %d times, want 2", n)
	}
}

// suppressions: count keeps an accepted or false-positive issue counted, saying who decided what.
func TestSonarQubeDecisionsCountUnderSuppressionsCount(t *testing.T) {
	t.Setenv("SONAR_TOKEN", sonarTestToken)
	f, srv := newFakeSonar(t)
	f.issues = []string{sonarIssuePage(1, sonarIssueJSON("k1", "javasecurity:S2083", 12, "FALSE_POSITIVE", "HIGH"))}
	ft := sonarTarget()
	ft.CountSuppressed = true
	rep, err := sonarImportOf(srv, sonarCommit, nil).Scan(context.Background(), ft, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 1 || rep.Results[0].Suppression != nil ||
		!strings.Contains(rep.Results[0].Detail, "marked as a false positive in SonarQube") ||
		!strings.Contains(rep.Results[0].Detail, "suppressions: count") {
		t.Errorf("findings = %+v", rep.Results)
	}
}

// An issue the server returns with no security impact, as a server that ignores the search's filter
// does, is left out and counted, and a fixed one is not read; an older server's issue, with a type and
// a legacy severity and no impacts, is read by its severity and status.
func TestSonarQubeReadsOnlySecurityIssues(t *testing.T) {
	t.Setenv("SONAR_TOKEN", sonarTestToken)
	f, srv := newFakeSonar(t)
	legacy := `{"key":"k9","rule":"java:S4507","severity":"CRITICAL","component":"acme_api:src/main/java/Login.java",
"line":5,"type":"VULNERABILITY","status":"RESOLVED","resolution":"WONTFIX","organization":"acme"}`
	legacyFixed := `{"key":"k10","rule":"java:S4507","severity":"MAJOR","component":"acme_api:src/main/java/Login.java",
"line":6,"type":"VULNERABILITY","status":"CLOSED","resolution":"FIXED"}`
	smell := `{"key":"k11","rule":"java:S100","severity":"MAJOR","component":"acme_api:src/main/java/Login.java","line":7,"type":"CODE_SMELL"}`
	f.issues = []string{sonarIssuePage(5,
		sonarIssueJSON("k1", "javasecurity:S2083", 12, "OPEN", ""),
		sonarIssueJSON("k2", "javasecurity:S2083", 13, "FIXED", "HIGH"),
		legacy, legacyFixed, smell)}
	rep, err := sonarImportOf(srv, sonarCommit, nil).Scan(context.Background(), sonarTarget(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 1 {
		t.Fatalf("got %d findings, want the legacy vulnerability only: %+v", len(rep.Results), rep.Results)
	}
	r := rep.Results[0]
	if r.RuleID != "java:S4507" || r.Severity("") != sarif.SeverityHigh || r.Suppression == nil ||
		r.Suppression.Justification != "accepted in SonarQube" {
		t.Errorf("legacy issue = %+v, suppression %+v", r, r.Suppression)
	}
	if got := fieldOf(rep, "left out"); !strings.HasPrefix(got, "2 issues with no security impact") {
		t.Errorf("left out = %q", got)
	}
}

// Every page is read until the total is, and a total above what SonarQube's search returns is refused
// rather than read in part.
func TestSonarQubePagesAndRefusesPastTheCap(t *testing.T) {
	t.Setenv("SONAR_TOKEN", sonarTestToken)
	f, srv := newFakeSonar(t)
	f.issues = []string{
		sonarIssuePage(2, sonarIssueJSON("k1", "javasecurity:S2083", 12, "OPEN", "HIGH")),
		sonarIssuePage(2, sonarIssueJSON("k2", "javasecurity:S2083", 14, "OPEN", "HIGH")),
	}
	rep, err := sonarImportOf(srv, sonarCommit, nil).Scan(context.Background(), sonarTarget(), nil)
	if err != nil || len(rep.Results) != 2 {
		t.Fatalf("got %d findings, err %v; want both pages read", len(rep.Results), err)
	}

	f.issues = []string{sonarIssuePage(10001, sonarIssueJSON("k1", "javasecurity:S2083", 12, "OPEN", "HIGH"))}
	_, err = sonarImportOf(srv, sonarCommit, nil).Scan(context.Background(), sonarTarget(), nil)
	if err == nil || !strings.Contains(err.Error(), "SonarQube counts 10001 security issues, more than the 10000") {
		t.Errorf("err = %v, want the cap named", err)
	}
}

// An analysis of another commit, or one naming none, keeps every finding and leaves the import
// unbound, saying why.
func TestSonarQubeAnalysisOfAnotherCommitIsUnbound(t *testing.T) {
	t.Setenv("SONAR_TOKEN", sonarTestToken)
	for _, tc := range []struct{ revision, want string }{
		{"cdef823154deb8223ced97d6928823c54e57ee46", "SonarQube analyzed cdef823154de, so its findings may not"},
		{"", "SonarQube's latest analysis names no commit"},
	} {
		f, srv := newFakeSonar(t)
		f.revision = tc.revision
		f.issues = []string{sonarIssuePage(1, sonarIssueJSON("k1", "javasecurity:S2083", 12, "OPEN", "HIGH"))}
		rep, err := sonarImportOf(srv, sonarCommit, nil).Scan(context.Background(), sonarTarget(), nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(rep.Results) != 1 || !strings.HasPrefix(fieldOf(rep, "commit"), notStated) {
			t.Errorf("revision %q: findings %d, commit %q", tc.revision, len(rep.Results), fieldOf(rep, "commit"))
		}
		var caveat string
		for _, p := range rep.Provenance {
			for _, d := range p.Detail {
				if d.Key == sarif.ImportUnbound {
					caveat = d.Value
				}
			}
		}
		if !strings.HasPrefix(caveat, tc.want) {
			t.Errorf("revision %q: caveat = %q, want %q", tc.revision, caveat, tc.want)
		}
	}
}

// Every refusal stops the import with what to do about it; none reads as a project with no findings.
func TestSonarQubeRefusalsAreErrors(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(f *fakeSonar, ft *plugin.FileTarget)
		token string
		want  string
	}{
		{"401", func(f *fakeSonar, _ *plugin.FileTarget) { f.refuseCode = http.StatusUnauthorized }, sonarTestToken,
			"SonarQube refused $SONAR_TOKEN as invalid or expired"},
		{"403", func(f *fakeSonar, _ *plugin.FileTarget) { f.refuseCode = http.StatusForbidden }, sonarTestToken,
			"$SONAR_TOKEN cannot browse project acme_api"},
		{"404", func(f *fakeSonar, _ *plugin.FileTarget) {
			f.refuseCode, f.refuseBody = http.StatusNotFound, `{"errors":[{"msg":"Project doesn't exist"}]}`
		}, sonarTestToken, "has no project acme_api, or the token cannot see it"},
		{"400", func(f *fakeSonar, _ *plugin.FileTarget) {
			f.refuseCode, f.refuseBody = http.StatusBadRequest, `{"errors":[{"msg":"Value of parameter 'p' is invalid."}]}`
		}, sonarTestToken, "SonarQube answered HTTP 400. Value of parameter 'p' is invalid"},
		{"500", func(f *fakeSonar, _ *plugin.FileTarget) { f.refuseCode = http.StatusInternalServerError }, sonarTestToken,
			"SonarQube answered HTTP 500"},
		{"no analysis", func(f *fakeSonar, _ *plugin.FileTarget) { f.noAnalysis = true }, sonarTestToken,
			"SonarQube has no analysis of project acme_api yet"},
		{"empty token", func(*fakeSonar, *plugin.FileTarget) {}, "", "$SONAR_TOKEN is empty"},
		{"unlisted variable", func(_ *fakeSonar, ft *plugin.FileTarget) { ft.TokenEnv = "MY_SONAR" }, sonarTestToken,
			"$MY_SONAR is not listed in $DRAUGR_TOKEN_ENVS"},
		{"no project", func(_ *fakeSonar, ft *plugin.FileTarget) { ft.Project = "" }, sonarTestToken,
			"names no SonarQube project"},
		{"no repository", func(_ *fakeSonar, ft *plugin.FileTarget) { ft.Repositories = nil }, sonarTestToken,
			"declares no repository"},
		{"unknown rule", func(f *fakeSonar, _ *plugin.FileTarget) { f.rules = nil }, sonarTestToken,
			"SonarQube has no rule javasecurity:S2083"},
		{"not a rule", func(f *fakeSonar, _ *plugin.FileTarget) {
			f.rules = map[string]string{"javasecurity:S2083": `{"errors":[]}`}
		}, sonarTestToken, "rule javasecurity:S2083 is not a rule"},
		{"not issues", func(f *fakeSonar, _ *plugin.FileTarget) { f.issues = []string{`{"errors":[]}`} }, sonarTestToken,
			"not a list of issues"},
		{"unknown impact", func(f *fakeSonar, _ *plugin.FileTarget) {
			f.issues = []string{sonarIssuePage(1, sonarIssueJSON("k1", "javasecurity:S2083", 12, "OPEN", "SEVERE"))}
		}, sonarTestToken, `security severity "SEVERE"`},
		{"unknown legacy severity", func(f *fakeSonar, _ *plugin.FileTarget) {
			f.issues = []string{sonarIssuePage(1, `{"key":"k1","rule":"java:S1","severity":"WORST","type":"VULNERABILITY"}`)}
		}, sonarTestToken, `severity "WORST"`},
		{"no rule", func(f *fakeSonar, _ *plugin.FileTarget) {
			f.issues = []string{sonarIssuePage(1, `{"key":"k1","rule":"","type":"VULNERABILITY","severity":"MAJOR"}`)}
		}, sonarTestToken, "issue k1 names no rule"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SONAR_TOKEN", tc.token)
			t.Setenv(credential.TokenEnvsVar, "")
			t.Setenv("MY_SONAR", sonarTestToken)
			f, srv := newFakeSonar(t)
			f.issues = []string{sonarIssuePage(1, sonarIssueJSON("k1", "javasecurity:S2083", 12, "OPEN", "HIGH"))}
			ft := sonarTarget()
			tc.setup(f, &ft)
			_, err := sonarImportOf(srv, sonarCommit, nil).Scan(context.Background(), ft, nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

// A rate limit SonarQube names is waited out, and one that keeps on is reported.
func TestSonarQubeWaitsOutARateLimit(t *testing.T) {
	t.Setenv("SONAR_TOKEN", sonarTestToken)
	f, srv := newFakeSonar(t)
	f.issues = []string{sonarIssuePage(1, sonarIssueJSON("k1", "javasecurity:S2083", 12, "OPEN", "HIGH"))}
	f.limited = 1
	var waits []time.Duration
	if _, err := sonarImportOf(srv, sonarCommit, &waits).Scan(context.Background(), sonarTarget(), nil); err != nil {
		t.Fatal(err)
	}
	if len(waits) != 1 || waits[0] != 7*time.Second {
		t.Errorf("waits = %v, want the 7s Retry-After", waits)
	}
	f.limited = 5
	_, err := sonarImportOf(srv, sonarCommit, nil).Scan(context.Background(), sonarTarget(), nil)
	if err == nil || !strings.Contains(err.Error(), "kept limiting requests after 3 tries") {
		t.Errorf("err = %v", err)
	}
}

// A component of several repositories reads the one the import names, by the end of its address.
func TestSonarQubeNamesOneOfSeveralRepositories(t *testing.T) {
	repos := []plugin.RepositoryTarget{{URL: "https://gitlab.com/acme/web"}, {URL: "https://gitlab.com/acme/api.git"}}
	ft := plugin.FileTarget{Component: "app", Repositories: repos, Repository: "acme/api"}
	r, err := sourceRepositoryOf(ft)
	if err != nil || r.URL != "https://gitlab.com/acme/api.git" {
		t.Errorf("repository = %+v, err %v", r, err)
	}
	ft.Repository = "acme/other"
	if _, err := sourceRepositoryOf(ft); err == nil || !strings.Contains(err.Error(), "acme/other is not one of") {
		t.Errorf("err = %v", err)
	}
	ft.Repository = ""
	if _, err := sourceRepositoryOf(ft); err == nil || !strings.Contains(err.Error(), "several repositories") {
		t.Errorf("err = %v", err)
	}
}

// doctor says where the token goes without sending it, and refuses a server that is not an address.
func TestSonarQubeSourceCheck(t *testing.T) {
	ft := sonarTarget()
	t.Setenv("SONAR_TOKEN", sonarTestToken)
	t.Setenv("SONAR_HOST_URL", "")
	if detail, ok := SourceCheck(ft); !ok || detail != "token in $SONAR_TOKEN, findings read from https://sonarcloud.io by the scan" {
		t.Errorf("check = %q, %v", detail, ok)
	}
	t.Setenv("SONAR_HOST_URL", "ftp://sonar.internal")
	if detail, ok := SourceCheck(ft); ok || !strings.Contains(detail, "SONAR_HOST_URL is not an http or https address") {
		t.Errorf("check = %q, %v", detail, ok)
	}
	t.Setenv("SONAR_TOKEN", "")
	if detail, ok := SourceCheck(ft); ok || !strings.Contains(detail, "is empty") {
		t.Errorf("check = %q, %v", detail, ok)
	}
	if strings.Contains(fmt.Sprint(SourceCheck(ft)), sonarTestToken) {
		t.Error("the check's detail holds the token")
	}
}

// The server is the pipeline's $SONAR_HOST_URL, else SonarQube Cloud, never the descriptor's.
func TestSonarQubeServerComesFromTheEnvironment(t *testing.T) {
	t.Setenv("SONAR_HOST_URL", "")
	if got := newSonarClient().base; got != "https://sonarcloud.io" {
		t.Errorf("base = %q", got)
	}
	t.Setenv("SONAR_HOST_URL", "https://sonar.acme.internal/")
	if got := newSonarClient().base; got != "https://sonar.acme.internal" {
		t.Errorf("base = %q", got)
	}
}

// An offline run is refused before anything is sent.
func TestSonarQubeIsNotReadOffline(t *testing.T) {
	t.Setenv("SONAR_TOKEN", sonarTestToken)
	t.Setenv("DRAUGR_OFFLINE", "1")
	f, srv := newFakeSonar(t)
	_, err := sonarImportOf(srv, sonarCommit, nil).Scan(context.Background(), sonarTarget(), nil)
	if err == nil || !strings.Contains(err.Error(), "offline") || len(f.requests) != 0 {
		t.Errorf("err = %v, %d requests", err, len(f.requests))
	}
}

// recordedSonar serves the answers SonarQube Community Build gave for a project it analyzed, from
// testdata/sonarqube (its NOTICE says how they were recorded), and records what was asked.
type recordedSonar struct {
	t        *testing.T
	requests []*http.Request
}

func (f *recordedSonar) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.requests = append(f.requests, r)
	q := r.URL.Query()
	var file string
	switch r.URL.Path {
	case "/api/project_analyses/search":
		file = "project_analyses.json"
	case "/api/issues/search":
		if q.Get("componentKeys") != "draugr-fixture" || q.Get("p") != "1" {
			f.t.Errorf("issues asked with %s", r.URL.RawQuery)
		}
		file = "issues.json"
	case "/api/rules/show":
		file = "rules-" + strings.ReplaceAll(q.Get("key"), ":", "-") + ".json"
	}
	body, err := os.ReadFile(filepath.Join("testdata", "sonarqube", file)) // #nosec G304 G703 -- a fixture this package holds, named by the test
	if file == "" || err != nil {
		f.t.Errorf("unexpected request %s", r.URL)
		w.WriteHeader(http.StatusNotFound)
		return
	}
	_, _ = w.Write(body) // #nosec G705 -- a recorded JSON answer served to the test's own client
}

// What a real SonarQube Community Build answers is read as it is meant: each security issue a finding
// at its file and line, rated by its security impact, the accepted one set aside with its comment as
// the reason, and the import bound to the commit the analysis read. Community Build's rules state no
// security standards, so these findings carry no CWE.
func TestSonarQubeReadsWhatCommunityBuildAnswers(t *testing.T) {
	t.Setenv("SONAR_TOKEN", sonarTestToken)
	const analyzed = "61486d359fa0ec8222c3c922e2b8ca497fe6e0cb"
	f := &recordedSonar{t: t}
	srv := httptest.NewTLSServer(f)
	t.Cleanup(srv.Close)
	ft := sonarTarget()
	ft.Project = "draugr-fixture"

	rep, err := sonarImportOf(srv, analyzed, nil).Scan(context.Background(), ft, nil)
	if err != nil {
		t.Fatal(err)
	}
	type row struct {
		rule string
		line int
	}
	var got []row
	for _, r := range rep.Results {
		got = append(got, row{r.RuleID, r.Location.StartLine})
		if r.Location.URI != "app/client.py" || r.Severity("") != sarif.SeverityHigh || len(r.CWE) != 0 {
			t.Errorf("%s: uri %q, severity %s, CWE %v", r.RuleID, r.Location.URI, r.Severity(""), r.CWE)
		}
		if r.RuleID == "python:S4423" {
			s := r.Suppression
			if s == nil || s.Author != "admin" || s.Service != "SonarQube" ||
				s.Justification != "accepted in SonarQube: Only reached by the legacy device bridge, retired next quarter." {
				t.Errorf("accepted issue's suppression = %+v", s)
			}
		} else if r.Suppression != nil {
			t.Errorf("%s set aside: %+v", r.RuleID, r.Suppression)
		}
	}
	want := []row{{"python:S4830", 10}, {"python:S5659", 15}, {"python:S5527", 20}, {"python:S4423", 20}}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("findings = %v, want %v", got, want)
	}
	if r := rep.Rules["python:S5659"]; r.ShortDescription != "JWT should be signed and verified" {
		t.Errorf("rule = %+v, want its name", r)
	}
	if got := fieldOf(rep, "commit"); got != short(analyzed) {
		t.Errorf("commit = %q, want the analysis's", got)
	}
}
