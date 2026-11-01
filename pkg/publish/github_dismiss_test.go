package publish

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/report"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// fakeCodeScanning answers the code-scanning endpoints the github publisher calls: the upload, the
// upload's processing status, the alert listings and the alert updates.
type fakeCodeScanning struct {
	t *testing.T
	// statuses is what successive status requests answer; the last repeats. Empty means complete.
	statuses []string
	// open and dismissed are the alerts each listing returns. open is served in pages of pageSize
	// when pageSize is set.
	open, dismissed []codeScanningAlert
	pageSize        int
	// refuse is the alert numbers whose update fails.
	refuse map[int]bool
	// noID answers the upload without naming it.
	noID bool

	mu       sync.Mutex
	polls    int
	toolName string
	ref      string
	patches  map[int]map[string]string
}

func (f *fakeCodeScanning) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/code-scanning/sarifs"):
		w.WriteHeader(http.StatusAccepted)
		if !f.noID {
			_, _ = w.Write([]byte(`{"id":"up-1","url":"x"}`))
		}
	case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/code-scanning/sarifs/up-1"):
		status := "complete"
		if len(f.statuses) > 0 {
			status = f.statuses[min(f.polls, len(f.statuses)-1)]
		}
		f.polls++
		_, _ = fmt.Fprintf(w, `{"processing_status":%q,"errors":["line 3: not a result"]}`, status)
	case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/code-scanning/alerts"):
		q := r.URL.Query()
		f.toolName, f.ref = q.Get("tool_name"), q.Get("ref")
		alerts := f.dismissed
		if q.Get("state") == "open" {
			alerts = f.open
		}
		if f.pageSize > 0 && q.Get("state") == "open" {
			page := 0
			_, _ = fmt.Sscan(q.Get("page"), &page)
			start := page * f.pageSize
			end := min(start+f.pageSize, len(alerts))
			if end < len(alerts) {
				next := *r.URL
				nq := next.Query()
				nq.Set("page", fmt.Sprint(page+1))
				next.RawQuery = nq.Encode()
				w.Header().Set("Link", fmt.Sprintf(`<http://%s%s>; rel="next"`, r.Host, next.RequestURI()))
			}
			alerts = alerts[start:end]
		}
		_ = json.NewEncoder(w).Encode(alerts)
	case r.Method == http.MethodPatch && strings.Contains(r.URL.Path, "/code-scanning/alerts/"):
		var n int
		_, _ = fmt.Sscan(r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:], &n)
		if f.refuse[n] {
			http.Error(w, `{"message":"Resource not accessible by integration"}`, http.StatusForbidden)
			return
		}
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if f.patches == nil {
			f.patches = map[int]map[string]string{}
		}
		f.patches[n] = body
		_, _ = w.Write([]byte(`{}`))
	default:
		f.t.Errorf("unexpected request %s %s", r.Method, r.URL)
		w.WriteHeader(http.StatusNotFound)
	}
}

func alert(n int, state, rule, path string, line int, comment string) codeScanningAlert {
	a := codeScanningAlert{Number: n, State: state, DismissedComment: comment}
	a.Rule.ID = rule
	a.Instance.Location.Path = path
	a.Instance.Location.StartLine = line
	return a
}

// suppressedData is a report with a rule accepted in two files and open in a third.
func suppressedData() report.Data {
	at := func(path string, line int, s *sarif.Suppression) sarif.Result {
		return sarif.Result{RuleID: "G304", Level: sarif.LevelWarning, Priority: "P2", Tool: "gosec",
			Location: sarif.Location{URI: path, StartLine: line}, Suppression: s}
	}
	run := engine.Result{Controls: map[string]plugin.ControlResult{
		"sast": {Control: "sast", Report: sarif.Report{Tool: "gosec", Results: []sarif.Result{
			at("pkg/engine/engine.go", 2450, &sarif.Suppression{Kind: "inSource", Justification: "a file the descriptor names for import"}),
			at("internal/preflight/preflight.go", 484, &sarif.Suppression{Kind: "external",
				Justification: "the path doctor was asked to check", Source: ".draugr/exclusions/tool-install.saga-fragment.yaml", Line: 12}),
			at("internal/scanners/repo.go", 118, nil),
		}}},
	}}
	return report.Data{Release: saga.Release{Version: "1.0"}, Run: run, Verdict: norn.Result{Verdict: norn.Fail}}
}

func publishTo(t *testing.T, fake *fakeCodeScanning, d report.Data) error {
	t.Helper()
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)
	ghEnv(t, srv.URL)
	p, err := For(saga.PublisherConfig{Kind: "github"})
	if err != nil {
		t.Fatal(err)
	}
	g := p.(githubPublisher)
	g.processingPoll, g.processingWait = time.Millisecond, time.Second
	art, err := report.Build(saga.ReportConfig{Format: "sarif"}, d)
	if err != nil {
		t.Fatal(err)
	}
	return g.Publish(context.Background(), []report.Artifact{art})
}

// A suppressed finding's alert is dismissed with the reason and where the exclusion is written, an
// unsuppressed one is left open, and an alert for a result this upload does not carry is not
// touched.
func TestGithubPublisherDismissesTheAlertsOfSuppressedFindings(t *testing.T) {
	fake := &fakeCodeScanning{t: t, statuses: []string{"pending", "complete"}, pageSize: 2, open: []codeScanningAlert{
		alert(1, "open", "G304", "pkg/engine/engine.go", 2450, ""),
		alert(2, "open", "G304", "internal/preflight/preflight.go", 484, ""),
		alert(3, "open", "G304", "internal/scanners/repo.go", 118, ""),
		alert(4, "open", "G204", "internal/git/git.go", 138, ""),
	}}
	if err := publishTo(t, fake, suppressedData()); err != nil {
		t.Fatal(err)
	}
	if fake.polls < 2 {
		t.Errorf("polled %d times, want to wait out a pending upload", fake.polls)
	}
	if fake.ref != "refs/heads/main" || fake.toolName == "" {
		t.Errorf("alerts listed for ref %q, tool %q", fake.ref, fake.toolName)
	}
	if len(fake.patches) != 2 {
		t.Fatalf("patched %v, want alerts 1 and 2 only", fake.patches)
	}
	if got := fake.patches[1]; got["state"] != "dismissed" || got["dismissed_reason"] != "won't fix" ||
		got["dismissed_comment"] != "Accepted in Draugr: a file the descriptor names for import" {
		t.Errorf("alert 1 = %v", got)
	}
	if got := fake.patches[2]["dismissed_comment"]; got != "Accepted in Draugr: the path doctor was asked to check (.draugr/exclusions/tool-install.saga-fragment.yaml:12)" {
		t.Errorf("alert 2 comment = %q", got)
	}
}

// An alert Draugr dismissed earlier is reopened once its finding is no longer suppressed, such as an
// exclusion that expired. One a person dismissed stays as they left it.
func TestGithubPublisherReopensOnlyItsOwnDismissals(t *testing.T) {
	fake := &fakeCodeScanning{t: t, dismissed: []codeScanningAlert{
		alert(7, "dismissed", "G304", "internal/scanners/repo.go", 118, "Accepted in Draugr: expired since"),
		alert(8, "dismissed", "G304", "internal/scanners/repo.go", 118, "false positive, see the thread"),
		alert(9, "dismissed", "G304", "pkg/engine/engine.go", 2450, "Accepted in Draugr: a file the descriptor names for import"),
	}}
	if err := publishTo(t, fake, suppressedData()); err != nil {
		t.Fatal(err)
	}
	if len(fake.patches) != 1 || fake.patches[7]["state"] != "open" {
		t.Errorf("patched %v, want only alert 7 reopened", fake.patches)
	}
}

// Nothing is left disagreeing with the report without saying so: a processing failure, a wait that
// runs out and an update GitHub refuses are each an error, and the refusal names the alert after
// every other update has been tried.
func TestGithubPublisherSaysWhenTheTabDisagrees(t *testing.T) {
	cases := []struct {
		name string
		fake *fakeCodeScanning
		want string
	}{
		{"processing failed", &fakeCodeScanning{statuses: []string{"failed"}}, "could not process the upload: line 3: not a result"},
		{"never processed", &fakeCodeScanning{statuses: []string{"pending"}}, "had not processed the upload after 1s"},
		{"no upload id", &fakeCodeScanning{noID: true}, "returned no upload id"},
		{"update refused", &fakeCodeScanning{refuse: map[int]bool{1: true}, open: []codeScanningAlert{
			alert(1, "open", "G304", "pkg/engine/engine.go", 2450, ""),
			alert(2, "open", "G304", "internal/preflight/preflight.go", 484, ""),
		}}, "alert 1 (G304): 403 Forbidden"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c.fake.t = t
			err := publishTo(t, c.fake, suppressedData())
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
			if c.name == "update refused" && c.fake.patches[2] == nil {
				t.Error("a refused update stopped the ones after it")
			}
		})
	}
}

// The comment is what GitHub keeps of it, and a suppression with no reason says so rather than
// leaving the comment empty.
func TestDismissalComment(t *testing.T) {
	if got := dismissalComment("", "", 0); got != "Accepted in Draugr: no reason recorded" {
		t.Errorf("no reason = %q", got)
	}
	long := dismissalComment(strings.Repeat("word ", 100), "draugr.saga.yaml", 14)
	if n := len([]rune(long)); n != dismissalCommentLimit || !strings.HasSuffix(long, "… (draugr.saga.yaml:14)") {
		t.Errorf("long comment is %d runes and must keep where the exclusion is written: %q", n, long)
	}
	if got := dismissalComment("fixtures", "draugr.saga.yaml", 0); got != "Accepted in Draugr: fixtures (draugr.saga.yaml)" {
		t.Errorf("no line = %q", got)
	}
	if got := dismissalComment("folded\n  across\tlines", "", 0); got != "Accepted in Draugr: folded across lines" {
		t.Errorf("whitespace = %q", got)
	}
}

// The comment names the exclusion's file and line from the uploaded SARIF.
func TestUploadedResultsNameWhereTheExclusionIsWritten(t *testing.T) {
	doc := `{"runs":[{"tool":{"driver":{"name":"Draugr"}},"results":[
{"ruleId":"R","locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.go"},"region":{"startLine":1}}}],
 "suppressions":[{"kind":"external","justification":"fixtures","properties":{"source":"draugr.saga.yaml","line":14}}]}
]}]}`
	_, results, err := uploadedResults([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	got := results[alertKey{rule: "R", path: "a.go", line: 1}].comment
	if got != "Accepted in Draugr: fixtures (draugr.saga.yaml:14)" {
		t.Errorf("comment = %q", got)
	}
}

// One result open at a place keeps its alert open, whichever order the results come in, and a
// result with no location has no alert to match.
func TestUploadedResultsKeepAPlaceOpenIfAnyResultIsOpen(t *testing.T) {
	doc := `{"runs":[{"tool":{"driver":{"name":"Draugr"}},"results":[
{"ruleId":"R","locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.go"},"region":{"startLine":1}}}]},
{"ruleId":"R","locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.go"},"region":{"startLine":1}}}],"suppressions":[{"kind":"external","justification":"x"}]},
{"ruleId":"S","locations":[{"physicalLocation":{"artifactLocation":{"uri":"b.go"},"region":{"startLine":2}}}],"suppressions":[{"kind":"external","justification":"y"}]},
{"ruleId":"S","locations":[{"physicalLocation":{"artifactLocation":{"uri":"b.go"},"region":{"startLine":2}}}]},
{"ruleId":"T"}]}]}`
	tool, results, err := uploadedResults([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if tool != "Draugr" || len(results) != 2 {
		t.Fatalf("tool %q, results %v", tool, results)
	}
	for _, k := range []alertKey{{"R", "a.go", 1}, {"S", "b.go", 2}} {
		if results[k].suppressed {
			t.Errorf("%v is suppressed, want open", k)
		}
	}
	if _, _, err := uploadedResults([]byte("not json")); err == nil {
		t.Error("a SARIF that does not parse was read")
	}
}

// A run canceled while GitHub is still processing stops waiting.
func TestAwaitProcessingStopsWhenCanceled(t *testing.T) {
	fake := &fakeCodeScanning{t: t, statuses: []string{"pending"}}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	g := githubPublisher{repo: "acme/app", apiURL: srv.URL, client: http.DefaultClient,
		processingWait: time.Minute, processingPoll: time.Minute}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := g.awaitProcessing(ctx, "up-1"); err == nil {
		t.Error("waited past a canceled context")
	}
}
