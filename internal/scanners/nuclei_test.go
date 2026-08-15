package scanners

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	"os"

	"path/filepath"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

func TestNucleiInfo(t *testing.T) {
	info := NewNuclei().Info()
	if info.Name != "nuclei" {
		t.Errorf("name = %q", info.Name)
	}
	if info.Binary != "nuclei" {
		t.Errorf("binary = %q", info.Binary)
	}
	if len(info.Controls) != 1 || info.Controls[0] != "dast" {
		t.Errorf("controls = %v", info.Controls)
	}
	if len(info.TargetKinds) != 1 || info.TargetKinds[0] != plugin.TargetHost {
		t.Errorf("targetKinds = %v", info.TargetKinds)
	}
}

func TestNucleiArgv(t *testing.T) {
	got := nucleiArgv("https://app.example.com", "")
	want := []string{
		"nuclei", "-u", "https://app.example.com",
		"-jsonl", "-silent", "-nc", "-duc", "-etags", "headers",
	}
	if len(got) != len(want) {
		t.Fatalf("argv = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("argv[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestNucleiToResultsSeverities(t *testing.T) {
	// One finding per severity, plus a blank line and a malformed line (both skipped).
	jsonl := strings.Join([]string{
		`{"template-id":"crit","matched-at":"https://x/a","info":{"name":"Crit","severity":"critical"}}`,
		`{"template-id":"high","matched-at":"https://x/b","info":{"name":"High","severity":"high"}}`,
		`{"template-id":"med","matched-at":"https://x/c","info":{"name":"Med","severity":"medium"}}`,
		`{"template-id":"low","matched-at":"https://x/d","info":{"name":"Low","severity":"low"}}`,
		`{"template-id":"info","matched-at":"https://x/e","info":{"name":"Info","severity":"info"}}`,
		`{"template-id":"unknown","matched-at":"https://x/f","info":{"name":"Unknown","severity":"weird"}}`,
		``,
		`{not valid json`,
	}, "\n")

	results := nucleiToResults([]byte(jsonl))
	if len(results) != 6 {
		t.Fatalf("want 6 results (blank + malformed skipped), got %d", len(results))
	}

	byRule := make(map[string]sarif.Result, len(results))
	for _, r := range results {
		if r.Tool != "nuclei" {
			t.Errorf("tool = %q", r.Tool)
		}
		byRule[r.RuleID] = r
	}

	for _, tc := range []struct {
		rule     string
		level    sarif.Level
		score    float64
		hasScore bool
	}{
		{"crit", sarif.LevelError, 9.5, true},
		{"high", sarif.LevelError, 8.0, true},
		{"med", sarif.LevelWarning, 5.0, true},
		{"low", sarif.LevelNote, 2.0, true},
		{"info", sarif.LevelNote, 1.0, true},
		{"unknown", sarif.LevelNote, 0, false},
	} {
		r, ok := byRule[tc.rule]
		if !ok {
			t.Errorf("missing result for %q", tc.rule)
			continue
		}
		if r.Level != tc.level {
			t.Errorf("%s level = %q, want %q", tc.rule, r.Level, tc.level)
		}
		if r.Score != tc.score || r.HasScore != tc.hasScore {
			t.Errorf("%s score = %v/%v, want %v/%v", tc.rule, r.Score, r.HasScore, tc.score, tc.hasScore)
		}
	}
}

func TestNucleiToResultsMessageAndCWE(t *testing.T) {
	jsonl := `{"template-id":"xss","matched-at":"https://x/q","info":{"name":"Reflected XSS","severity":"high","description":"input reflected","classification":{"cwe-id":["CWE-79","CWE-80"]}}}`
	results := nucleiToResults([]byte(jsonl))
	if len(results) != 1 {
		t.Fatalf("want 1 result, got %d", len(results))
	}
	msg := results[0].Message
	if !strings.Contains(msg, "Reflected XSS") || !strings.Contains(msg, "input reflected") {
		t.Errorf("message missing name/description: %q", msg)
	}
	if !strings.Contains(msg, "CWE-79") || !strings.Contains(msg, "CWE-80") {
		t.Errorf("message missing CWEs: %q", msg)
	}
}

func TestNucleiToResultsMessageFallsBackToTemplateID(t *testing.T) {
	jsonl := `{"template-id":"only-id","matched-at":"https://x/z","info":{"severity":"info"}}`
	results := nucleiToResults([]byte(jsonl))
	if len(results) != 1 || results[0].Message != "only-id" {
		t.Fatalf("expected message to fall back to template-id, got %+v", results)
	}
}

func TestNucleiToResultsURIFallbackToHost(t *testing.T) {
	jsonl := `{"template-id":"t","host":"https://host.example.com","info":{"severity":"info"}}`
	results := nucleiToResults([]byte(jsonl))
	if len(results) != 1 {
		t.Fatalf("want 1 result, got %d", len(results))
	}
	if results[0].Location.URI != "https://host.example.com" {
		t.Errorf("uri = %q, want host fallback", results[0].Location.URI)
	}
}

func TestNucleiToResultsEmpty(t *testing.T) {
	if got := nucleiToResults(nil); got != nil {
		t.Errorf("empty input should yield no results, got %v", got)
	}
}

func TestNucleiScan(t *testing.T) {
	var gotArgv []string
	s := nucleiScanner{
		info: NewNuclei().Info(),
		run: func(_ context.Context, argv []string) ([]byte, error) {
			gotArgv = argv
			return []byte(`{"template-id":"t","matched-at":"https://x/a","info":{"name":"T","severity":"high"}}`), nil
		},
	}
	rep, err := s.Scan(context.Background(), plugin.HostTarget{URL: "https://x"}, nil)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if rep.Tool != "nuclei" {
		t.Errorf("tool = %q", rep.Tool)
	}
	if len(rep.Results) != 1 || rep.Results[0].Level != sarif.LevelError {
		t.Errorf("results = %+v", rep.Results)
	}
	if len(gotArgv) == 0 || gotArgv[2] != "https://x" {
		t.Errorf("argv not built from URL: %v", gotArgv)
	}
}

func TestNucleiScanErrors(t *testing.T) {
	s := NewNuclei()
	// Wrong target type.
	if _, err := s.Scan(context.Background(), plugin.ImageTarget{Ref: "x"}, nil); err == nil {
		t.Error("expected error for non-host target")
	}
	// Empty URL.
	if _, err := s.Scan(context.Background(), plugin.HostTarget{}, nil); err == nil {
		t.Error("expected error for empty URL")
	}
	// Run failure.
	failing := nucleiScanner{
		info: s.Info(),
		run:  func(context.Context, []string) ([]byte, error) { return nil, errors.New("boom") },
	}
	if _, err := failing.Scan(context.Background(), plugin.HostTarget{URL: "https://x"}, nil); err == nil {
		t.Error("expected error when run fails")
	}
}

// templatesPresent is what `nuclei -templates-version` prints when a template set is installed.
const templatesPresent = "[INF] Public nuclei-templates version: v10.4.6 (/home/u/nuclei-templates)\n"

// templatesAbsent is the same line with the version blank — what it prints when there are none.
// Nuclei exits 0 for both, which is why the warm step cannot trust the exit code.
const templatesAbsent = "[INF] Public nuclei-templates version:  (/home/u/nuclei-templates)\n"

func TestNucleiPrewarmDownloadsThenVerifies(t *testing.T) {
	// -duc is right on a scan and was wrong here: on `-update-templates` it disables the update
	// itself, so the command exited 0 having downloaded nothing and dast could never run.
	var argvs [][]string
	w := &nucleiTemplateWarmer{run: func(_ context.Context, argv []string) ([]byte, error) {
		argvs = append(argvs, argv)
		return []byte(templatesPresent), nil
	}}
	if err := w.warm(context.Background()); err != nil {
		t.Fatalf("warm: %v", err)
	}
	want := [][]string{{"nuclei", "-update-templates"}, {"nuclei", "-templates-version"}}
	if !reflect.DeepEqual(argvs, want) {
		t.Errorf("argv = %v, want %v", argvs, want)
	}
	for _, argv := range argvs {
		if slices.Contains(argv, "-duc") {
			t.Errorf("-duc cancels the update it is attached to: %v", argv)
		}
	}
}

func TestNucleiPrewarmIsMemoized(t *testing.T) {
	calls := 0
	w := &nucleiTemplateWarmer{run: func(context.Context, []string) ([]byte, error) {
		calls++
		return []byte(templatesPresent), nil
	}}
	for range 3 {
		if err := w.warm(context.Background()); err != nil {
			t.Fatalf("warm: %v", err)
		}
	}
	if calls != 2 {
		t.Errorf("ran %d commands, want 2 (download + verify, once)", calls)
	}
}

func TestNucleiPrewarmFailsWhenNothingWasDownloaded(t *testing.T) {
	// The check that would have caught this shipping: Nuclei exits 0 whether or not it fetched
	// anything, so the only honest confirmation is to ask afterwards what it has.
	w := &nucleiTemplateWarmer{run: func(_ context.Context, argv []string) ([]byte, error) {
		if argv[1] == "-templates-version" {
			return []byte(templatesAbsent), nil
		}
		return nil, nil
	}}
	err := w.warm(context.Background())
	if err == nil {
		t.Fatal("expected an error: a successful exit with no templates is the bug")
	}
	if !strings.Contains(err.Error(), "no template set") {
		t.Errorf("the error should name the cause, got %v", err)
	}
}

func TestNucleiPrewarmReportsADownloadFailure(t *testing.T) {
	w := &nucleiTemplateWarmer{run: func(context.Context, []string) ([]byte, error) {
		return nil, errors.New("no route to host")
	}}
	if err := w.warm(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "download nuclei templates") {
		t.Errorf("want a download error, got %v", err)
	}
}

func TestNucleiPrewarmReportsAFailedCheck(t *testing.T) {
	w := &nucleiTemplateWarmer{run: func(_ context.Context, argv []string) ([]byte, error) {
		if argv[1] == "-templates-version" {
			return nil, errors.New("exec failed")
		}
		return nil, nil
	}}
	if err := w.warm(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "check nuclei templates") {
		t.Errorf("want a check error, got %v", err)
	}
}

func TestNucleiScanReportsTheMissingTemplatesRatherThanTheSymptom(t *testing.T) {
	// Nuclei's own message is "no templates provided for scan", which reads as a mistake in the
	// descriptor and sends the reader to the wrong place entirely.
	warmer := &nucleiTemplateWarmer{run: func(_ context.Context, argv []string) ([]byte, error) {
		if argv[1] == "-templates-version" {
			return []byte(templatesAbsent), nil
		}
		return nil, nil
	}}
	_ = warmer.warm(context.Background())

	ran := false
	s := nucleiScanner{
		info: plugin.ScannerInfo{Name: "nuclei"},
		run: func(context.Context, []string) ([]byte, error) {
			ran = true
			return nil, nil
		},
		templates: warmer,
	}
	_, err := s.Scan(context.Background(), plugin.HostTarget{URL: "https://x"}, nil)
	if err == nil || !strings.Contains(err.Error(), "no templates") {
		t.Fatalf("want the template failure, got %v", err)
	}
	if ran {
		t.Error("the scan should not run at all without templates")
	}
}

func TestNucleiPrewarmDelegates(t *testing.T) {
	// The scanner's Prewarm delegates to a warmer; verify it runs without touching the real
	// binary by swapping the shared warmer for a fake.
	calls := 0
	orig := sharedNucleiTemplates
	t.Cleanup(func() { sharedNucleiTemplates = orig })
	sharedNucleiTemplates = &nucleiTemplateWarmer{run: func(context.Context, []string) ([]byte, error) {
		calls++
		return []byte(templatesPresent), nil
	}}
	if err := NewNuclei().(plugin.Prewarmer).Prewarm(context.Background()); err != nil {
		t.Fatalf("Prewarm: %v", err)
	}
	if calls != 2 {
		t.Errorf("Prewarm ran %d commands, want 2 (download + verify)", calls)
	}
}

// TestNucleiCredentialNeverReachesArgv is the assertion this feature exists to keep. A token on
// the command line is readable by every user on the machine for as long as the scan runs, so it
// travels in a file Nuclei is pointed at instead.
func TestNucleiCredentialNeverReachesArgv(t *testing.T) {
	t.Setenv("DRAUGR_TEST_API_TOKEN", "s3cret-value")
	var argv []string
	s := nucleiScanner{
		info: plugin.ScannerInfo{Name: "nuclei"},
		run: func(_ context.Context, a []string) ([]byte, error) {
			argv = a
			return nil, nil
		},
	}
	target := plugin.HostTarget{
		URL:  "https://api.example.com",
		Auth: &plugin.HostAuth{Kind: "bearer", TokenEnv: "DRAUGR_TEST_API_TOKEN"}, // #nosec G101 -- the name of an environment variable, which is the point: no credential is expressible here
	}
	if _, err := s.Scan(context.Background(), target, nil); err != nil {
		t.Fatal(err)
	}
	for _, a := range argv {
		if strings.Contains(a, "s3cret-value") {
			t.Fatalf("the credential is in the command line, where a process list will show it: %v", argv)
		}
	}
	i := slices.Index(argv, "-H")
	if i < 0 || i == len(argv)-1 {
		t.Fatalf("no -H pointing at a header file: %v", argv)
	}
	// The file is gone by now — Scan removes it — so the check is that a path was passed, not the
	// header itself.
	if strings.Contains(argv[i+1], ":") {
		t.Errorf("-H was given a header rather than a path: %q", argv[i+1])
	}
}

func TestNucleiHeaderFileIsPrivateAndRemoved(t *testing.T) {
	path, cleanup, err := writeHeaderFile("Authorization: Bearer x")
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("header file mode = %o, want 600 — it holds a credential", perm)
	}
	body, err := os.ReadFile(path) // #nosec G304 -- a path this test just created
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(body)); got != "Authorization: Bearer x" {
		t.Errorf("header file contains %q", got)
	}
	cleanup()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("the credential file outlived the scan")
	}
}

// TestNucleiRefusesToScanUnauthenticatedByAccident covers the failure the whole feature is about:
// a descriptor asking for an authenticated scan, an unset variable, and a scan that would probe
// the login page and report a pass about the application behind it.
func TestNucleiRefusesToScanUnauthenticatedByAccident(t *testing.T) {
	t.Setenv("DRAUGR_TEST_MISSING_TOKEN", "")
	ran := false
	s := nucleiScanner{
		info: plugin.ScannerInfo{Name: "nuclei"},
		run:  func(context.Context, []string) ([]byte, error) { ran = true; return nil, nil },
	}
	target := plugin.HostTarget{
		URL:  "https://api.example.com",
		Auth: &plugin.HostAuth{Kind: "bearer", TokenEnv: "DRAUGR_TEST_MISSING_TOKEN"}, // #nosec G101 -- the name of an environment variable, which is the point: no credential is expressible here
	}
	_, err := s.Scan(context.Background(), target, nil)
	if err == nil {
		t.Fatal("an unset credential must fail, not quietly scan anonymously")
	}
	if !strings.Contains(err.Error(), "DRAUGR_TEST_MISSING_TOKEN") {
		t.Errorf("the error should name the variable to set: %v", err)
	}
	if ran {
		t.Error("nuclei ran anyway")
	}
}

func TestAuthHeader(t *testing.T) {
	t.Setenv("DRAUGR_TEST_TOK", "abc123")
	for _, c := range []struct {
		name string
		auth *plugin.HostAuth
		want string
		err  bool
	}{
		{"anonymous", nil, "", false},
		{"bearer", &plugin.HostAuth{Kind: "bearer", TokenEnv: "DRAUGR_TEST_TOK"}, // #nosec G101 -- the name of an environment variable, which is the point: no credential is expressible here
			"Authorization: Bearer abc123", false},
		{"named header", &plugin.HostAuth{Kind: "header", Header: "X-API-Key", TokenEnv: "DRAUGR_TEST_TOK"}, // #nosec G101 -- the name of an environment variable, which is the point: no credential is expressible here
			"X-API-Key: abc123", false},
		{"unknown kind", &plugin.HostAuth{Kind: "oauth", TokenEnv: "DRAUGR_TEST_TOK"}, "", true}, // #nosec G101 -- the name of an environment variable, which is the point: no credential is expressible here
	} {
		t.Run(c.name, func(t *testing.T) {
			got, err := authHeader(c.auth)
			if (err != nil) != c.err {
				t.Fatalf("err = %v, want error: %v", err, c.err)
			}
			if got != c.want {
				t.Errorf("header = %q, want %q", got, c.want)
			}
		})
	}
}

// TestNucleiProvenanceNamesTheVariableNotTheValue keeps the record honest and the secret out of
// it. A report says the scan authenticated so a reader can tell it apart from an anonymous one,
// which reaches a different application entirely.
func TestNucleiProvenanceNamesTheVariableNotTheValue(t *testing.T) {
	t.Setenv("DRAUGR_TEST_TOK", "abc123")
	s := nucleiScanner{
		info: plugin.ScannerInfo{Name: "nuclei"},
		run:  func(context.Context, []string) ([]byte, error) { return nil, nil },
	}
	rep, err := s.Scan(context.Background(), plugin.HostTarget{
		URL:  "https://api.example.com",
		Auth: &plugin.HostAuth{Kind: "bearer", TokenEnv: "DRAUGR_TEST_TOK"}, // #nosec G101 -- the name of an environment variable, which is the point: no credential is expressible here
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Provenance) != 1 {
		t.Fatalf("provenance = %+v", rep.Provenance)
	}
	var flat string
	for _, f := range rep.Provenance[0].Fields {
		flat += f.Key + "=" + f.Value + " "
	}
	if strings.Contains(flat, "abc123") {
		t.Fatalf("the credential is in the report: %s", flat)
	}
	for _, want := range []string{"authenticated=bearer", "$DRAUGR_TEST_TOK"} {
		if !strings.Contains(flat, want) {
			t.Errorf("provenance should record %q, got: %s", want, flat)
		}
	}
}

func TestNucleiSpecArgv(t *testing.T) {
	argv := nucleiSpecArgv("/tmp/prepared.yaml", "")
	for _, want := range [][2]string{{"-l", "/tmp/prepared.yaml"}, {"-im", "openapi"}} {
		i := slices.Index(argv, want[0])
		if i < 0 || argv[i+1] != want[1] {
			t.Errorf("argv missing %s %s: %v", want[0], want[1], argv)
		}
	}
	// Not optional: without it Nuclei refuses a specification whose required parameters it cannot
	// fill, which is most of them, and scans nothing at all.
	if !slices.Contains(argv, "-sfv") {
		t.Errorf("a spec-driven scan needs -sfv or it refuses the document: %v", argv)
	}
	if slices.Contains(argv, "-u") {
		t.Errorf("a spec-driven scan takes its targets from the document, not -u: %v", argv)
	}
}

// TestNucleiScanFromSpecUsesThePreparedDocument checks the whole path: the scanner is handed a
// rewritten file, not the descriptor's, and reports what it left out.
func TestNucleiScanFromSpecUsesThePreparedDocument(t *testing.T) {
	spec := writeSpec(t, specWithWrites)
	var argv []string
	s := nucleiScanner{
		info: plugin.ScannerInfo{Name: "nuclei"},
		run: func(_ context.Context, a []string) ([]byte, error) {
			argv = a
			return nil, nil
		},
	}
	rep, err := s.Scan(context.Background(), plugin.HostTarget{
		URL:  "https://staging.example.com",
		Spec: &plugin.HostSpec{Path: spec},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	handed := argv[slices.Index(argv, "-l")+1]
	if handed == spec {
		t.Error("the descriptor's own document was handed over, so nothing was filtered or pinned")
	}
	if _, err := os.Stat(handed); !os.IsNotExist(err) {
		t.Error("the rewritten document outlived the scan")
	}
	var flat string
	for _, f := range rep.Provenance[0].Fields {
		flat += f.Key + "=" + f.Value + " "
	}
	for _, want := range []string{"methods=get, head", "operations=2", "delete (1)", "post (1)"} {
		if !strings.Contains(flat, want) {
			t.Errorf("provenance should record %q, got: %s", want, flat)
		}
	}
}

func TestNucleiScanRejectsAnUnusableSpec(t *testing.T) {
	s := nucleiScanner{
		info: plugin.ScannerInfo{Name: "nuclei"},
		run:  func(context.Context, []string) ([]byte, error) { return nil, nil },
	}
	for _, c := range []struct{ name, url, path string }{
		{"missing document", "https://x.example.com", filepath.Join(t.TempDir(), "absent.yaml")},
		{"unusable endpoint", "not-a-url", writeSpec(t, specWithWrites)},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := s.Scan(context.Background(), plugin.HostTarget{
				URL: c.url, Spec: &plugin.HostSpec{Path: c.path},
			}, nil)
			if err == nil {
				t.Error("expected an error rather than a scan of something else")
			}
		})
	}
}
