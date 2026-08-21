package scanners

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

func TestGovulncheckInfo(t *testing.T) {
	info := NewGovulncheck().Info()
	if info.Name != "govulncheck" {
		t.Errorf("Name = %q, want govulncheck", info.Name)
	}
	if info.Binary != "govulncheck" {
		t.Errorf("Binary = %q, want govulncheck", info.Binary)
	}
	if got := info.Controls; len(got) != 1 || got[0] != "sca" {
		t.Errorf("Controls = %v, want [sca]", got)
	}
	if got := info.TargetKinds; len(got) != 1 || got[0] != plugin.TargetRepository {
		t.Errorf("TargetKinds = %v, want [repository]", got)
	}
}

func TestGovulncheckArgsRunsOncePerModule(t *testing.T) {
	// A repository is not required to be a Go module. A polyglot repository keeps its Go service
	// in a subdirectory and a monorepo keeps several, so running once at the root would answer
	// for whichever the root happens to be — or fail, when the root holds no go.mod at all.
	root := t.TempDir()
	for _, dir := range []string{"services/api", "services/worker", "vendor/example.com/dep", "app/testdata"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, dir, "go.mod"), []byte("module x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got := govulncheckArgs(root, plugin.Config{})
	if len(got) != 2 {
		t.Fatalf("got %d commands, want one per real module: %v", len(got), got)
	}
	for _, argv := range got {
		if argv[0] != "govulncheck" || argv[1] != "-C" {
			t.Errorf("argv = %v, want it to change into the module directory", argv)
		}
		if argv[len(argv)-1] != "./..." {
			t.Errorf("argv = %v, want ./... as the pattern", argv)
		}
		if strings.Contains(argv[2], "vendor") || strings.Contains(argv[2], "testdata") {
			t.Errorf("argv = %v: vendored and testdata modules are not part of the build", argv)
		}
	}
}

func TestGovulncheckArgsIsEmptyWithoutAGoModule(t *testing.T) {
	if got := govulncheckArgs(t.TempDir(), plugin.Config{}); len(got) != 0 {
		t.Fatalf("args = %v, want none for a repository with no Go module", got)
	}
}

func TestParseGovulncheckSaysWhenThereWasNothingToAnalyze(t *testing.T) {
	// A repository the analyzer could not answer for must not read like one where it looked and
	// found everything unreachable.
	report, err := parseGovulncheck(nil, "", plugin.Config{})
	if err != nil {
		t.Fatalf("no module should not be an error: %v", err)
	}
	if len(report.Results) != 0 {
		t.Errorf("results = %v, want none", report.Results)
	}
	if len(report.Provenance) != 1 || len(report.Provenance[0].Fields) != 1 {
		t.Fatalf("provenance = %+v, want one statement about coverage", report.Provenance)
	}
	if !strings.Contains(report.Provenance[0].Fields[0].Value, "no go.mod") {
		t.Errorf("provenance = %q, want it to say why nothing was analyzed", report.Provenance[0].Fields[0].Value)
	}
}

// TestParseGovulncheckReachability is the test the design rests on: real output from
// govulncheck, in which two of four vulnerabilities in one module are called and two are not.
// One repository would prove the loop runs; this proves the two verdicts do not collapse into
// one answer for the module.
func TestParseGovulncheckReachability(t *testing.T) {
	out, err := os.ReadFile("testdata/govulncheck-reachable.json")
	if err != nil {
		t.Fatal(err)
	}
	report, err := parseGovulncheck(out, "", plugin.Config{})
	if err != nil {
		t.Fatalf("parseGovulncheck: %v", err)
	}

	byRule := map[string]sarif.Result{}
	for _, r := range report.Results {
		byRule[r.RuleID] = r
	}

	want := map[string]sarif.ReachabilityState{
		"CVE-2022-32149": sarif.ReachabilityReachable,   // ParseAcceptLanguage is called
		"CVE-2021-38561": sarif.ReachabilityReachable,   // same call path
		"CVE-2020-14040": sarif.ReachabilityUnreachable, // module in the build, nothing calls it
		"CVE-2026-56852": sarif.ReachabilityUnreachable,
	}
	if len(report.Results) != len(want) {
		t.Fatalf("got %d results, want %d: %v", len(report.Results), len(want), byRule)
	}
	for rule, state := range want {
		res, ok := byRule[rule]
		if !ok {
			t.Fatalf("no result for %s (got %v)", rule, byRule)
		}
		if res.Reachability == nil {
			t.Fatalf("%s: no reachability", rule)
		}
		if res.Reachability.State != state {
			t.Errorf("%s: state = %q, want %q", rule, res.Reachability.State, state)
		}
		if res.Package == nil || res.Package.Name != "golang.org/x/text" {
			t.Errorf("%s: package = %+v, want golang.org/x/text", rule, res.Package)
		}
		if res.Package != nil && res.Package.PURL != "pkg:golang/golang.org/x/text@v0.3.0" {
			t.Errorf("%s: purl = %q", rule, res.Package.PURL)
		}
		if res.Reachability.Analyzer != "govulncheck" || res.Reachability.Method != "call-graph" {
			t.Errorf("%s: analyzer/method = %q/%q", rule, res.Reachability.Analyzer, res.Reachability.Method)
		}
	}

	// The call path is the evidence, and it reads caller first.
	reached := byRule["CVE-2022-32149"].Reachability
	if len(reached.Paths) == 0 {
		t.Fatal("reachable finding carries no call path")
	}
	frames := reached.Paths[0].Frames
	if len(frames) < 2 {
		t.Fatalf("call path has %d frames, want at least 2: %+v", len(frames), frames)
	}
	if frames[0].Function != "main" {
		t.Errorf("first frame = %q, want the caller (main)", frames[0].Function)
	}
	if last := frames[len(frames)-1]; last.Function != "ParseAcceptLanguage" {
		t.Errorf("last frame = %q, want the vulnerable symbol", last.Function)
	}

	// An unreachable finding names the symbols that would have to be called, so the verdict can
	// be checked by hand.
	unreached := byRule["CVE-2020-14040"].Reachability
	if len(unreached.Paths) != 0 {
		t.Errorf("unreachable finding carries call paths: %+v", unreached.Paths)
	}
	if len(unreached.Symbols) == 0 {
		t.Error("unreachable finding names no vulnerable symbols")
	}
}

// TestParseGovulncheckWillNotClaimUnreachableWithoutGrounds is the safety property the whole
// three-state model exists for: an analysis that did not run must not look like one that found
// nothing reachable.
func TestParseGovulncheckWillNotClaimUnreachableWithoutGrounds(t *testing.T) {
	// A module-level scan sees no calls at all, so "nothing calls it" is not something it could
	// have found out.
	stream := `{"config":{"scan_level":"module","scan_mode":"source"}}
{"SBOM":{"modules":[{"path":"golang.org/x/text","version":"v0.3.0"}]}}
{"osv":{"id":"GO-2020-0015","summary":"s","aliases":["CVE-2020-14040"]}}
{"finding":{"osv":"GO-2020-0015","trace":[{"module":"golang.org/x/text","version":"v0.3.0"}]}}`
	report, err := parseGovulncheck([]byte(stream), "", plugin.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Results) != 1 {
		t.Fatalf("results = %d, want 1", len(report.Results))
	}
	if got := report.Results[0].Reachability.State; got != sarif.ReachabilityUnknown {
		t.Errorf("state = %q, want unknown — a module scan cannot see a call", got)
	}
}

func TestParseGovulncheckWillNotClaimUnreachableForAModuleItNeverSaw(t *testing.T) {
	// The other half: symbol level, but the module is absent from what the run analyzed.
	stream := `{"config":{"scan_level":"symbol","scan_mode":"source"}}
{"SBOM":{"modules":[{"path":"example.com/app"}]}}
{"osv":{"id":"GO-2020-0015","summary":"s","aliases":["CVE-2020-14040"]}}
{"finding":{"osv":"GO-2020-0015","trace":[{"module":"golang.org/x/text","version":"v0.3.0"}]}}`
	report, err := parseGovulncheck([]byte(stream), "", plugin.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if got := report.Results[0].Reachability.State; got != sarif.ReachabilityUnknown {
		t.Errorf("state = %q, want unknown — the module was not in what was analyzed", got)
	}
}

func TestParseGovulncheckReportsEachCVEAnAdvisoryHas(t *testing.T) {
	// A manifest scanner reports one finding per CVE, so an advisory with several has to become
	// several — emitting one would leave the rest with no reachability while looking complete.
	stream := `{"config":{"scan_level":"symbol"}}
{"SBOM":{"modules":[{"path":"m","version":"v1"}]}}
{"osv":{"id":"GO-2021-0159","summary":"s","aliases":["CVE-2015-5739","CVE-2015-5740"]}}
{"finding":{"osv":"GO-2021-0159","trace":[{"module":"m","version":"v1"}]}}`
	report, err := parseGovulncheck([]byte(stream), "", plugin.Config{})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, r := range report.Results {
		got[r.RuleID] = true
	}
	if !got["CVE-2015-5739"] || !got["CVE-2015-5740"] || len(got) != 2 {
		t.Errorf("rule ids = %v, want both CVEs", got)
	}
}

func TestParseGovulncheckFallsBackToTheGoAdvisoryID(t *testing.T) {
	// An advisory with no CVE still has to be reportable, under an id a suppression can name.
	stream := `{"config":{"scan_level":"symbol"}}
{"SBOM":{"modules":[{"path":"m","version":"v1"}]}}
{"osv":{"id":"GO-2026-9999","summary":"s"}}
{"finding":{"osv":"GO-2026-9999","trace":[{"module":"m","version":"v1"}]}}`
	report, err := parseGovulncheck([]byte(stream), "", plugin.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Results) != 1 || report.Results[0].RuleID != "GO-2026-9999" {
		t.Errorf("rule id = %+v, want the GO advisory id", report.Results)
	}
}

func TestParseGovulncheckRejectsUnreadableOutput(t *testing.T) {
	// A tool whose output cannot be read has not reported "no vulnerabilities".
	if _, err := parseGovulncheck([]byte("{not json"), "", plugin.Config{}); err == nil {
		t.Fatal("want an error for output that is not the stream govulncheck writes")
	}
}

func TestParseGovulncheckEmptyOutputIsACleanRun(t *testing.T) {
	report, err := parseGovulncheck([]byte(""), "", plugin.Config{})
	if err != nil {
		t.Fatalf("empty output should not error: %v", err)
	}
	if len(report.Results) != 0 {
		t.Errorf("results = %d, want none", len(report.Results))
	}
}

func TestGovulncheckPathSummaryPicksTheShortest(t *testing.T) {
	// What a reader needs before deciding whether to open the full evidence.
	paths := []sarif.CallPath{
		{Frames: []sarif.CallFrame{{Function: "a"}, {Function: "b"}, {Function: "c"}}},
		{Frames: []sarif.CallFrame{{Function: "a"}, {Function: "c"}}},
	}
	if got := govulncheckPathSummary(paths); got != "a → c" {
		t.Errorf("summary = %q, want the shortest path", got)
	}
	if got := govulncheckPathSummary(nil); got != "a call path exists" {
		t.Errorf("summary with no paths = %q", got)
	}
}
