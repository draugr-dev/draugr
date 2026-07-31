package report

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/sbom"
)

// update rewrites the golden files instead of comparing against them:
//
//	go test ./pkg/report -update
var update = flag.Bool("update", false, "rewrite the console golden files")

// The console layout is copied by hand into six documents and recaptured in the demo screenshot,
// and
// none of those notice when it changes. The assertions elsewhere in this package check that
// particular strings are present, which is the wrong shape for a *layout*: column widths, blank
// lines and ordering are exactly what a reader compares against their own terminal, and exactly
// what a `strings.Contains` check cannot see.
//
// So the whole frame is pinned. Any change to it fails here, at the pull request that made it,
// with a list of the artifacts that now disagree — see goldenMismatch below. Regenerating is one
// flag; the point is that it can't happen by accident.
func TestConsoleGolden(t *testing.T) {
	for _, tc := range []struct {
		name string
		data Data
	}{
		{"full", goldenFullData()},
		{"clean", goldenCleanData()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var b bytes.Buffer
			if err := (consoleReporter{}).Render(&b, tc.data); err != nil {
				t.Fatal(err)
			}
			assertGolden(t, filepath.Join("testdata", "console-"+tc.name+".golden"), b.Bytes())
		})
	}
}

func assertGolden(t *testing.T, path string, got []byte) {
	t.Helper()
	if *update {
		if err := os.WriteFile(path, got, 0o600); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s", path)
		return
	}
	want, err := os.ReadFile(path) //nolint:gosec // a fixed path under testdata/
	if err != nil {
		t.Fatalf("read golden: %v (run: go test ./pkg/report -update)", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s\n--- want ---\n%s\n--- got ---\n%s", goldenMismatch(path), want, got)
	}
}

// goldenMismatch names the artifacts that a console-layout change invalidates. The failure is
// the only moment anyone is looking at this, so it carries the checklist rather than a doc
// pointing at one.
func goldenMismatch(path string) string {
	return "console output changed — " + path + " is stale.\n\n" +
		"If the change is intended, regenerate and refresh what copies this layout:\n" +
		"  1. go test ./pkg/report -update\n" +
		"  2. make examples          # real output from the demo sandbox, to paste into docs\n" +
		"  3. update what quotes or describes the layout:\n" +
		"     README.md, docs/concepts/verdict-and-gating.md (pasted output),\n" +
		"     docs/reference/cli.md, docs/concepts/principles.md,\n" +
		"     docs/guides/findings-in-your-editor.md (described, not pasted)\n" +
		"  4. update the blog posts in the draugr.dev repo that quote console output:\n" +
		"     src/content/blog/{security-scan-in-60-seconds,what-scanner-output-costs-your-agent}.md\n" +
		"     (grep for 'Draugr — ' there; they are a separate repo, so nothing else will catch them)\n" +
		"  5. recapture the demo screenshot:\n" +
		"     gh workflow run 'Demo screenshot' --repo draugr-dev/draugr\n"
}

// goldenFullData exercises every element of the frame at once: a failing verdict with a release,
// priority counts, controls spanning all four severity bands, a control that errored, the
// suppression and SBOM evidence lines, a rule id long enough to be shortened, more findings than
// the table shows, findings attributed to two different components, and a scanner's account of
// what it measured.
//
// Every element, because an element the fixture omits is an element the golden does not pin —
// and the layout is copied into six documents, two blog posts and a recorded GIF that nothing
// else checks.
func goldenFullData() Data {
	sca := []sarif.Result{
		{RuleID: "CVE-2019-20477", Level: sarif.LevelError, Score: 9.8, HasScore: true, Priority: "P1",
			Tool: "trivy", Component: "payments", Location: sarif.Location{URI: "app/requirements.txt", StartLine: 4},
			Message: "PyYAML: command execution through python/object/apply constructor in FullLoader"},
		{RuleID: "CVE-2019-10906", Level: sarif.LevelError, Score: 8.6, HasScore: true, Priority: "P1",
			Tool: "trivy", Component: "payments", Location: sarif.Location{URI: "app/requirements.txt", StartLine: 5},
			Message: "python-jinja2: str.format_map allows sandbox escape"},
		{RuleID: "CVE-2018-1000656", Level: sarif.LevelWarning, Score: 7.5, HasScore: true, Priority: "P2",
			Tool: "trivy", Component: "internal-tool", Location: sarif.Location{URI: "app/requirements.txt", StartLine: 2},
			Message: "python-flask: Denial of Service via crafted JSON file"},
		{RuleID: "CVE-2020-28493", Level: sarif.LevelNote, Priority: "P4", Tool: "trivy",
			Location: sarif.Location{URI: "app/requirements.txt", StartLine: 5}, Message: "jinja2: ReDoS"},
	}
	iac := []sarif.Result{
		{RuleID: "DS-0002", Level: sarif.LevelError, Score: 8.0, HasScore: true, Priority: "P1",
			Tool: "trivy", Component: "payments", Location: sarif.Location{URI: "app/Dockerfile", StartLine: 1},
			Message: "Image user should not be 'root'"},
		{RuleID: "KSV-0014", Level: sarif.LevelWarning, Score: 5.5, HasScore: true, Priority: "P3",
			Tool: "trivy", Location: sarif.Location{URI: "deploy/pod.yaml", StartLine: 8},
			Message: "Root file system is not read-only"},
	}
	sast := []sarif.Result{
		{RuleID: "python.flask.security.injection.tainted-sql-string.tainted-sql-string",
			Level: sarif.LevelError, Priority: "P2", Tool: "semgrep",
			Location: sarif.Location{URI: "app/main.py", StartLine: 42},
			Message:  "Detected user input flowing into a raw SQL string"},
	}
	licenses := []sarif.Result{
		{RuleID: "license/GPL-3.0-only/some-lib", Level: sarif.LevelWarning, Priority: "P3",
			Tool: "trivy-license", Location: sarif.Location{URI: "go.mod", StartLine: 17},
			Message: "some-lib is GPL-3.0-only. Copyleft."},
	}
	run := engine.Result{
		Controls: map[string]plugin.ControlResult{
			"sca": {Control: "sca", Report: sarif.Report{Tool: "trivy", Results: sca}},
			"iac": {Control: "iac", Report: sarif.Report{Tool: "trivy", Results: iac,
				Provenance: []sarif.Provenance{{Tool: "trivy", Version: "0.69.3"}}}},
			"sast": {Control: "sast", Report: sarif.Report{Tool: "semgrep", Results: sast}},
			"licenses": {Control: "licenses", Report: sarif.Report{Tool: "trivy-license", Results: licenses,
				Provenance: []sarif.Provenance{{Tool: "trivy-license", Version: "0.69.3",
					Fields: []sarif.Field{{Key: "policy", Value: "deny copyleft"}}}}}},
		},
		ScanErrors: map[string][]string{"dast": {"nuclei: executable file not found in $PATH"}},
		Suppressed: 2,
		SBOMs:      []sbom.Document{{Format: "spdx-json"}, {Format: "spdx-json"}},
	}
	verdict := norn.Result{Verdict: norn.Fail, Controls: []norn.ControlOutcome{
		{Control: "iac", Verdict: norn.Fail, Counts: sarif.Counts{Error: 1, Warning: 1}},
		{Control: "licenses", Verdict: norn.Pass, Counts: sarif.Counts{Warning: 1}},
		{Control: "sast", Verdict: norn.Fail, Counts: sarif.Counts{Error: 1}},
		{Control: "sca", Verdict: norn.Fail, Counts: sarif.Counts{Error: 2, Warning: 1, Note: 1}},
	}}
	return Data{
		Release: saga.Release{Name: "draugr-demo", Version: "0.0.0"},
		Run:     run,
		Verdict: verdict,
		TopN:    5, // fewer than the findings above, so the truncation line is pinned too
	}
}

// goldenCleanData pins the other frame users see: nothing found, and the report has to say so
// without implying more than it checked.
func goldenCleanData() Data {
	return Data{
		Release: saga.Release{Name: "my-app", Version: "1.0"},
		Run: engine.Result{Controls: map[string]plugin.ControlResult{
			"images": {Control: "images", Report: sarif.Report{Tool: "trivy"}},
		}},
		Verdict: norn.Result{Verdict: norn.Pass, Controls: []norn.ControlOutcome{
			{Control: "images", Verdict: norn.Pass},
		}},
	}
}
