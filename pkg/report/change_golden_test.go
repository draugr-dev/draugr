package report_test

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/draugr-dev/draugr/pkg/diff"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/report"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/skald"
)

// The repositories of the two components the change goldens describe, one each.
const (
	goldenAPIRepo = "https://github.com/acme/api"
	goldenWebRepo = "https://github.com/acme/web"
)

// TestChangeConsoleGolden pins the console a run prints when a gate on new findings judges it: a
// --base was compared and failOnNew is set. Beside TestConsoleGolden, and in this package because
// the change is drawn by pkg/diff, which imports pkg/report.
//
// Two components on two repositories, with every new finding in one of them, so a layout that
// collapsed the change onto one component or one repository would show it here.
func TestChangeConsoleGolden(t *testing.T) {
	for _, tc := range []struct {
		name string
		data report.Data
	}{
		{"change", changeData(report.ViewFindings, true)},
		{"change-actions", changeData(report.ViewActions, true)},
		{"change-compact", changeData(report.ViewCompact, true)},
		// The base compared with itself, under a whole run that fails its own gate: nothing is new,
		// so nothing is listed, and the verdict is the change's pass.
		{"change-nothing-new", changeData(report.ViewFindings, false)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("COLUMNS", "")
			reporter, err := report.For("console")
			if err != nil {
				t.Fatal(err)
			}
			var b bytes.Buffer
			if err := reporter.Render(&b, tc.data); err != nil {
				t.Fatal(err)
			}
			report.AssertGolden(t, filepath.Join("testdata", "console-"+tc.name+".golden"), b.Bytes())
		})
	}
}

// changeData is a run compared with its base under failOnNew: P2. With changed, api's repository
// gains two urllib3 advisories at P2 and a Semgrep finding at P3, and web is as it was; without, the
// head is the base.
func changeData(view report.View, changed bool) report.Data {
	base := []sarif.Result{
		changeResult("sca", "trivy", "CVE-2026-27205", "api", goldenAPIRepo, "requirements.txt", 1, "P3",
			"Information disclosure via improper caching of session data", flask()),
		changeResult("sca", "trivy", "CVE-2026-27205", "web", goldenWebRepo, "requirements.txt", 1, "P3",
			"Information disclosure via improper caching of session data", flask()),
		changeResult("sast", "semgrep", "python.flask.security.injection.tainted-sql-string.tainted-sql-string",
			"web", goldenWebRepo, "app/db.py", 42, "P1", "Detected user input flowing into a raw SQL string", nil),
	}
	head := append([]sarif.Result{}, base...)
	if changed {
		head = append(head,
			changeResult("sca", "trivy", "CVE-2025-66418", "api", goldenAPIRepo, "requirements.txt", 3, "P2",
				"Unbounded decompression chain leads to resource exhaustion", urllib3("2.6.0")),
			changeResult("sca", "trivy", "CVE-2025-66471", "api", goldenAPIRepo, "requirements.txt", 3, "P2",
				"urllib3 Streaming API improperly handles highly compressed data", urllib3("2.6.0")),
			changeResult("sast", "semgrep", "python.flask.security.audit.debug-enabled.debug-enabled",
				"api", goldenAPIRepo, "app.py", 12, "P3", "Detected Flask app with debug=True", nil))
	}
	baseReport := sarif.Report{Results: base, Provenance: []sarif.Provenance{
		{Tool: "trivy-fs", Fields: []sarif.Field{{Key: "repository", Value: goldenAPIRepo}, {Key: "revision", Value: "4f2a9c1e0b3d"}}},
		{Tool: "trivy-fs", Fields: []sarif.Field{{Key: "repository", Value: goldenWebRepo}, {Key: "revision", Value: "9d8e7f6a5b4c"}}},
	}}
	compared := diff.Compare(baseReport, sarif.Report{Results: head})
	compared.Gate = diff.Gate{FailOnPriority: "P2"}
	compared.Tripped = compared.GateNew("", "P2")

	byControl := map[string][]sarif.Result{}
	for _, r := range head {
		byControl[r.Control] = append(byControl[r.Control], r)
	}
	verdict := norn.Pass
	if len(compared.Tripped) > 0 {
		verdict = norn.Fail
	}
	return report.Data{
		Project: "acme",
		Release: saga.Release{Version: "2.3.0"},
		Run: engine.Result{Controls: map[string]plugin.ControlResult{
			"sca":  {Control: "sca", Report: sarif.Report{Tool: "trivy", Results: byControl["sca"]}},
			"sast": {Control: "sast", Report: sarif.Report{Tool: "semgrep", Results: byControl["sast"]}},
			// A coverage statement, which qualifies the change as much as the whole run.
			"provenance": {Control: "provenance", Report: sarif.Report{Tool: "cosign", Provenance: []sarif.Provenance{{
				Tool: "cosign", Fields: []sarif.Field{{Key: "coverage", Value: "1 of 2 images checked, 1 unsigned"}},
			}}}},
		}},
		// The whole run fails its own gate on web's P1, and that decides nothing.
		Verdict: norn.Result{Verdict: verdict, Controls: []norn.ControlOutcome{
			{Control: "provenance", Verdict: norn.Pass},
			{Control: "sast", Verdict: norn.Fail},
			{Control: "sca", Verdict: norn.Pass},
		}},
		View: view,
		Gate: report.GateSettings{
			FailOnNew:     "P2",
			FailOnNewFrom: "config.gate.failOnNew",
			New: &skald.NewFindings{
				Base:       sarif.RepositoriesIn([]sarif.Report{baseReport}),
				Introduced: compared.Counted().New,
				Tripped:    len(compared.Tripped) > 0,
			},
			BasePath: "base/results.sarif",
			WholeRun: norn.Fail,
		},
		Change: diff.ScanView{Result: compared},
	}
}

// changeResult is one finding as a scan's results.sarif carries it.
func changeResult(control, tool, rule, component, repo, uri string, line int, priority, message string,
	pkg *sarif.Package,
) sarif.Result {
	level := sarif.LevelWarning
	if priority == "P1" {
		level = sarif.LevelError
	}
	return sarif.Result{
		Control: control, Tool: tool, RuleID: rule, Level: level, Priority: priority, Message: message,
		Component: component, Repository: repo, Location: sarif.Location{URI: uri, StartLine: line},
		Package: pkg,
	}
}

func flask() *sarif.Package {
	return &sarif.Package{Name: "flask", Version: "3.0.3", FixedVersion: "3.1.3", Ecosystem: "pip"}
}

func urllib3(fixed string) *sarif.Package {
	return &sarif.Package{Name: "urllib3", Version: "1.26.5", FixedVersion: fixed, Ecosystem: "pip"}
}
