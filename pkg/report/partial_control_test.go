package report

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// pairController plans a job for each of its scanners on the repository each component lists.
type pairController struct {
	name     string
	scanners []string
	repos    map[string]string
}

func (c pairController) Info() plugin.ControllerInfo {
	return plugin.ControllerInfo{Name: c.name, Scope: plugin.ScopeComponent}
}

func (c pairController) Plan(_ saga.Model, comp *saga.Component) ([]plugin.ScanJob, error) {
	var jobs []plugin.ScanJob
	for _, s := range c.scanners {
		jobs = append(jobs, plugin.ScanJob{Scanner: s, Target: plugin.RepositoryTarget{URL: c.repos[comp.Name], Revision: "main"}})
	}
	return jobs, nil
}

func (c pairController) Aggregate(reports []sarif.Report) (plugin.ControlResult, error) {
	return plugin.ControlResult{Control: c.name, Report: sarif.Merge(reports...)}, nil
}

// cleanScanner finds nothing, or fails on every target when told to. It reports no version, so it
// leaves no provenance behind it.
type cleanScanner struct {
	name  string
	fails bool
}

func (s cleanScanner) Info() plugin.ScannerInfo { return plugin.ScannerInfo{Name: s.name} }

func (s cleanScanner) Scan(context.Context, plugin.Target, plugin.Config) (sarif.Report, error) {
	if s.fails {
		return sarif.Report{}, errors.New("run " + s.name + ": exit status 1: invalid file regexp")
	}
	return sarif.Report{Tool: s.name}, nil
}

// twoScannerRun runs two components in two repositories through sca, where trivy-fs fails and
// grype-fs finds nothing, and secrets, where both scanners fail.
func twoScannerRun(t *testing.T) Data {
	t.Helper()
	repos := map[string]string{"api": "https://github.com/acme/api", "web": "https://github.com/acme/web"}
	reg := engine.NewRegistry()
	reg.RegisterController(pairController{name: "sca", scanners: []string{"trivy-fs", "grype-fs"}, repos: repos})
	reg.RegisterController(pairController{name: "secrets", scanners: []string{"gitleaks", "trufflehog"}, repos: repos})
	reg.RegisterScanner(cleanScanner{name: "trivy-fs", fails: true})
	reg.RegisterScanner(cleanScanner{name: "grype-fs"})
	reg.RegisterScanner(cleanScanner{name: "gitleaks", fails: true})
	reg.RegisterScanner(cleanScanner{name: "trufflehog", fails: true})
	on := map[string]saga.ControllerSettings{"sca": {}, "secrets": {}}
	run, err := engine.New(reg).Run(context.Background(), saga.Model{
		Release:    saga.Release{Version: "1"},
		Components: []saga.Component{{Name: "api", Controls: on}, {Name: "web", Controls: on}},
	})
	if err == nil {
		t.Fatal("want the run to report the failed scanners")
	}
	reports := map[string]sarif.Report{}
	for name, cr := range run.Controls {
		reports[name] = cr.Report
	}
	verdict := (norn.Policy{FailOn: sarif.SeverityHigh}).Evaluate(reports)
	verdict.Verdict = norn.Fail // the CLI fails a run with a scan error
	return Data{Project: "storefront", Release: saga.Release{Version: "1"}, Run: run, Verdict: verdict}
}

// consoleStates reads each control's word off the CONTROLS block.
func consoleStates(t *testing.T, out string) map[string]string {
	t.Helper()
	states := map[string]string{}
	in := false
	for _, line := range strings.Split(out, "\n") {
		switch {
		case line == "CONTROLS":
			in = true
		case in && line == "":
			return states
		case in && strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "   "):
			if f := strings.Fields(line); len(f) >= 2 {
				states[f[0]] = f[1]
			}
		}
	}
	t.Fatalf("no CONTROLS block in\n%s", out)
	return nil
}

// A control with a failed scanner fails in report.json, as the console marks it ERROR, whether its
// other scanner reported and found nothing (sca) or every scanner failed (secrets). The console's
// closing line names the scanner that reported, and report.json lists it.
func TestAControlWithAFailedScannerReadsAlikeInTheConsoleAndReportJSON(t *testing.T) {
	d := twoScannerRun(t)
	console := renderConsole(t, d)
	states := consoleStates(t, console)

	var doc struct {
		Controls []struct {
			Name       string   `json:"name"`
			Verdict    string   `json:"verdict"`
			ScanErrors []string `json:"scanErrors"`
			Reported   []string `json:"reported"`
		} `json:"controls"`
	}
	if err := json.Unmarshal([]byte(renderWith(t, jsonReporter{}, d)), &doc); err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{"sca": {"grype-fs"}, "secrets": nil}
	if len(doc.Controls) != len(want) {
		t.Fatalf("controls = %+v, want sca and secrets", doc.Controls)
	}
	for _, c := range doc.Controls {
		if states[c.Name] != "ERROR" {
			t.Errorf("console marks %s %q, want ERROR", c.Name, states[c.Name])
		}
		if c.Verdict != "fail" {
			t.Errorf("report.json gives %s %q where the console says ERROR, want fail", c.Name, c.Verdict)
		}
		if len(c.ScanErrors) == 0 {
			t.Errorf("%s carries no scanErrors", c.Name)
		}
		if !slices.Equal(c.Reported, want[c.Name]) {
			t.Errorf("%s reported = %q, want %q", c.Name, c.Reported, want[c.Name])
		}
	}
	closing := "No findings from the scanners that reported. In sca, grype-fs reported and trivy-fs did not. " +
		"secrets did not report."
	if !strings.Contains(console, closing) {
		t.Errorf("console does not close on %q:\n%s", closing, console)
	}
}

// A control in error that has no scanner reporting on one side and failing on the other gets no
// sentence of its own: images, whose one scanner read one target and failed on another, reported in
// part, and a run with no such control keeps the line it always had.
func TestNoFindingsWithErrors(t *testing.T) {
	incomplete := map[string][]string{"sca": {"x"}, "images": {"y"}}
	controls := []norn.ControlOutcome{{Control: "images"}, {Control: "sast"}, {Control: "sca"}}
	run := engine.Result{
		ScanErrors: incomplete,
		Reported:   map[string][]string{"images": {"trivy"}, "sca": {"grype-fs", "osv-scanner"}, "sast": {"semgrep"}},
		FailedScans: []engine.FailedScan{
			{Scanner: "trivy", Control: "images"},
			{Scanner: "trivy-fs", Control: "sca"},
		},
	}
	d := Data{Run: run, Verdict: norn.Result{Controls: controls}}
	got := noFindingsWithErrors(d, []string{"dast"})
	want := "No findings from the scanners that reported. In sca, grype-fs and osv-scanner reported and trivy-fs did not. " +
		"images reported in part. dast did not report."
	if got != want {
		t.Errorf("closing =\n %q\nwant\n %q", got, want)
	}

	d.Run.Reported = nil
	if got := noFindingsWithErrors(d, []string{"dast"}); got != "No findings from the controls that ran. A control marked ERROR did not report." {
		t.Errorf("with no scanner reporting beside a failure, closing = %q", got)
	}
}
