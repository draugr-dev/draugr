package report

import (
	"context"
	"encoding/json"
	"encoding/xml"
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
	if !strings.Contains(console, noFindingsWithErrors) {
		t.Errorf("console does not close on %q:\n%s", noFindingsWithErrors, console)
	}
}

// A control with a scan error is a JUnit suite that errors, with the scanner's error in its testcase
// and no passing testcase beside it: sca, where trivy-fs failed and grype-fs found nothing, and
// secrets, where both scanners failed and no verdict entry exists.
func TestJUnitErrorsAControlWithAFailedScanner(t *testing.T) {
	d := twoScannerRun(t)
	var suites junitTestsuites
	if err := xml.Unmarshal([]byte(renderWith(t, junitReporter{}, d)), &suites); err != nil {
		t.Fatal(err)
	}
	if suites.Errors != 2 || suites.Failures != 0 || suites.Tests != 2 {
		t.Errorf("root tests=%d failures=%d errors=%d, want 2/0/2", suites.Tests, suites.Failures, suites.Errors)
	}
	want := map[string]string{"sca": "trivy-fs", "secrets": "gitleaks"}
	if len(suites.Suites) != len(want) {
		t.Fatalf("suites = %+v, want sca and secrets", suites.Suites)
	}
	for _, s := range suites.Suites {
		if s.Errors != 1 || s.Tests != 1 || len(s.TestCases) != 1 {
			t.Errorf("%s: tests=%d errors=%d cases=%d, want one erroring testcase", s.Name, s.Tests, s.Errors, len(s.TestCases))
			continue
		}
		tc := s.TestCases[0]
		if tc.Error == nil || tc.Failure != nil {
			t.Errorf("%s: testcase %+v, want an <error> and no <failure>", s.Name, tc)
			continue
		}
		if !strings.Contains(tc.Error.Message, "run "+want[s.Name]+": exit status 1") ||
			!strings.Contains(tc.Error.Body, "invalid file regexp") {
			t.Errorf("%s: error %+v, want the failure of %s", s.Name, tc.Error, want[s.Name])
		}
	}
}

// A control whose scanner failed beside findings another reported keeps its failing testcases and
// gains the erroring one ahead of them, and the scan error's repeats across jobs read as one message.
func TestJUnitKeepsFindingsBesideAScanError(t *testing.T) {
	d := sampleData()
	d.Run.ScanErrors = map[string][]string{"secrets": {"run trufflehog: boom", "run trufflehog: boom"}}
	var suites junitTestsuites
	if err := xml.Unmarshal([]byte(renderWith(t, junitReporter{}, d)), &suites); err != nil {
		t.Fatal(err)
	}
	if suites.Failures != 3 || suites.Errors != 1 || suites.Tests != 4 {
		t.Errorf("root tests=%d failures=%d errors=%d, want 4/3/1", suites.Tests, suites.Failures, suites.Errors)
	}
	for _, s := range suites.Suites {
		if s.Name != "secrets" {
			if s.Errors != 0 {
				t.Errorf("%s errors = %d, want 0", s.Name, s.Errors)
			}
			continue
		}
		first := s.TestCases[0]
		if s.Failures != 1 || s.Errors != 1 || first.Error == nil || first.Error.Message != "run trufflehog: boom (2 jobs)" {
			t.Errorf("secrets = %+v, want its finding and one scan error", s)
		}
	}
}

// TestEveryHumanFormatClosesOnTheSameLine: the console, markdown and HTML reports of a run with a
// control in error and no findings close on one sentence, so the formats cannot drift apart. A
// caveat beside the error leaves the error's line, which says more.
func TestEveryHumanFormatClosesOnTheSameLine(t *testing.T) {
	d := twoScannerRun(t)
	d.Run.Inputs = []engine.InputCoverage{{Component: "api", Control: "sca", Scanners: []string{"grype-fs"},
		Unread: []engine.UnreadInput{{Repository: "https://github.com/acme/api", Path: "package.json", Reason: "no lockfile"}}}}
	for name, r := range map[string]Reporter{"console": consoleReporter{}, "markdown": markdownReporter{}, "html": htmlReporter{}} {
		var buf strings.Builder
		if err := r.Render(&buf, d); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !strings.Contains(buf.String(), "package.json") {
			t.Errorf("%s does not list the caveat", name)
		}
		if !strings.Contains(buf.String(), noFindingsWithErrors) || strings.Contains(buf.String(), noFindingsWithCaveats) {
			t.Errorf("%s does not close on %q alone", name, noFindingsWithErrors)
		}
	}
}
