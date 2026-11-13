package report

import (
	"bytes"
	"encoding/xml"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/skald"
)

const (
	junitAPI = "https://example.com/api.git"
	junitWeb = "https://example.com/web.git"
)

// renderJUnit renders d as JUnit and reads it back.
func renderJUnit(t *testing.T, d Data) junitTestsuites {
	t.Helper()
	var b bytes.Buffer
	if err := (junitReporter{}).Render(&b, d); err != nil {
		t.Fatal(err)
	}
	var suites junitTestsuites
	if err := xml.Unmarshal(b.Bytes(), &suites); err != nil {
		t.Fatalf("junit output not valid XML: %v\n%s", err, b.String())
	}
	return suites
}

// suiteNamed is the suite for control, failing the test where there is none.
func suiteNamed(t *testing.T, suites junitTestsuites, control string) junitTestsuite {
	t.Helper()
	for _, s := range suites.Suites {
		if s.Name == control {
			return s
		}
	}
	t.Fatalf("no suite for %s", control)
	return junitTestsuite{}
}

// judgedJUnitData is a run of two components on two repositories that the gate on new findings
// judged at P1. The change is in api: two P1 findings on one package, and one P3, below the gate.
// web holds a finding identical to the first of them in every field but its component and
// repository, there at the base, and one finding both repositories had. images has a finding the
// base had, and secrets found nothing.
func judgedJUnitData() Data {
	newOne := depResult("api", junitAPI, "CVE-NEW-1", "P1", 9.8, "lodash", "4.17.15", "4.17.19")
	newTwo := depResult("api", junitAPI, "CVE-NEW-2", "P1", 9.1, "lodash", "4.17.15", "4.17.21")
	below := depResult("api", junitAPI, "CVE-LOW", "P3", 3.1, "minimist", "1.2.0", "1.2.6")
	oldAPI := depResult("api", junitAPI, "CVE-OLD", "P2", 7.5, "axios", "0.21.0", "0.21.2")
	oldWeb := depResult("web", junitWeb, "CVE-OLD", "P2", 7.5, "axios", "0.21.0", "0.21.2")
	webCopy := depResult("web", junitWeb, "CVE-NEW-1", "P1", 9.8, "lodash", "4.17.15", "4.17.19")
	image := sarif.Result{RuleID: "CVE-IMG", Tool: "trivy", Control: "images", Priority: "P1",
		Level: sarif.LevelError, Component: "web", Location: sarif.Location{URI: "nginx:1.19"}}

	d := goldenCleanData()
	d.Run = engine.Result{Controls: map[string]plugin.ControlResult{
		"sca":     {Report: sarif.Report{Tool: "trivy", Results: []sarif.Result{newOne, newTwo, below, oldAPI, oldWeb, webCopy}}},
		"images":  {Report: sarif.Report{Tool: "trivy", Results: []sarif.Result{image}}},
		"secrets": {Report: sarif.Report{Tool: "gitleaks"}},
	}}
	d.Verdict = norn.Result{Verdict: norn.Fail, Controls: []norn.ControlOutcome{
		{Control: "images", Verdict: norn.Fail}, {Control: "sca", Verdict: norn.Fail},
		{Control: "secrets", Verdict: norn.Pass}}}
	d.Gate.FailOnNew = "P1"
	d.Gate.BasePath = "base/results.sarif"
	d.Gate.New = &skald.NewFindings{
		Base:       []sarif.RepositoryRef{{URL: junitAPI, Revision: "aaaa1111"}, {URL: junitWeb, Revision: "bbbb2222"}},
		Introduced: []sarif.Result{newOne, newTwo, below},
		Tripped:    []sarif.Result{newOne, newTwo},
	}
	return d
}

// A run judged on its change fails, in the test panel, exactly the findings its exit code failed on:
// the new ones that met the gate. The finding already there, the one new and below the gate, and the
// copy of a failing finding that web already had are not tests the change failed, and are not listed.
func TestJUnitOnAJudgedRunFailsOnlyWhatTheChangeIntroduced(t *testing.T) {
	suites := renderJUnit(t, judgedJUnitData())

	if suites.Failures != 2 || suites.Errors != 0 {
		t.Errorf("failures=%d errors=%d, want the 2 new P1 findings and no error", suites.Failures, suites.Errors)
	}
	sca := suiteNamed(t, suites, "sca")
	if len(sca.TestCases) != 2 {
		t.Fatalf("sca lists %d testcases, want only the 2 that failed: %+v", len(sca.TestCases), sca.TestCases)
	}
	for _, tc := range sca.TestCases {
		if tc.Failure == nil {
			t.Errorf("%s is listed and does not fail", tc.Name)
			continue
		}
		if !strings.HasPrefix(tc.Name, "CVE-NEW-") {
			t.Errorf("%s failed, and the change did not introduce it", tc.Name)
		}
		if !strings.HasSuffix(tc.Failure.Message, ", new since aaaa111, bbbb222") {
			t.Errorf("message = %q, want it to say the finding is new since the base", tc.Failure.Message)
		}
		if !strings.Contains(tc.Failure.Body, "Upgrade lodash 4.17.15 → 4.17.21 to clear all 2 failing findings on this package.") {
			t.Errorf("%s body names no upgrade that clears both:\n%s", tc.Name, tc.Failure.Body)
		}
	}

	// A control the change failed nothing in passes on the one question the run asked, whether it
	// has findings from before or none at all.
	for _, control := range []string{"images", "secrets"} {
		s := suiteNamed(t, suites, control)
		if s.Tests != 1 || s.Failures != 0 || s.TestCases[0].Failure != nil {
			t.Errorf("%s: tests=%d failures=%d, want one passing testcase", control, s.Tests, s.Failures)
			continue
		}
		if got, want := s.TestCases[0].Name, "nothing new at P1 since aaaa111, bbbb222"; got != want {
			t.Errorf("%s passing testcase = %q, want %q", control, got, want)
		}
	}
}

// A judged run's control whose scanner failed still errors: the change cannot be said to have added
// nothing where the check did not run in full.
func TestJUnitOnAJudgedRunStillErrorsAnIncompleteControl(t *testing.T) {
	d := judgedJUnitData()
	d.Run.ScanErrors = map[string][]string{"secrets": {"gitleaks: exit status 2"}}

	s := suiteNamed(t, renderJUnit(t, d), "secrets")
	if s.Errors != 1 || len(s.TestCases) != 1 || s.TestCases[0].Error == nil {
		t.Errorf("secrets: errors=%d testcases=%+v, want the scan error alone", s.Errors, s.TestCases)
	}
}

// Without a base, every finding fails as before, and each failure on a package names the upgrade
// that clears all of them on it. A package with no fixed release says so instead.
func TestJUnitNamesTheUpgradeThatClearsAPackage(t *testing.T) {
	d := judgedJUnitData()
	d.Gate.New, d.Gate.FailOnNew = nil, ""
	d.Run.Controls["sca"] = plugin.ControlResult{Report: sarif.Report{Tool: "trivy", Results: []sarif.Result{
		depResult("api", junitAPI, "CVE-A", "P1", 9.8, "lodash", "4.17.15", "4.17.19"),
		depResult("api", junitAPI, "CVE-B", "P2", 7.1, "lodash", "4.17.15", "4.17.21"),
		depResult("api", junitAPI, "CVE-C", "P2", 7.0, "minimist", "1.2.0", "1.2.6"),
		depResult("api", junitAPI, "CVE-D", "P3", 4.0, "left-pad", "1.0.0", ""),
		// The same package in the other repository is another upgrade, in another project.
		depResult("web", junitWeb, "CVE-B", "P2", 7.1, "lodash", "4.17.15", "4.17.21"),
	}}}

	suites := renderJUnit(t, d)
	if suites.Failures != 6 {
		t.Errorf("failures = %d, want every finding of the whole run", suites.Failures)
	}
	bodies := map[string][]string{}
	for _, tc := range suiteNamed(t, suites, "sca").TestCases {
		if tc.Failure == nil {
			t.Fatalf("%s passed on a run with no base", tc.Name)
		}
		if strings.Contains(tc.Failure.Message, "new since") {
			t.Errorf("%s message %q calls a finding new on a run with no base", tc.Name, tc.Failure.Message)
		}
		bodies[strings.SplitN(tc.Name, " ", 2)[0]] = append(bodies[strings.SplitN(tc.Name, " ", 2)[0]], tc.Failure.Body)
	}
	for rule, want := range map[string]string{
		"CVE-A": "Upgrade lodash 4.17.15 → 4.17.21 to clear all 2 failing findings on this package.",
		"CVE-C": "Upgrade minimist 1.2.0 → 1.2.6.",
		"CVE-D": "left-pad 1.0.0, no fix available.",
	} {
		if len(bodies[rule]) != 1 || !strings.Contains(bodies[rule][0], want) {
			t.Errorf("%s bodies = %q, want one containing %q", rule, bodies[rule], want)
		}
	}
	// CVE-B fails twice, once per repository: api's shares lodash with CVE-A, web's is alone.
	var shared, alone bool
	for _, b := range bodies["CVE-B"] {
		shared = shared || strings.Contains(b, "to clear all 2 failing findings on this package.")
		alone = alone || strings.Contains(b, "Upgrade lodash 4.17.15 → 4.17.21.")
	}
	if !shared || !alone {
		t.Errorf("CVE-B bodies = %q, want api's naming the shared upgrade and web's its own", bodies["CVE-B"])
	}
}
