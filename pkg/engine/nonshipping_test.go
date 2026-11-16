package engine

import (
	"context"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// jobPerRepo is a control planning one job per repository of a component, with no policy and no
// mark, as licenses is.
type jobPerRepo struct {
	name    string
	scanner string
}

func (c jobPerRepo) Info() plugin.ControllerInfo {
	return plugin.ControllerInfo{Name: c.name, Scope: plugin.ScopeComponent}
}

func (c jobPerRepo) Plan(_ saga.Model, comp *saga.Component) ([]plugin.ScanJob, error) {
	if comp == nil {
		return nil, nil
	}
	var jobs []plugin.ScanJob
	for _, r := range comp.Repositories {
		jobs = append(jobs, plugin.ScanJob{Scanner: c.scanner, Target: plugin.RepositoryTarget{URL: r.URL, Paths: r.Paths}})
	}
	return jobs, nil
}

func (c jobPerRepo) Aggregate(reports []sarif.Report) (plugin.ControlResult, error) {
	merged := sarif.Merge(reports...)
	return plugin.ControlResult{Control: c.name, Report: merged}, nil
}

// nonShippingController is a repository control that opts in to the mark, with each component's
// answer fixed.
type nonShippingController struct {
	jobPerRepo
	report map[string]bool
}

func (c nonShippingController) ReportsNonShipping(_ saga.Model, component string) (bool, string) {
	return c.report[component], "config.controls." + c.name + ".nonShippingPaths"
}

// markerController is a repository control whose findings are marked with no setting to set them
// aside, as secrets is.
type markerController struct{ jobPerRepo }

func (markerController) MarksNonShipping() {}

// fixtureScanner reports one finding in shipped code and one under tests/ for every repository.
type fixtureScanner struct{ name string }

func (s fixtureScanner) Info() plugin.ScannerInfo { return plugin.ScannerInfo{Name: s.name} }

func (s fixtureScanner) Scan(_ context.Context, target plugin.Target, _ plugin.Config) (sarif.Report, error) {
	return sarif.Report{Tool: s.name, Results: []sarif.Result{
		{RuleID: "R1", Level: sarif.LevelError, Message: target.Identity(), Location: sarif.Location{URI: "main.tf"}},
		{RuleID: "R1", Level: sarif.LevelError, Message: target.Identity(), Location: sarif.Location{URI: "tests/fixture.tf"}},
	}}, nil
}

// Over two components in two repositories, a run marks each opted-in control's findings under a
// test directory, sets aside only those of the component whose setting suppresses them, and leaves a
// control with neither the policy nor the mark unmarked and counted.
func TestARunMarksAndSetsAsideNonShippingFindingsPerComponent(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterScanner(fixtureScanner{name: "s"})
	reg.RegisterController(nonShippingController{jobPerRepo{name: "iac", scanner: "s"}, map[string]bool{"api": true}})
	reg.RegisterController(jobPerRepo{name: "licenses", scanner: "s"})
	m := saga.Model{
		Release: saga.Release{Version: "1"},
		Config: saga.Config{Controls: map[string]saga.ControllerSettings{
			"iac": {"enabled": true}, "licenses": {"enabled": true},
		}},
		Components: []saga.Component{
			{Name: "api", Repositories: []saga.Repository{{URL: "https://example.test/api.git"}}},
			{Name: "web", Repositories: []saga.Repository{{URL: "https://example.test/web.git"}}},
		},
	}
	res, err := New(reg).Run(context.Background(), m)
	if err != nil {
		t.Fatal(err)
	}
	if res.NonShipping != 1 {
		t.Errorf("NonShipping = %d, want 1, web's finding under tests/", res.NonShipping)
	}
	iac := res.Controls["iac"].Report.Results
	if len(iac) != 4 {
		t.Fatalf("iac holds %d findings, want 4", len(iac))
	}
	for _, r := range iac {
		wantMark := ""
		if r.Location.URI == "tests/fixture.tf" {
			wantMark = "test"
		}
		if r.NonShipping != wantMark {
			t.Errorf("iac %s %s: mark %q, want %q", r.Component, r.Location.URI, r.NonShipping, wantMark)
		}
		wantSuppressed := r.Component == "web" && wantMark != ""
		if r.Suppressed() != wantSuppressed {
			t.Errorf("iac %s %s: suppressed %v, want %v", r.Component, r.Location.URI, r.Suppressed(), wantSuppressed)
		}
		if wantSuppressed && (r.Suppression.Origin != sarif.OriginSetting ||
			r.Suppression.Justification != sarif.JustificationNonShipping ||
			r.Suppression.Source != "config.controls.iac.nonShippingPaths") {
			t.Errorf("iac web suppression %+v, want the setting's", r.Suppression)
		}
	}
	licenses := res.Controls["licenses"].Report.Results
	if len(licenses) != 4 {
		t.Fatalf("licenses holds %d findings, want 4", len(licenses))
	}
	for _, r := range licenses {
		if r.NonShipping != "" || r.Suppressed() {
			t.Errorf("licenses %s %s: mark %q, suppressed %v; a control with neither the policy nor the mark is neither marked nor set aside",
				r.Component, r.Location.URI, r.NonShipping, r.Suppressed())
		}
	}
}

// testFileScanner reports a finding in shipped code, one under tests/ and one in a Go test file
// outside any test directory.
type testFileScanner struct{ name string }

func (s testFileScanner) Info() plugin.ScannerInfo { return plugin.ScannerInfo{Name: s.name} }

func (s testFileScanner) Scan(_ context.Context, target plugin.Target, _ plugin.Config) (sarif.Report, error) {
	return sarif.Report{Tool: s.name, Results: []sarif.Result{
		{RuleID: "R1", Level: sarif.LevelError, Message: target.Identity(), Location: sarif.Location{URI: "internal/auth/token.go"}},
		{RuleID: "R1", Level: sarif.LevelError, Message: target.Identity(), Location: sarif.Location{URI: "tests/fixture.env"}},
		{RuleID: "R1", Level: sarif.LevelError, Message: target.Identity(), Location: sarif.Location{URI: "internal/auth/token_test.go"}},
	}}, nil
}

// A marking control's findings under tests/ and in a Go test file are labeled test and still
// counted, with nothing set aside, and a policy control's finding in a Go test file is labeled too.
// Over two components, so neither component's findings take the other's mark.
func TestARunMarksSecretsInTestFilesAndCountsThem(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterScanner(testFileScanner{name: "s"})
	reg.RegisterController(markerController{jobPerRepo{name: "secrets", scanner: "s"}})
	reg.RegisterController(nonShippingController{jobPerRepo{name: "sast", scanner: "s"}, map[string]bool{"api": true, "web": true}})
	m := saga.Model{
		Release: saga.Release{Version: "1"},
		Config: saga.Config{Controls: map[string]saga.ControllerSettings{
			"secrets": {"enabled": true}, "sast": {"enabled": true},
		}},
		Components: []saga.Component{
			{Name: "api", Repositories: []saga.Repository{{URL: "https://example.test/api.git"}}},
			{Name: "web", Repositories: []saga.Repository{{URL: "https://example.test/web.git"}}},
		},
	}
	res, err := New(reg).Run(context.Background(), m)
	if err != nil {
		t.Fatal(err)
	}
	if res.NonShipping != 0 {
		t.Errorf("NonShipping = %d, want 0: nothing asked for a marked finding to be set aside", res.NonShipping)
	}
	for _, control := range []string{"secrets", "sast"} {
		results := res.Controls[control].Report.Results
		if len(results) != 6 {
			t.Fatalf("%s holds %d findings, want 6", control, len(results))
		}
		for _, r := range results {
			want := "test"
			if r.Location.URI == "internal/auth/token.go" {
				want = ""
			}
			if r.NonShipping != want {
				t.Errorf("%s %s %s: mark %q, want %q", control, r.Component, r.Location.URI, r.NonShipping, want)
			}
			if r.Suppressed() {
				t.Errorf("%s %s %s: suppressed %+v; a marked finding still counts", control, r.Component, r.Location.URI, r.Suppression)
			}
		}
	}
}

// A marking control has no setting to answer, so a descriptor that writes nonShippingPaths under it
// sets nothing aside.
func TestApplyNonShippingLeavesAMarkersFindingsCounted(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterController(markerController{jobPerRepo{name: "secrets"}})
	e := New(reg)
	m := saga.Model{Config: saga.Config{Controls: map[string]saga.ControllerSettings{
		"secrets": {"nonShippingPaths": "suppress"},
	}}}
	controls := map[string]plugin.ControlResult{"secrets": {Report: sarif.Report{Results: []sarif.Result{
		{Component: "api", NonShipping: "test", Location: sarif.Location{URI: "tests/a.env"}},
	}}}}
	if n := e.applyNonShipping(controls, m); n != 0 {
		t.Errorf("set aside %d, want 0", n)
	}
	if controls["secrets"].Report.Results[0].Suppressed() {
		t.Error("a marking control's finding was set aside")
	}
}

// A component the descriptor roots at a directory is matched below that root, so one rooted at
// examples/demo on purpose is shipped code, and a tests/ directory inside a scoped component is not.
func TestMarkNonShippingReadsBelowTheDeclaredRoot(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterController(nonShippingController{jobPerRepo: jobPerRepo{name: "sast"}})
	e := New(reg)
	m := saga.Model{Components: []saga.Component{
		{Name: "demo", Repositories: []saga.Repository{{URL: "one", Paths: []string{"examples/demo/**"}}}},
		{Name: "api", Repositories: []saga.Repository{
			{URL: "one", Paths: []string{"services/api"}},
			{URL: "two", Paths: []string{".", "services"}},
		}},
	}}
	results := []sarif.Result{
		{Component: "demo", Location: sarif.Location{URI: "examples/demo/app.js"}},
		{Component: "demo", Location: sarif.Location{URI: "examples/demo/test/app.js"}},
		{Component: "api", Location: sarif.Location{URI: "services/api/tests/a.js"}},
		{Component: "api", Location: sarif.Location{URI: "services/api/main.js"}},
		{Component: "api", Location: sarif.Location{URI: "docs/x.js"}},
		{Component: "", Location: sarif.Location{URI: "examples/demo/app.js"}},
	}
	controls := map[string]plugin.ControlResult{"sast": {Report: sarif.Report{Results: results}}}
	e.markNonShipping(controls, m)
	got := controls["sast"].Report.Results
	for i, want := range []string{"", "test", "test", "", "docs", "example"} {
		if got[i].NonShipping != want {
			t.Errorf("%s %s: mark %q, want %q", got[i].Component, got[i].Location.URI, got[i].NonShipping, want)
		}
	}
}

// A control the registry does not know is left alone.
func TestMarkNonShippingSkipsAnUnknownControl(t *testing.T) {
	e := New(NewRegistry())
	controls := map[string]plugin.ControlResult{"iac": {Report: sarif.Report{Results: []sarif.Result{
		{Location: sarif.Location{URI: "tests/a.tf"}},
	}}}}
	e.markNonShipping(controls, saga.Model{})
	if controls["iac"].Report.Results[0].NonShipping != "" {
		t.Error("a control with no registered controller was marked")
	}
}

// A finding a dependency setting already set aside keeps that reason, and one an exclusion set aside
// keeps the exclusion's.
func TestApplyNonShippingKeepsAnEarlierReason(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterController(nonShippingController{jobPerRepo: jobPerRepo{name: "sca"}})
	e := New(reg)
	dev := sarif.Result{Component: "api", NonShipping: "test",
		Suppression: &sarif.Suppression{Origin: sarif.OriginSetting, Justification: sarif.JustificationDevDependency}}
	excluded := sarif.Result{Component: "api", NonShipping: "test",
		Suppression: &sarif.Suppression{Origin: sarif.OriginSaga, Justification: "accepted"}}
	controls := map[string]plugin.ControlResult{"sca": {Report: sarif.Report{Results: []sarif.Result{dev, excluded}}}}
	if n := e.applyNonShipping(controls, saga.Model{}); n != 0 {
		t.Errorf("set aside %d, want 0", n)
	}
	got := controls["sca"].Report.Results
	if got[0].Suppression.Justification != sarif.JustificationDevDependency || got[1].Suppression.Origin != sarif.OriginSaga {
		t.Errorf("an earlier reason was replaced: %+v, %+v", got[0].Suppression, got[1].Suppression)
	}
}

// One flaw in one package held by go.mod and by tests/go.mod, both counted. The flaw is counted
// under the copy that ships even where the test copy is the stronger finding.
func TestCorrelationCountsAFlawUnderTheShippedCopy(t *testing.T) {
	inTests := devFinding("grype", "web", "one", "tests/go.mod", "CVE-2026-0003", false)
	inTests.NonShipping = "test"
	inTests.Priority = "P1"
	shipped := devFinding("trivy", "web", "one", "go.mod", "CVE-2026-0003", false)
	shipped.Priority = "P2"
	controls := map[string]plugin.ControlResult{"sca": {Report: sarif.Report{Results: []sarif.Result{inTests, shipped}}}}
	applyCorrelation(controls)
	got := controls["sca"].Report.Results
	if got[1].Correlated() || !got[0].Correlated() {
		t.Errorf("counted under %+v / %+v, want the shipped copy counted", got[0].Correlation, got[1].Correlation)
	}
}

// A run records the reason the prioritizer gave for holding a band down.
func TestARunRecordsWhyABandWasHeldDown(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterScanner(fixtureScanner{name: "s"})
	reg.RegisterController(jobPerRepo{name: "iac", scanner: "s"})
	m := saga.Model{
		Release:    saga.Release{Version: "1"},
		Config:     saga.Config{Controls: map[string]saga.ControllerSettings{"iac": {"enabled": true}}},
		Components: []saga.Component{{Name: "api", Repositories: []saga.Repository{{URL: "https://example.test/api.git"}}}},
	}
	held := WithPrioritization(func(string, saga.Exposure, saga.Criticality, sarif.Result) Priority {
		return Priority{Band: "P3", Cap: "pinned"}
	})
	res, err := New(reg, held).Run(context.Background(), m)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range res.Controls["iac"].Report.Results {
		if r.Priority != "P3" || r.PriorityCap != "pinned" {
			t.Errorf("%s: band %s, cap %q", r.Location.URI, r.Priority, r.PriorityCap)
		}
	}
}

// A run stamps each finding with the scanner whose job reported it.
func TestARunNamesEachFindingsScanner(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterScanner(fixtureScanner{name: "s"})
	reg.RegisterController(jobPerRepo{name: "iac", scanner: "s"})
	m := saga.Model{
		Release:    saga.Release{Version: "1"},
		Config:     saga.Config{Controls: map[string]saga.ControllerSettings{"iac": {"enabled": true}}},
		Components: []saga.Component{{Name: "api", Repositories: []saga.Repository{{URL: "https://example.test/api.git"}}}},
	}
	res, err := New(reg).Run(context.Background(), m)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range res.Controls["iac"].Report.Results {
		if r.Scanner != "s" {
			t.Errorf("%s: scanner %q, want the job's", r.Location.URI, r.Scanner)
		}
	}
}

// A scanner that read a Go module of test files only labels its findings as a test's; the path
// names no kind there, so the label stands. Where the path does name one, the path's kind wins, and
// a finding no scanner labeled and no path places stays unlabeled.
func TestMarkNonShippingKeepsAScannersTestLabelWhereThePathSaysNothing(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterController(nonShippingController{jobPerRepo: jobPerRepo{name: "sca"}})
	e := New(reg)
	m := saga.Model{Components: []saga.Component{{Name: "api", Repositories: []saga.Repository{{URL: "one"}}}}}
	results := []sarif.Result{
		{Component: "api", NonShipping: "test", Location: sarif.Location{URI: "e2e/go.mod"}},
		{Component: "api", NonShipping: "test", Location: sarif.Location{URI: "docs/go.mod"}},
		{Component: "api", Location: sarif.Location{URI: "go.mod"}},
	}
	controls := map[string]plugin.ControlResult{"sca": {Report: sarif.Report{Results: results}}}
	e.markNonShipping(controls, m)
	got := controls["sca"].Report.Results
	for i, want := range []string{"test", "docs", ""} {
		if got[i].NonShipping != want {
			t.Errorf("%s: label %q, want %q", got[i].Location.URI, got[i].NonShipping, want)
		}
	}
}
