package engine

import (
	"context"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// jobPerRepo is a control planning one job per repository of a component, with no policy, as
// secrets is.
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
// control without the policy unmarked and counted.
func TestARunMarksAndSetsAsideNonShippingFindingsPerComponent(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterScanner(fixtureScanner{name: "s"})
	reg.RegisterController(nonShippingController{jobPerRepo{name: "iac", scanner: "s"}, map[string]bool{"api": true}})
	reg.RegisterController(jobPerRepo{name: "secrets", scanner: "s"})
	m := saga.Model{
		Release: saga.Release{Version: "1"},
		Config: saga.Config{Controls: map[string]saga.ControllerSettings{
			"iac": {"enabled": true}, "secrets": {"enabled": true},
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
	for _, r := range res.Controls["secrets"].Report.Results {
		if r.NonShipping != "" || r.Suppressed() {
			t.Errorf("secrets %s %s: mark %q, suppressed %v; a control without the policy is neither marked nor set aside",
				r.Component, r.Location.URI, r.NonShipping, r.Suppressed())
		}
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
