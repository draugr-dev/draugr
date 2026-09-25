package engine

import (
	"context"
	"reflect"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// inputScanner reports, for each repository, the inputs a test gives it.
type inputScanner struct {
	name   string
	inputs map[string][]sarif.Input
}

func (s inputScanner) Info() plugin.ScannerInfo {
	return plugin.ScannerInfo{
		Name: s.name, Controls: []string{"sca"}, TargetKinds: []plugin.TargetKind{plugin.TargetRepository},
	}
}

func (s inputScanner) Scan(_ context.Context, target plugin.Target, _ plugin.Config) (sarif.Report, error) {
	repo, _ := target.(plugin.RepositoryTarget)
	var out []sarif.Input
	for _, in := range s.inputs[repo.URL] {
		in.Scanner, in.Repository = s.name, repo.URL
		out = append(out, in)
	}
	return sarif.Report{Tool: s.name, Inputs: out}, nil
}

// inputController plans every scanner over every repository a component declares.
type inputController struct{ scanners []string }

func (c inputController) Info() plugin.ControllerInfo {
	return plugin.ControllerInfo{Name: "sca", Scope: plugin.ScopeComponent, DefaultScanners: c.scanners}
}

func (c inputController) Plan(_ saga.Model, comp *saga.Component) ([]plugin.ScanJob, error) {
	if comp == nil {
		return nil, nil
	}
	var jobs []plugin.ScanJob
	for _, r := range comp.Repositories {
		for _, s := range c.scanners {
			jobs = append(jobs, plugin.ScanJob{Scanner: s, Target: plugin.RepositoryTarget{URL: r.URL}})
		}
	}
	return jobs, nil
}

func (c inputController) Aggregate(reports []sarif.Report) (plugin.ControlResult, error) {
	return plugin.ControlResult{Control: "sca", Report: sarif.Merge(reports...)}, nil
}

// Two components, two repositories each side of a shared one, and two scanners. Every way the
// coverage could collapse is present: a file one scanner read and the other did not, the same
// path in two repositories, and one repository scanned once for two components.
func TestRunReportsWhatNoScanOfAComponentRead(t *testing.T) {
	trivy := inputScanner{name: "trivy-fs", inputs: map[string][]sarif.Input{
		"api": {
			{Path: "requirements.txt", Packages: 4},
			{Path: "requirements-dev.txt", Unread: "no packages read"},
			{Path: "pyproject.toml", Unread: "no lockfile"},
		},
		"web":    {{Path: "package.json", Unread: "no lockfile"}},
		"shared": {{Path: "go.mod", Packages: 9}},
	}}
	grype := inputScanner{name: "grype-fs", inputs: map[string][]sarif.Input{
		"api": {
			{Path: "requirements.txt", Packages: 4},
			{Path: "requirements-dev.txt", Packages: 2},
			{Path: "pyproject.toml", Unread: "no lockfile"},
		},
		"web": {{Path: "package.json", Unread: "no lockfile"}},
	}}
	reg := NewRegistry()
	reg.RegisterController(inputController{scanners: []string{"trivy-fs", "grype-fs"}})
	reg.RegisterScanner(trivy)
	reg.RegisterScanner(grype)
	model := saga.Model{
		Config: saga.Config{Controls: map[string]saga.ControllerSettings{"sca": {"enabled": true}}},
		Components: []saga.Component{
			{Name: "backend", Repositories: []saga.Repository{{URL: "api"}, {URL: "shared"}}},
			{Name: "frontend", Repositories: []saga.Repository{{URL: "web"}, {URL: "shared"}}},
		},
	}
	res, err := New(reg).Run(context.Background(), model)
	if err != nil {
		t.Fatal(err)
	}
	want := []InputCoverage{
		{
			Component: "backend", Control: "sca", Scanners: []string{"grype-fs", "trivy-fs"}, Read: 3,
			Unread: []UnreadInput{{Repository: "api", Path: "pyproject.toml", Reason: "no lockfile"}},
		},
		{
			Component: "frontend", Control: "sca", Scanners: []string{"grype-fs", "trivy-fs"}, Read: 1,
			Unread: []UnreadInput{{Repository: "web", Path: "package.json", Reason: "no lockfile"}},
		},
	}
	if !reflect.DeepEqual(res.Inputs, want) {
		t.Errorf("Inputs =\n%+v\nwant\n%+v", res.Inputs, want)
	}
}

// A scan that read every dependency file says so: coverage with a count and nothing unread, which
// is a different statement from no coverage at all.
func TestRunSaysWhenEveryFileWasRead(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterController(inputController{scanners: []string{"trivy-fs"}})
	reg.RegisterScanner(inputScanner{name: "trivy-fs", inputs: map[string][]sarif.Input{
		"api": {{Path: "go.mod", Packages: 9}},
	}})
	model := saga.Model{
		Config:     saga.Config{Controls: map[string]saga.ControllerSettings{"sca": {"enabled": true}}},
		Components: []saga.Component{{Name: "api", Repositories: []saga.Repository{{URL: "api"}}}},
	}
	res, err := New(reg).Run(context.Background(), model)
	if err != nil {
		t.Fatal(err)
	}
	want := []InputCoverage{{Component: "api", Control: "sca", Scanners: []string{"trivy-fs"}, Read: 1}}
	if !reflect.DeepEqual(res.Inputs, want) {
		t.Errorf("Inputs = %+v, want %+v", res.Inputs, want)
	}
}

func TestStampingInputsLeavesTheCachedReportAlone(t *testing.T) {
	e := &Engine{}
	cached := sarif.Report{Inputs: []sarif.Input{{Scanner: "trivy-fs", Path: "go.mod"}}}
	got := e.stampJobFields(cached, PlannedJob{Component: "api"}, nil)
	if got.Inputs[0].Component != "api" {
		t.Errorf("stamped input = %+v", got.Inputs[0])
	}
	if cached.Inputs[0].Component != "" {
		t.Errorf("the cached report was mutated: %+v", cached.Inputs[0])
	}
}

// The reason is stable whichever scanner finished first.
func TestInputCoveragePrefersOneReasonDeterministically(t *testing.T) {
	byCtl := map[string][]sarif.Report{"sca": {
		{Inputs: []sarif.Input{{Scanner: "b", Component: "c", Path: "x", Unread: "no packages read"}}},
		{Inputs: []sarif.Input{{Scanner: "a", Component: "c", Path: "x", Unread: "no lockfile"}}},
	}}
	got := inputCoverage(byCtl)
	if len(got) != 1 || len(got[0].Unread) != 1 || got[0].Unread[0].Reason != "no lockfile" {
		t.Errorf("coverage = %+v", got)
	}
}
