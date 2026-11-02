package engine

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// buildScanner is a pickyScanner that can say which build it is.
type buildScanner struct {
	pickyScanner
	version string
}

func (s buildScanner) CacheVersion(context.Context) string { return s.version }

// Two components in two repositories, one scanner failing in one of them and reading the other: the
// failure is recorded once, for the component and repository where it happened, with the version of
// the scanner that failed. A scanner registered and never planned is not recorded at all.
func TestRunRecordsTheScannerBehindEachFailedJob(t *testing.T) {
	const (
		api = "https://github.com/acme/api"
		web = "https://github.com/acme/web"
	)
	repos := map[string][]string{"api": {api}, "web": {web}}
	reg := NewRegistry()
	reg.RegisterController(reposController{name: "sca", scanner: "dep", repos: repos})
	reg.RegisterController(reposController{name: "secrets", scanner: "leak", repos: repos})
	reg.RegisterScanner(buildScanner{pickyScanner{name: "dep", failOn: []string{web}}, "dep@1.2.3"})
	reg.RegisterScanner(pickyScanner{name: "leak"})
	reg.RegisterScanner(pickyScanner{name: "lint", failOn: []string{api, web}}) // registered, never planned

	on := map[string]saga.ControllerSettings{"sca": {}, "secrets": {}}
	res, err := New(reg).Run(context.Background(), saga.Model{
		Release:    saga.Release{Version: "1"},
		Components: []saga.Component{{Name: "api", Controls: on}, {Name: "web", Controls: on}},
	})
	if err == nil {
		t.Fatal("want the run to report its failed scan")
	}
	want := []FailedScan{{
		Scanner: "dep", Version: "dep@1.2.3", Control: "sca", Component: "web",
		Kind: "repository", Target: web + "@main", Detail: "dep: git clone " + web + ": Repository not found",
	}}
	if !slices.Equal(res.FailedScans, want) {
		t.Errorf("failed scans = %+v, want %+v", res.FailedScans, want)
	}
	if got := res.ScanErrors["sca"]; len(got) != 1 || got[0] != want[0].Detail {
		t.Errorf("sca errors = %v, want the failure's own text", got)
	}
}

// Two components sharing one repository share its scan, and both jobs name the scanner that failed
// them, with the version the scan that ran reported. A job naming a scanner nobody registered is
// recorded too, without a version, because nothing ran that could give one.
func TestRunRecordsSharedAndUnregisteredFailures(t *testing.T) {
	const mono = "https://github.com/acme/mono"
	repos := map[string][]string{"api": {mono}, "web": {mono}}
	reg := NewRegistry()
	reg.RegisterController(reposController{name: "sca", scanner: "dep", repos: repos})
	reg.RegisterController(reposController{name: "sast", scanner: "absent", repos: map[string][]string{"api": {mono}}})
	reg.RegisterScanner(buildScanner{pickyScanner{name: "dep", failOn: []string{mono}}, "dep@1.2.3"})

	on := map[string]saga.ControllerSettings{"sca": {}, "sast": {}}
	res, err := New(reg).Run(context.Background(), saga.Model{
		Release:    saga.Release{Version: "1"},
		Components: []saga.Component{{Name: "api", Controls: on}, {Name: "web", Controls: on}},
	})
	if err == nil {
		t.Fatal("want the run to report its failed scans")
	}
	var got []string
	for _, f := range res.FailedScans {
		got = append(got, f.Scanner+" "+f.Version+" "+f.Control+" "+f.Component)
	}
	want := []string{"absent  sast api", "dep dep@1.2.3 sca api", "dep dep@1.2.3 sca web"}
	if !slices.Equal(got, want) {
		t.Errorf("failed scans = %q, want %q", got, want)
	}
}

// pairController plans a job for each of its scanners on every repository a component lists.
type pairController struct {
	name     string
	scanners []string
	repos    map[string][]string
}

func (c pairController) Info() plugin.ControllerInfo {
	return plugin.ControllerInfo{Name: c.name, Scope: plugin.ScopeComponent}
}

func (c pairController) Plan(_ saga.Model, comp *saga.Component) ([]plugin.ScanJob, error) {
	var jobs []plugin.ScanJob
	for _, s := range c.scanners {
		for _, u := range c.repos[comp.Name] {
			jobs = append(jobs, plugin.ScanJob{Scanner: s, Target: plugin.RepositoryTarget{URL: u, Revision: "main"}})
		}
	}
	return jobs, nil
}

func (c pairController) Aggregate(reports []sarif.Report) (plugin.ControlResult, error) {
	return plugin.ControlResult{Control: c.name, Report: sarif.Merge(reports...)}, nil
}

// Two components in two repositories, three controls of two scanners each. In sca, dep fails on web
// and audit reads both, so dep reported for api and failed for web; in secrets both scanners fail
// everywhere; in sast both read everything. Each control's record says which of its scanners
// reported, and Partial separates the ones that only reported from the ones that failed.
func TestRunRecordsWhichScannersReportedForEachControl(t *testing.T) {
	const (
		api = "https://github.com/acme/api"
		web = "https://github.com/acme/web"
	)
	repos := map[string][]string{"api": {api}, "web": {web}}
	reg := NewRegistry()
	reg.RegisterController(pairController{name: "sca", scanners: []string{"dep", "audit"}, repos: repos})
	reg.RegisterController(pairController{name: "secrets", scanners: []string{"leak", "hunt"}, repos: repos})
	reg.RegisterController(pairController{name: "sast", scanners: []string{"lint", "taint"}, repos: repos})
	reg.RegisterScanner(pickyScanner{name: "dep", failOn: []string{web}})
	reg.RegisterScanner(pickyScanner{name: "audit"})
	reg.RegisterScanner(pickyScanner{name: "leak", failOn: []string{api, web}})
	reg.RegisterScanner(pickyScanner{name: "hunt", failOn: []string{api, web}})
	reg.RegisterScanner(pickyScanner{name: "lint"})
	reg.RegisterScanner(pickyScanner{name: "taint"})

	on := map[string]saga.ControllerSettings{"sca": {}, "secrets": {}, "sast": {}}
	res, err := New(reg).Run(context.Background(), saga.Model{
		Release:    saga.Release{Version: "1"},
		Components: []saga.Component{{Name: "api", Controls: on}, {Name: "web", Controls: on}},
	})
	if err == nil {
		t.Fatal("want the run to report its failed scans")
	}
	want := map[string][]string{"sca": {"audit", "dep"}, "sast": {"lint", "taint"}}
	if len(res.Reported) != len(want) {
		t.Errorf("reported = %v, want %v", res.Reported, want)
	}
	for control, scanners := range want {
		if !slices.Equal(res.Reported[control], scanners) {
			t.Errorf("reported[%s] = %v, want %v", control, res.Reported[control], scanners)
		}
	}

	for _, tc := range []struct {
		control            string
		incomplete         bool
		reported, failedBy []string
	}{
		{"sca", true, []string{"audit"}, []string{"dep"}},
		{"secrets", true, nil, nil},
		{"sast", false, nil, nil},
	} {
		if got := res.Incomplete(tc.control); got != tc.incomplete {
			t.Errorf("Incomplete(%s) = %v, want %v", tc.control, got, tc.incomplete)
		}
		reported, failed := res.Partial(tc.control)
		if !slices.Equal(reported, tc.reported) || !slices.Equal(failed, tc.failedBy) {
			t.Errorf("Partial(%s) = %v, %v; want %v, %v", tc.control, reported, failed, tc.reported, tc.failedBy)
		}
	}
}

// A control whose one scanner read one target and failed on another has no scanner that only
// reported, so Partial names nothing; a run that reported nothing records no map.
func TestPartialNeedsAScannerOnEachSide(t *testing.T) {
	res := Result{
		Reported:    map[string][]string{"images": {"trivy"}},
		FailedScans: []FailedScan{{Scanner: "trivy", Control: "images"}},
	}
	if reported, failed := res.Partial("images"); reported != nil || failed != nil {
		t.Errorf("Partial(images) = %v, %v; want nothing", reported, failed)
	}
	if got := sortedReported(nil); got != nil {
		t.Errorf("sortedReported(nil) = %v, want nil", got)
	}
}

// Failures arrive in whatever order the jobs finish; the record is sorted, and a job that failed
// twice alike for one component and target is one fact.
func TestSortFailedScans(t *testing.T) {
	if got := sortFailedScans(nil); got != nil {
		t.Errorf("no failures = %v, want nil", got)
	}
	a := FailedScan{Scanner: "dep", Control: "sca", Component: "web", Target: "b", Detail: "x"}
	b := FailedScan{Scanner: "dep", Control: "sca", Component: "api", Target: "a", Detail: "x"}
	c := FailedScan{Scanner: "audit", Control: "sca", Component: "web", Target: "b", Detail: "y"}
	got := sortFailedScans([]FailedScan{a, b, a, c})
	if want := []FailedScan{c, b, a}; !slices.Equal(got, want) {
		t.Errorf("sorted = %+v, want %+v", got, want)
	}
}

// A job with no target names none.
func TestFailedScanForAJobWithNoTarget(t *testing.T) {
	f := failedScanFor(PlannedJob{Control: "threats", Component: ""}, "v1", errors.New("boom"))
	if f.Kind != "" || f.Target != "" || f.Version != "v1" || f.Detail != "boom" {
		t.Errorf("failure = %+v", f)
	}
}
