package engine

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/draugr-dev/draugr/pkg/saga"
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
