package engine

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/draugr-dev/draugr/pkg/dephealth"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// packageScanner reports one finding in a package named after the component it scanned, so two
// components ask about two packages.
type packageScanner struct{ name string }

func (s packageScanner) Info() plugin.ScannerInfo { return plugin.ScannerInfo{Name: s.name} }

func (s packageScanner) Scan(_ context.Context, target plugin.Target, _ plugin.Config) (sarif.Report, error) {
	return sarif.Report{Tool: s.name, Results: []sarif.Result{{
		RuleID: "CVE-1", Level: sarif.LevelWarning, Location: sarif.Location{URI: target.Identity()},
		Package: &sarif.Package{Name: target.Identity(), Version: "1.0.0", PURL: "pkg:npm/" + target.Identity() + "@1.0.0"},
	}}}, nil
}

// healthRun scans two components with a resolver that answers as given, beside a KEV feed the
// caller recorded, and returns what the run says it consulted and what it asked about.
func healthRun(t *testing.T, known map[string]dephealth.Package, resolveErr error) ([]sarif.Consulted, []string) {
	t.Helper()
	reg := NewRegistry()
	reg.RegisterController(fakeController{name: "sca", scope: plugin.ScopeComponent, scanner: "pkgs"})
	reg.RegisterScanner(packageScanner{name: "pkgs"})
	m := saga.Model{
		Release:    saga.Release{Version: "1"},
		Config:     saga.Config{Controls: map[string]saga.ControllerSettings{"sca": {"enabled": true}}},
		Components: []saga.Component{{Name: "api"}, {Name: "web"}},
	}
	src := dephealth.New(nil, "")
	var asked []string
	resolve := func(_ context.Context, purls []string) error {
		asked = purls
		if resolveErr != nil {
			return resolveErr
		}
		src.Load(known, "2026-10-31")
		return nil
	}
	feeds := []sarif.Consulted{{Signal: "kev", AsOf: "2026-10-30", Entries: 1}}
	res, err := New(reg, WithConsulted(feeds), WithDependencyHealth(resolve, src)).Run(context.Background(), m)
	if err != nil {
		t.Fatal(err)
	}
	if len(feeds) != 1 {
		t.Errorf("the caller's consulted list was written to: %+v", feeds)
	}
	return res.Consulted, asked
}

// A lookup that answered is recorded beside the feeds, with the day and how many packages it knew,
// whether or not it raised anything: neither package here is deprecated or malicious.
func TestADependencyHealthLookupIsRecordedAsConsulted(t *testing.T) {
	known := map[string]dephealth.Package{"pkg:npm/api@1.0.0": {}, "pkg:npm/web@1.0.0": {}}
	consulted, asked := healthRun(t, known, nil)
	if !slices.Equal(asked, []string{"pkg:npm/api@1.0.0", "pkg:npm/web@1.0.0"}) {
		t.Errorf("asked about %v, want both components' packages", asked)
	}
	want := []sarif.Consulted{
		{Signal: "kev", AsOf: "2026-10-30", Entries: 1},
		{Signal: dephealth.DatasetName, AsOf: "2026-10-31", Entries: 2},
	}
	if !slices.Equal(consulted, want) {
		t.Errorf("consulted = %+v, want %+v", consulted, want)
	}
}

// A lookup that failed, or that knew none of the packages, consulted nothing, and the run does not
// claim it did.
func TestADependencyHealthLookupThatAnsweredNothingIsNotRecorded(t *testing.T) {
	for name, tc := range map[string]struct {
		known map[string]dephealth.Package
		err   error
	}{
		"failed":       {err: errors.New("deps.dev: 503")},
		"knew nothing": {known: map[string]dephealth.Package{}},
	} {
		consulted, _ := healthRun(t, tc.known, tc.err)
		for _, c := range consulted {
			if c.Signal == dephealth.DatasetName {
				t.Errorf("%s: recorded as consulted: %+v", name, consulted)
			}
		}
		if len(consulted) != 1 || consulted[0].Signal != "kev" {
			t.Errorf("%s: the feeds the caller recorded were lost: %+v", name, consulted)
		}
	}
}
