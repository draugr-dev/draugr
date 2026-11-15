package engine

import (
	"context"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// A dependency finding in a developer tool's lockfile is marked as a tool's, below the root the
// component declares, and only in sca. A finding under docs, examples or tests keeps that mark
// alone, and one a scanner already set aside keeps its own reason.
func TestMarkToolDependencies(t *testing.T) {
	m := saga.Model{Components: []saga.Component{
		{Name: "api", Repositories: []saga.Repository{{URL: "one", Paths: []string{"services/api/**"}}}},
	}}
	at := func(comp, uri string) sarif.Result {
		return sarif.Result{Component: comp, Location: sarif.Location{URI: uri}}
	}
	sca := []sarif.Result{
		at("", ".config/mise/locks/mise.extras/pypi-aiautocommit/0.28.1/uv.lock"),
		at("api", "services/api/.config/mise/locks/uv.lock"),
		at("", "_tools/go.mod"),
		at("", "uv.lock"),
		at("", "tests/.config/mise/uv.lock"),
		at("", ".config/mise/uv.lock"),
	}
	sca[4].NonShipping = "test"
	sca[5].Aside = sarif.AsideGenerated
	controls := map[string]plugin.ControlResult{
		"sca":  {Report: sarif.Report{Results: sca}},
		"sast": {Report: sarif.Report{Results: []sarif.Result{at("", ".config/mise/x.go")}}},
	}
	markToolDependencies(controls, m)
	for i, want := range []string{"tooling", "tooling", "", "", "", "generated"} {
		if got := controls["sca"].Report.Results[i].Aside; got != want {
			t.Errorf("sca %s: aside %q, want %q", sca[i].Location.URI, got, want)
		}
	}
	if got := controls["sast"].Report.Results[0].Aside; got != "" {
		t.Errorf("a sast finding was marked %q", got)
	}

	none := map[string]plugin.ControlResult{}
	markToolDependencies(none, m)
	if len(none) != 0 {
		t.Error("a run with no sca gained one")
	}
}

// toolLockScanner reports one finding in the application's lockfile and one in a tool's.
type toolLockScanner struct{}

func (toolLockScanner) Info() plugin.ScannerInfo { return plugin.ScannerInfo{Name: "locks"} }

func (toolLockScanner) Scan(_ context.Context, target plugin.Target, _ plugin.Config) (sarif.Report, error) {
	return sarif.Report{Tool: "locks", Results: []sarif.Result{
		{RuleID: "CVE-1", Level: sarif.LevelError, Message: target.Identity(), Location: sarif.Location{URI: "uv.lock"}},
		{RuleID: "CVE-1", Level: sarif.LevelError, Message: target.Identity(), Location: sarif.Location{URI: ".config/mise/locks/uv.lock"}},
	}}, nil
}

// A run marks a tool's lockfile finding in sca, and both findings still count.
func TestARunMarksToolDependencies(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterScanner(toolLockScanner{})
	reg.RegisterController(jobPerRepo{name: "sca", scanner: "locks"})
	m := saga.Model{
		Release:    saga.Release{Version: "1"},
		Config:     saga.Config{Controls: map[string]saga.ControllerSettings{"sca": {"enabled": true}}},
		Components: []saga.Component{{Name: "api", Repositories: []saga.Repository{{URL: "https://example.test/api.git"}}}},
	}
	res, err := New(reg).Run(context.Background(), m)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, r := range res.Controls["sca"].Report.Results {
		if r.Suppressed() {
			t.Errorf("%s was set aside", r.Location.URI)
		}
		got[r.Location.URI] = r.Aside
	}
	if got["uv.lock"] != "" || got[".config/mise/locks/uv.lock"] != sarif.AsideTooling {
		t.Errorf("aside by file = %v", got)
	}
}
