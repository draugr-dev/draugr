package engine

import (
	"testing"
	"time"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// componentControl is a per-component control that plans nothing, enough for a declaration to list.
type componentControl struct{ name string }

func (c componentControl) Info() plugin.ControllerInfo {
	return plugin.ControllerInfo{Name: c.name, Scope: plugin.ScopeComponent}
}

func (componentControl) Plan(saga.Model, *saga.Component) ([]plugin.ScanJob, error) { return nil, nil }

func (c componentControl) Aggregate([]sarif.Report) (plugin.ControlResult, error) {
	return plugin.ControlResult{Control: c.name}, nil
}

// A declaration records each control's settings as the run reads them: a project-wide control's
// own, and each component's laid over the project's, one digest per key with the enabled flag left
// out. A control the descriptor turned off records none.
func TestADeclarationRecordsEachControlsSettings(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterController(componentControl{name: "sca"})
	reg.RegisterController(repoListController{name: "secrets"})
	trivyFs := saga.ControllerSettings{"pkgTypes": []any{"os", "library"}}
	model := saga.Model{
		Config: saga.Config{Controls: map[string]saga.ControllerSettings{
			"sca":     {"enabled": true, "trivyFs": trivyFs},
			"secrets": {"enabled": true, "gitleaks": saga.ControllerSettings{"history": true}},
		}},
		Components: []saga.Component{
			{Name: "api", Repositories: []saga.Repository{{URL: "r/api"}, {URL: "r/lib"}}},
			{Name: "web", Repositories: []saga.Repository{{URL: "r/web"}, {URL: "r/ui"}},
				Controls: map[string]saga.ControllerSettings{"sca": {"retirejs": saga.ControllerSettings{"enabled": true}}}},
			{Name: "docs", Controls: map[string]saga.ControllerSettings{"sca": {"enabled": false, "trivyFs": trivyFs}}},
		},
	}
	d := New(reg).declarations(model, time.Now())

	if got := d.Settings["secrets"]; len(got) != 1 || got["gitleaks"] != SettingDigest(map[string]any{"history": true}) {
		t.Errorf("secrets settings = %v", got)
	}
	api, web, docs := d.Components[0], d.Components[1], d.Components[2]
	if got := api.Settings["sca"]; len(got) != 1 || got["trivyFs"] != SettingDigest(trivyFs) {
		t.Errorf("api's sca settings = %v, want the project's trivyFs alone", got)
	}
	if got := web.Settings["sca"]; len(got) != 2 || got["trivyFs"] != api.Settings["sca"]["trivyFs"] ||
		got["retirejs"] != SettingDigest(map[string]any{"enabled": true}) {
		t.Errorf("web's sca settings = %v, want the project's trivyFs and its own retirejs", got)
	}
	if docs.Settings != nil || len(docs.Controls) != 0 {
		t.Errorf("docs turned sca off and records %v", docs.Settings)
	}
}

// A key set by both the project and the component is named by the merged value and the project's
// together. A control that unions the two, as licenses does with its lists, would otherwise read an
// entry taken out of the project's list, under a component's own list, as no change.
func TestAKeyBothLevelsSetCoversTheProjectsValue(t *testing.T) {
	component := saga.ControllerSettings{"deny": []any{"AGPL-3.0-only"}}
	before := SettingsOf(saga.ControllerSettings{"deny": []any{"GPL-3.0-only", "SSPL-1.0"}}, component)
	after := SettingsOf(saga.ControllerSettings{"deny": []any{"GPL-3.0-only"}}, component)
	if before["deny"] == after["deny"] {
		t.Error("an entry taken out of the project's list kept the digest under the component's own list")
	}
	if SettingsOf(saga.ControllerSettings{"enabled": true}, nil) != nil {
		t.Error("a control with only its enabled flag records settings")
	}
}

// A digest is sixteen hex characters, the same for one value however its keys were written, and
// a value JSON cannot write is still named, alike each time.
func TestASettingDigestNamesAValue(t *testing.T) {
	a := SettingDigest(map[string]any{"b": 1, "a": map[string]any{"y": 2, "x": 1}})
	b := SettingDigest(saga.ControllerSettings{"a": saga.ControllerSettings{"x": 1, "y": 2}, "b": 1})
	if len(a) != 16 || a != b {
		t.Errorf("digests %q and %q for one value", a, b)
	}
	odd := map[any]any{1: "x", 2: "y"}
	if d := SettingDigest(odd); len(d) != 16 || d != SettingDigest(map[any]any{2: "y", 1: "x"}) || d == SettingDigest(map[any]any{1: "x"}) {
		t.Errorf("a value JSON cannot write was named %q", d)
	}
}
