package controllers

import (
	"slices"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// devModel is a descriptor whose project sca block is project and whose two components carry web
// and tools as theirs.
func devModel(project, web, tools saga.ControllerSettings) saga.Model {
	m := saga.Model{Config: saga.Config{Controls: map[string]saga.ControllerSettings{"sca": project}}}
	for name, s := range map[string]saga.ControllerSettings{"web": web, "tools": tools} {
		c := saga.Component{Name: name}
		if s != nil {
			c.Controls = map[string]saga.ControllerSettings{"sca": s}
		}
		m.Components = append(m.Components, c)
	}
	slices.SortFunc(m.Components, func(a, b saga.Component) int {
		if a.Name < b.Name {
			return -1
		}
		return 1
	})
	return m
}

func trivyBlock(include bool) saga.ControllerSettings {
	return saga.ControllerSettings{"trivyFs": saga.ControllerSettings{"includeDevDeps": include}}
}

// The component's setting before the project's, devDependencies before the deprecated
// includeDevDeps at each level, and suppress where nothing is written, named by the project's key.
func TestReportsDevDependenciesResolvesPerComponent(t *testing.T) {
	policy := NewSCA().(plugin.DevDependencyPolicy)
	for _, tc := range []struct {
		name        string
		model       saga.Model
		component   string
		report      bool
		decidedFrom string
	}{
		{"default", devModel(nil, nil, nil), "web", false, "config.controls.sca.devDependencies"},
		{"project", devModel(saga.ControllerSettings{"devDependencies": "report"}, nil, nil), "web", true,
			"config.controls.sca.devDependencies"},
		{"component over project", devModel(saga.ControllerSettings{"devDependencies": "report"},
			saga.ControllerSettings{"devDependencies": "suppress"}, nil), "web", false,
			`components["web"].controls.sca.devDependencies`},
		{"other component keeps the project's", devModel(saga.ControllerSettings{"devDependencies": "report"},
			saga.ControllerSettings{"devDependencies": "suppress"}, nil), "tools", true,
			"config.controls.sca.devDependencies"},
		{"project includeDevDeps", devModel(trivyBlock(true), nil, nil), "web", true,
			"config.controls.sca.trivyFs.includeDevDeps"},
		{"component includeDevDeps false", devModel(saga.ControllerSettings{"devDependencies": "report"}, trivyBlock(false), nil),
			"web", false, `components["web"].controls.sca.trivyFs.includeDevDeps`},
		{"devDependencies beside includeDevDeps", devModel(saga.ControllerSettings{
			"devDependencies": "suppress", "trivyFs": saga.ControllerSettings{"includeDevDeps": true}}, nil, nil),
			"web", false, "config.controls.sca.devDependencies"},
		{"unknown component", devModel(saga.ControllerSettings{"devDependencies": "report"}, nil, nil), "", true,
			"config.controls.sca.devDependencies"},
	} {
		report, from := policy.ReportsDevDependencies(tc.model, tc.component)
		if report != tc.report || from != tc.decidedFrom {
			t.Errorf("%s: (%v, %q), want (%v, %q)", tc.name, report, from, tc.report, tc.decidedFrom)
		}
	}
}

// Each includeDevDeps written is named with what to write instead, and one beside devDependencies
// is named as ignored.
func TestSCAWarnsOfEachIncludeDevDeps(t *testing.T) {
	model := devModel(trivyBlock(true),
		saga.ControllerSettings{"devDependencies": "report", "trivyFs": saga.ControllerSettings{"includeDevDeps": false}},
		trivyBlock(false))
	got := NewSCA().(plugin.Warner).Warnings(model)
	want := []string{
		"config.controls.sca.trivyFs.includeDevDeps is deprecated and stops being read in the next release. Replace it with config.controls.sca.devDependencies: report.",
		`components["tools"].controls.sca.trivyFs.includeDevDeps is deprecated and stops being read in the next release. Delete it; suppress is the default.`,
		`components["web"].controls.sca.trivyFs.includeDevDeps is deprecated and ignored beside components["web"].controls.sca.devDependencies. Remove it.`,
	}
	if !slices.Equal(got, want) {
		t.Errorf("warnings\n%q\nwant\n%q", got, want)
	}
	if got := NewSCA().(plugin.Warner).Warnings(devModel(nil, nil, nil)); len(got) != 0 {
		t.Errorf("a descriptor without includeDevDeps drew %q", got)
	}
}

// Both settings are declared, so validate and the schema know them, and each takes suppress or
// report and nothing else.
func TestSCADeclaresDevDependencies(t *testing.T) {
	var names []string
	for _, o := range plugin.Options(NewSCA().Info().OptionSchema) {
		names = append(names, o.Name)
	}
	slices.Sort(names)
	if !slices.Equal(names, []string{"devDependencies", "providedDependencies"}) {
		t.Errorf("options %v, want devDependencies and providedDependencies", names)
	}
	for _, key := range []string{"devDependencies", "providedDependencies"} {
		for _, v := range []string{"suppress", "report"} {
			if err := plugin.ValidateConfig(NewSCA().Info().OptionSchema, plugin.Config{key: v}); err != nil {
				t.Errorf("%s: %s: %v", key, v, err)
			}
		}
		for _, v := range []any{"include", "", true} {
			if err := plugin.ValidateConfig(NewSCA().Info().OptionSchema, plugin.Config{key: v}); err == nil {
				t.Errorf("%s: %v was accepted", key, v)
			}
		}
	}
}

// The component's setting before the project's, and suppress where nothing is written, named by
// the project's key.
func TestReportsProvidedDependenciesResolvesPerComponent(t *testing.T) {
	policy := NewSCA().(plugin.ProvidedDependencyPolicy)
	const project = "config.controls.sca.providedDependencies"
	report := saga.ControllerSettings{"providedDependencies": "report"}
	suppress := saga.ControllerSettings{"providedDependencies": "suppress"}
	for _, tc := range []struct {
		name        string
		model       saga.Model
		component   string
		report      bool
		decidedFrom string
	}{
		{"default", devModel(nil, nil, nil), "web", false, project},
		{"project", devModel(report, nil, nil), "web", true, project},
		{"component over project", devModel(report, suppress, nil), "web", false,
			`components["web"].controls.sca.providedDependencies`},
		{"other component keeps the project's", devModel(report, suppress, nil), "tools", true, project},
		{"component alone", devModel(nil, nil, report), "tools", true,
			`components["tools"].controls.sca.providedDependencies`},
		{"devDependencies decides nothing here", devModel(saga.ControllerSettings{"devDependencies": "report"}, nil, nil),
			"web", false, project},
		{"unknown component", devModel(report, nil, nil), "", true, project},
	} {
		report, from := policy.ReportsProvidedDependencies(tc.model, tc.component)
		if report != tc.report || from != tc.decidedFrom {
			t.Errorf("%s: (%v, %q), want (%v, %q)", tc.name, report, from, tc.report, tc.decidedFrom)
		}
	}
}
