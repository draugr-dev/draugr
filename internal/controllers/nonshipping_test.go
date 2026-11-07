package controllers

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// nonShippingModel is a descriptor whose project block for control is project, and whose two
// components carry web and tools as theirs.
func nonShippingModel(control string, project, web, tools saga.ControllerSettings) saga.Model {
	m := saga.Model{Config: saga.Config{Controls: map[string]saga.ControllerSettings{control: project}}}
	for _, name := range []string{"tools", "web"} {
		c := saga.Component{Name: name}
		s := map[string]saga.ControllerSettings{"web": web, "tools": tools}[name]
		if s != nil {
			c.Controls = map[string]saga.ControllerSettings{control: s}
		}
		m.Components = append(m.Components, c)
	}
	return m
}

// Each of sast, iac and sca resolves its own nonShippingPaths: the component's over the project's,
// and report where nothing is written, named by the project's key.
func TestReportsNonShippingResolvesPerComponent(t *testing.T) {
	t.Parallel()
	report := saga.ControllerSettings{"nonShippingPaths": "report"}
	suppress := saga.ControllerSettings{"nonShippingPaths": "suppress"}
	for _, control := range []string{"sast", "iac", "sca"} {
		var policy plugin.NonShippingPolicy
		switch control {
		case "sast":
			policy = NewSAST().(plugin.NonShippingPolicy)
		case "iac":
			policy = NewIAC().(plugin.NonShippingPolicy)
		default:
			policy = NewSCA().(plugin.NonShippingPolicy)
		}
		project := "config.controls." + control + ".nonShippingPaths"
		web := `components["web"].controls.` + control + ".nonShippingPaths"
		for _, tc := range []struct {
			name        string
			model       saga.Model
			component   string
			report      bool
			decidedFrom string
		}{
			{"default", nonShippingModel(control, nil, nil, nil), "web", true, project},
			{"project", nonShippingModel(control, suppress, nil, nil), "web", false, project},
			{"component over project", nonShippingModel(control, suppress, report, nil), "web", true, web},
			{"other component keeps the project's", nonShippingModel(control, suppress, report, nil), "tools", false, project},
			{"component suppresses over the default", nonShippingModel(control, nil, suppress, nil), "web", false, web},
			{"unknown component", nonShippingModel(control, suppress, report, nil), "", false, project},
		} {
			got, from := policy.ReportsNonShipping(tc.model, tc.component)
			if got != tc.report || from != tc.decidedFrom {
				t.Errorf("%s %s: (%v, %q), want (%v, %q)", control, tc.name, got, from, tc.report, tc.decidedFrom)
			}
		}
	}
}

// Another control's setting answers nothing for this one: iac set to suppress leaves sast counting.
func TestNonShippingIsReadFromTheControlsOwnBlock(t *testing.T) {
	t.Parallel()
	m := nonShippingModel("iac", saga.ControllerSettings{"nonShippingPaths": "suppress"}, nil, nil)
	if got, from := NewSAST().(plugin.NonShippingPolicy).ReportsNonShipping(m, "web"); !got ||
		from != "config.controls.sast.nonShippingPaths" {
		t.Errorf("sast read iac's setting: (%v, %q)", got, from)
	}
}

// secrets does not take the setting and is never asked: a credential beside a test is still live.
func TestSecretsHasNoNonShippingPolicy(t *testing.T) {
	t.Parallel()
	if _, ok := NewSecrets().(plugin.NonShippingPolicy); ok {
		t.Error("secrets implements NonShippingPolicy, so its findings under tests/ would be marked and could be set aside")
	}
	for _, o := range plugin.Options(NewSecrets().Info().OptionSchema) {
		if o.Name == nonShippingKey {
			t.Error("secrets declares nonShippingPaths")
		}
	}
}

// sast, iac and sca each declare the setting with report as its default, in a schema that parses.
func TestNonShippingIsDeclaredByEachControl(t *testing.T) {
	t.Parallel()
	for _, c := range []plugin.Controller{NewSAST(), NewIAC(), NewSCA()} {
		info := c.Info()
		var schema struct {
			Properties map[string]struct {
				Default string `json:"default"`
			} `json:"properties"`
		}
		if err := json.Unmarshal(info.OptionSchema, &schema); err != nil {
			t.Fatalf("%s: option schema does not parse: %v", info.Name, err)
		}
		p, ok := schema.Properties[nonShippingKey]
		if !ok {
			t.Errorf("%s does not declare %s", info.Name, nonShippingKey)
			continue
		}
		if p.Default != devReport {
			t.Errorf("%s: %s defaults to %q, want report", info.Name, nonShippingKey, p.Default)
		}
		var names []string
		for _, o := range plugin.Options(info.OptionSchema) {
			names = append(names, o.Name)
		}
		if !slices.Contains(names, nonShippingKey) {
			t.Errorf("%s: plugin.Options does not list %s: %v", info.Name, nonShippingKey, names)
		}
		for _, v := range []string{"suppress", "report"} {
			if err := plugin.ValidateConfig(info.OptionSchema, plugin.Config{nonShippingKey: v}); err != nil {
				t.Errorf("%s: %s: %v", info.Name, v, err)
			}
		}
		for _, v := range []any{"ignore", "", false} {
			if err := plugin.ValidateConfig(info.OptionSchema, plugin.Config{nonShippingKey: v}); err == nil {
				t.Errorf("%s: %v was accepted", info.Name, v)
			}
		}
	}
}
