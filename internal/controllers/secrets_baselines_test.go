package controllers

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/saga"
)

// detectSecretsBaselines resolves as every suppress-or-report setting does: the component's, then
// the project's, then suppress, each named by the key a reader edits.
func TestReportsDetectSecretsBaselinesResolvesPerComponent(t *testing.T) {
	const project = "config.controls.secrets.detectSecretsBaselines"
	model := func(proj, comp saga.ControllerSettings) saga.Model {
		m := saga.Model{Config: saga.Config{Controls: map[string]saga.ControllerSettings{"secrets": proj}},
			Components: []saga.Component{{Name: "web"}, {Name: "api"}}}
		if comp != nil {
			m.Components[0].Controls = map[string]saga.ControllerSettings{"secrets": comp}
		}
		return m
	}
	report := saga.ControllerSettings{"detectSecretsBaselines": "report"}
	suppress := saga.ControllerSettings{"detectSecretsBaselines": "suppress"}
	for _, c := range []struct {
		name      string
		model     saga.Model
		component string
		want      bool
		from      string
	}{
		{"default", model(nil, nil), "web", false, project},
		{"project", model(report, nil), "api", true, project},
		{"component over project", model(report, suppress), "web", false, `components["web"].controls.secrets.detectSecretsBaselines`},
	} {
		got, from := Secrets{}.ReportsDetectSecretsBaselines(c.model, c.component)
		if got != c.want || from != c.from {
			t.Errorf("%s: %v from %q, want %v from %q", c.name, got, from, c.want, c.from)
		}
	}
	if (Secrets{}).Info().OptionSchema == nil {
		t.Error("the secrets control declares no option schema, so the key would be refused")
	}
}
