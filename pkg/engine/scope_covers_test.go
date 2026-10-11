package engine

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/saga"
)

// A scope covers a component when it ran every control the component enables, and the project
// when it covered every component.
func TestScopeCovers(t *testing.T) {
	model := saga.Model{Components: []saga.Component{{Name: "api"}, {Name: "web"}}}
	for _, c := range []struct {
		name              string
		scope             Scope
		project, api, web bool
	}{
		{"whole run", Scope{}, true, true, true},
		{"one component", Scope{Components: []string{"web"}}, false, false, true},
		{"every component by name", Scope{Components: []string{"api", "web"}}, true, true, true},
		{"narrowed by control", Scope{Controls: []string{"sast"}}, false, false, false},
	} {
		covered := c.scope.Resolve(model).covers(model)
		if covered("") != c.project || covered("api") != c.api || covered("web") != c.web {
			t.Errorf("%s: project %v api %v web %v, want %v %v %v", c.name,
				covered(""), covered("api"), covered("web"), c.project, c.api, c.web)
		}
	}
}

// An exclusion names findings whichever control produced them, so a run that left a control or a
// component out cannot say one matched nothing. A whole run still can.
func TestARunNarrowedByScopeReportsNoExclusionAsUnmatched(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterController(&scopeTestController{name: "alpha"})
	reg.RegisterController(&scopeTestController{name: "beta"})
	reg.RegisterScanner(&fakeScanner{name: "alpha"})
	reg.RegisterScanner(&fakeScanner{name: "beta"})
	model := saga.Model{
		Config: saga.Config{
			Controls: map[string]saga.ControllerSettings{"alpha": {"enabled": true}, "beta": {"enabled": true}},
			Exclude:  []saga.ExcludeRule{{Rules: []string{"CVE-NOWHERE"}, Reason: "fixed upstream"}},
		},
		Components: []saga.Component{{Name: "app"}, {Name: "web"}},
	}
	for _, c := range []struct {
		name  string
		scope Scope
		want  int
	}{
		{"whole run", Scope{}, 1},
		{"one control", Scope{Controls: []string{"alpha"}}, 0},
		{"one component", Scope{Components: []string{"web"}}, 0},
	} {
		res, err := New(reg, WithScope(c.scope.Resolve(model))).Run(t.Context(), model)
		if err != nil {
			t.Fatal(err)
		}
		if len(res.UnmatchedExclusions) != c.want {
			t.Errorf("%s: unmatched exclusions = %+v, want %d", c.name, res.UnmatchedExclusions, c.want)
		}
	}
}
