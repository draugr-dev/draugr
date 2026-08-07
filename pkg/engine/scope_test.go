package engine

import (
	"slices"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

func threeComponents() saga.Model {
	return saga.Model{Components: []saga.Component{
		{Name: "app"}, {Name: "frontend"}, {Name: "payments"},
	}}
}

func TestScopeZeroValueScansEverything(t *testing.T) {
	// The ordinary case, and the one that must not have changed: a caller that never sets a
	// scope is unaffected by there being one.
	var s Scope
	if !s.Empty() {
		t.Error("the zero scope restricts nothing")
	}
	for _, name := range []string{"app", "anything"} {
		if !s.IncludesComponent(name) || !s.includesControl(name) {
			t.Errorf("%q should be in scope", name)
		}
	}
}

func TestScopeRestrictsOneAxisAtATime(t *testing.T) {
	// An empty list means "no restriction on this axis", not "nothing" — so naming components
	// runs every control against them, and naming controls runs them against every component.
	s := Scope{Components: []string{"app"}}
	if !s.includesControl("dast") {
		t.Error("naming no control must not exclude every control")
	}
	if s.IncludesComponent("frontend") {
		t.Error("a component not named is out of scope")
	}

	s = Scope{Controls: []string{"sca"}}
	if !s.IncludesComponent("frontend") {
		t.Error("naming no component must not exclude every component")
	}
	if s.includesControl("dast") {
		t.Error("a control not named is out of scope")
	}
}

func TestScopeValidateRejectsAMisspelling(t *testing.T) {
	// The failure this exists for. A name matching nothing scans nothing and passes — the "we
	// did not look" verdict a scope is otherwise careful not to produce, reached by typo.
	s := Scope{Components: []string{"frontnd"}, Controls: []string{"scaa"}}
	err := s.Validate(threeComponents(), []string{"sca", "secrets"})
	if err == nil {
		t.Fatal("a name matching nothing must not be accepted")
	}
	for _, want := range []string{"frontnd", "scaa", "--components", "--controls"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error should mention %q: %v", want, err)
		}
	}
	// The reader is one character from the answer and should not have to go and find it.
	for _, want := range []string{"app, frontend, payments", "sca, secrets"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error should list what is available (%q): %v", want, err)
		}
	}
}

func TestScopeValidateAcceptsWhatExists(t *testing.T) {
	s := Scope{Components: []string{"app", "payments"}, Controls: []string{"sca"}}
	if err := s.Validate(threeComponents(), []string{"sca", "secrets"}); err != nil {
		t.Errorf("every name exists: %v", err)
	}
}

func TestScopeResolveNamesWhatWasLeftOut(t *testing.T) {
	// Two components named out of three, so the skipped list is neither empty nor everything —
	// with one component either way, an implementation that returned the wrong set would look
	// right.
	s := Scope{Components: []string{"app"}}.Resolve(threeComponents())
	if want := []string{"frontend", "payments"}; !slices.Equal(s.SkippedComponents, want) {
		t.Errorf("got %q, want %q", s.SkippedComponents, want)
	}
	// Declaration order, not sorted: the reader is comparing this against their descriptor.
	s = Scope{Components: []string{"frontend"}}.Resolve(saga.Model{Components: []saga.Component{
		{Name: "zeta"}, {Name: "frontend"}, {Name: "alpha"},
	}})
	if want := []string{"zeta", "alpha"}; !slices.Equal(s.SkippedComponents, want) {
		t.Errorf("got %q, want %q — declaration order", s.SkippedComponents, want)
	}
}

func TestScopeResolveSaysNothingWhenNoComponentWasNamed(t *testing.T) {
	// A control-only scope skips no component, and claiming otherwise would put every component
	// in the report as "not scanned" on a run that scanned all of them.
	s := Scope{Controls: []string{"sca"}}.Resolve(threeComponents())
	if len(s.SkippedComponents) != 0 {
		t.Errorf("nothing was skipped: %q", s.SkippedComponents)
	}
}

func TestPlanRestrictsToTheScope(t *testing.T) {
	// Two components and two controls, because one of each cannot tell a filter that works from
	// one that drops everything or nothing.
	model := saga.Model{
		Config: saga.Config{Controllers: map[string]saga.ControllerSettings{
			"alpha": {"enabled": true}, "beta": {"enabled": true},
		}},
		Components: []saga.Component{
			{Name: "app", Repositories: []saga.Repository{{URL: "a"}}},
			{Name: "frontend", Repositories: []saga.Repository{{URL: "b"}}},
		},
	}
	reg := NewRegistry()
	reg.RegisterController(&scopeTestController{name: "alpha"})
	reg.RegisterController(&scopeTestController{name: "beta"})

	planned, err := New(reg, WithScope(Scope{Components: []string{"app"}, Controls: []string{"alpha"}})).Plan(model)
	if err != nil {
		t.Fatal(err)
	}
	if len(planned) != 1 {
		t.Fatalf("want one job (alpha × app), got %d: %+v", len(planned), planned)
	}
	if planned[0].Control != "alpha" || planned[0].Component != "app" {
		t.Errorf("planned %s/%s, want alpha/app", planned[0].Control, planned[0].Component)
	}

	// And without a scope, all four.
	planned, err = New(reg).Plan(model)
	if err != nil {
		t.Fatal(err)
	}
	if len(planned) != 4 {
		t.Errorf("an unscoped run plans every pair, got %d", len(planned))
	}
}

func TestRunCarriesItsScope(t *testing.T) {
	// The result has to say what it covered, because every artifact it becomes has to.
	reg := NewRegistry()
	reg.RegisterController(&scopeTestController{name: "alpha"})
	reg.RegisterScanner(&fakeScanner{name: "alpha"})
	sc := Scope{Components: []string{"app"}}
	res, err := New(reg, WithScope(sc)).Run(t.Context(), saga.Model{
		Config:     saga.Config{Controllers: map[string]saga.ControllerSettings{"alpha": {"enabled": true}}},
		Components: []saga.Component{{Name: "app"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(res.Scope.Components, sc.Components) {
		t.Errorf("the run lost its scope: %+v", res.Scope)
	}
}

// scopeTestController plans one no-op job per component, so the count of planned jobs is the
// only thing under test.
type scopeTestController struct{ name string }

func (c *scopeTestController) Info() plugin.ControllerInfo {
	return plugin.ControllerInfo{Name: c.name, Scope: plugin.ScopeComponent}
}

func (c *scopeTestController) Plan(_ saga.Model, comp *saga.Component) ([]plugin.ScanJob, error) {
	if comp == nil {
		return nil, nil
	}
	return []plugin.ScanJob{{Scanner: c.name, Target: plugin.ImageTarget{Ref: "x"}}}, nil
}

func (c *scopeTestController) Aggregate(reports []sarif.Report) (plugin.ControlResult, error) {
	return plugin.ControlResult{Report: sarif.Merge(reports...)}, nil
}
