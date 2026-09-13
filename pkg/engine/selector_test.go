package engine

import (
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/saga"
)

// monorepo is one repository carved into components by different teams, which is the shape these
// selectors exist for.
func monorepo() saga.Model {
	return saga.Model{Components: []saga.Component{
		{Name: "storefront", Exposure: saga.ExposurePublic, Criticality: saga.CriticalityImportant,
			Labels: map[string]string{"team": "web", "tier": "1"}},
		{Name: "checkout", Exposure: saga.ExposurePublic, Criticality: saga.CriticalityCritical,
			Labels: map[string]string{"team": "web", "tier": "0"}},
		{Name: "ledger", Exposure: saga.ExposureInternal, Criticality: saga.CriticalityCritical,
			Labels: map[string]string{"team": "payments", "tier": "0"}},
		{Name: "docs", Exposure: saga.ExposureRestricted, Criticality: saga.CriticalitySupporting},
	}}
}

// A selector resolves to a component list, so everything downstream sees what every other kind of
// narrowing produces and nothing has to learn a second shape.
func TestSelectorsResolveToComponents(t *testing.T) {
	for _, tc := range []struct {
		name  string
		scope Scope
		want  []string
	}{
		{"one label", Scope{Labels: []string{"team=web"}}, []string{"storefront", "checkout"}},
		{
			// Two values on one key are alternatives, which is what anybody who has written a
			// label selector expects.
			"one key twice", Scope{Labels: []string{"team=web", "team=payments"}},
			[]string{"storefront", "checkout", "ledger"},
		},
		{
			// Two keys narrow together.
			"two keys", Scope{Labels: []string{"team=web", "tier=0"}}, []string{"checkout"},
		},
		{"an exposure", Scope{Exposure: []saga.Exposure{saga.ExposurePublic}}, []string{"storefront", "checkout"}},
		{
			"two exposures",
			Scope{Exposure: []saga.Exposure{saga.ExposurePublic, saga.ExposureInternal}},
			[]string{"storefront", "checkout", "ledger"},
		},
		{
			"a criticality", Scope{Criticality: []saga.Criticality{saga.CriticalityCritical}},
			[]string{"checkout", "ledger"},
		},
		{
			// The question a release check asks: what is both exposed and worth the most.
			"across two axes",
			Scope{Exposure: []saga.Exposure{saga.ExposurePublic}, Criticality: []saga.Criticality{saga.CriticalityCritical}},
			[]string{"checkout"},
		},
		{
			// Names and selectors narrow together rather than adding up.
			"a name and a selector",
			Scope{Components: []string{"storefront", "ledger"}, Labels: []string{"team=web"}},
			[]string{"storefront"},
		},
		{
			// A component that declares no labels is matched by no label selector.
			"a component with no labels", Scope{Labels: []string{"team=web"}}, []string{"storefront", "checkout"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.scope.Resolve(monorepo()).Components
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Errorf("Components = %v, want %v", got, tc.want)
			}
		})
	}
}

// What was left out is named, the same as for any other narrowing, so a scoped run cannot look
// like a whole one.
func TestASelectedRunSaysWhatItSkipped(t *testing.T) {
	got := Scope{Labels: []string{"team=web"}}.Resolve(monorepo())
	if want := "ledger,docs"; strings.Join(got.SkippedComponents, ",") != want {
		t.Errorf("SkippedComponents = %v, want %v", got.SkippedComponents, want)
	}
}

// A selector that matches nothing scans nothing and passes, which is the verdict this type exists
// to avoid reaching by accident.
func TestASelectorThatMatchesNothingIsRefused(t *testing.T) {
	err := Scope{Labels: []string{"team=nope"}}.Validate(monorepo(), nil)
	if err == nil {
		t.Fatal("a selector matching nothing was accepted, so the run would scan nothing and pass")
	}
	// What it offers is the values that key has, because a reader who mistyped one is a word away
	// from the answer. Component names are not that answer: they may not carry the key at all, and
	// a monorepo, which is the case these selectors exist for, has hundreds of them.
	for _, want := range []string{"team=nope", "matches no component", "team=web", "team=payments"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not say %q: %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "storefront") {
		t.Errorf("the error lists component names, which is a wall on the repositories this is for: %v", err)
	}
}

// A key nothing declares is said plainly, rather than offering an empty list of values.
func TestAnUnknownLabelKeySaysSo(t *testing.T) {
	err := Scope{Labels: []string{"squad=web"}}.Validate(monorepo(), nil)
	if err == nil || !strings.Contains(err.Error(), `no component declares label "squad"`) {
		t.Errorf("error = %v, want one naming the key nothing carries", err)
	}
}

// A classification that matches nothing adds no list. Every message about these already names all
// four values, so repeating them where the reader has already chosen one is noise.
func TestAClassificationThatMatchesNothingOffersNoList(t *testing.T) {
	err := Scope{Exposure: []saga.Exposure{saga.ExposureAuthenticated}}.Validate(monorepo(), nil)
	if err == nil {
		t.Fatal("an exposure no component declares was accepted")
	}
	if strings.Contains(err.Error(), "(") {
		t.Errorf("the error appends a list where the reader needs none: %v", err)
	}
}

// A long list is cut, and the tail is counted so nobody reads what is left as the whole set.
func TestALongListIsNotAWall(t *testing.T) {
	var big saga.Model
	for _, n := range []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l"} {
		big.Components = append(big.Components, saga.Component{Name: n})
	}
	err := Scope{Components: []string{"nope"}}.Validate(big, nil)
	if err == nil {
		t.Fatal("an unknown component was accepted")
	}
	if !strings.Contains(err.Error(), "and 4 more") {
		t.Errorf("error does not count what it left out: %v", err)
	}
	if strings.Contains(err.Error(), ", l") {
		t.Errorf("error lists every component: %v", err)
	}
}

// Draugr's own vocabulary is answered with the values that are right, which a label cannot be:
// the keys and values there are the organization's and there is no list to check them against.
func TestAWrongClassificationNamesTheRightOnes(t *testing.T) {
	err := Scope{Exposure: []saga.Exposure{"pubic"}}.Validate(monorepo(), nil)
	if err == nil {
		t.Fatal("an exposure that does not exist was accepted")
	}
	for _, want := range []string{"pubic", "public", "authenticated", "internal", "restricted"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not say %q: %v", want, err)
		}
	}
}

// A selector that is not one is rejected as the shape it should have been, rather than matching
// nothing and being reported as an empty result.
func TestAMalformedSelectorIsRefusedAsMalformed(t *testing.T) {
	// An empty value is rejected with the rest. A missing key and an empty one read the same from a
	// map, so `team=` would otherwise select every component nobody has labeled, which is the
	// opposite of what somebody typing it is asking for.
	for _, bad := range []string{"team", "team=", "=web", ""} {
		err := Scope{Labels: []string{bad}}.Validate(monorepo(), nil)
		if err == nil || !strings.Contains(err.Error(), "key=value") {
			t.Errorf("Validate(%q) = %v, want an error naming the shape", bad, err)
		}
	}
}

// A scope that selects restricts something, even before Resolve has turned it into names. Read
// wrongly, a selected run would render as an unscoped one.
func TestASelectingScopeIsNotEmpty(t *testing.T) {
	if (Scope{Labels: []string{"team=web"}}).Empty() {
		t.Error("a scope selecting by label reports itself as restricting nothing")
	}
	if !(Scope{}).Empty() {
		t.Error("the zero scope restricts something")
	}
}

// The request travels beside the result. Two runs naming the same components may have been asked
// different questions, and a set that shrank because a label moved looks like a deliberate
// narrowing from the artifact alone.
func TestTheSelectorTravelsWithTheResult(t *testing.T) {
	sel := Scope{Labels: []string{"team=web"}, Exposure: []saga.Exposure{saga.ExposurePublic}}.Selectors()
	if len(sel) != 2 {
		t.Fatalf("Selectors() = %v, want the label and the exposure", sel)
	}
	if sel[0].Key != "labels" || sel[0].Value != "team=web" {
		t.Errorf("Selectors()[0] = %+v", sel[0])
	}
	if len(Scope{Components: []string{"a"}}.Selectors()) != 0 {
		t.Error("a scope that named components claims a selector")
	}
}
