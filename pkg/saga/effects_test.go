package saga

import (
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Both shapes have to parse, because the list form is what every existing descriptor uses and the
// mapping is what makes the permission match the decision.
func TestAllowEffectsAcceptsBothShapes(t *testing.T) {
	var asList Config
	if err := yaml.Unmarshal([]byte("allowEffects: [network, mutate]"), &asList); err != nil {
		t.Fatal(err)
	}
	if want := []string{"network", "mutate"}; !reflect.DeepEqual(asList.AllowEffects.Everywhere, want) {
		t.Errorf("list form = %+v, want %v", asList.AllowEffects.Everywhere, want)
	}

	var byEnv Config
	doc := "allowEffects:\n  staging: [network, mutate]\n  production: []\n"
	if err := yaml.Unmarshal([]byte(doc), &byEnv); err != nil {
		t.Fatal(err)
	}
	if got := byEnv.AllowEffects.Environments(); !reflect.DeepEqual(got, []string{"production", "staging"}) {
		t.Errorf("environments = %v", got)
	}
}

// A list means every environment, including the ones nobody has declared. It is not a shorthand
// for a mapping, and reading it as one would make an unstated target inherit nothing.
func TestTheListFormReachesEveryEnvironment(t *testing.T) {
	p := EffectPermissions{Everywhere: []string{"network"}}
	for _, env := range []string{"", "staging", "production", "somewhere-new"} {
		if got := p.In(env); !reflect.DeepEqual(got, []string{"network"}) {
			t.Errorf("In(%q) = %v, want [network]", env, got)
		}
	}
}

// The whole safety argument: a permission granted to one environment must not reach another, and a
// target that declared no environment must not inherit the most permissive entry.
func TestAPermissionDoesNotLeakBetweenEnvironments(t *testing.T) {
	p := EffectPermissions{
		Everywhere:    []string{"disclosure"},
		ByEnvironment: map[string][]string{"staging": {"network", "mutate"}, "production": {}},
	}
	for name, tc := range map[string]struct {
		env  string
		want []string
	}{
		"staging gets its own and the shared": {"staging", []string{"disclosure", "network", "mutate"}},
		"production gets only the shared":     {"production", []string{"disclosure"}},
		"an unstated target inherits nothing": {"", []string{"disclosure"}},
		"an undeclared environment likewise":  {"qa", []string{"disclosure"}},
	} {
		t.Run(name, func(t *testing.T) {
			if got := p.In(tc.env); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("In(%q) = %v, want %v", tc.env, got, tc.want)
			}
		})
	}
}

// A declared environment with an empty list is a decision. It must not read as an omission that
// falls back to something else.
func TestAnEmptyListAcceptsNothing(t *testing.T) {
	p := EffectPermissions{ByEnvironment: map[string][]string{"production": {}}}
	if got := p.In("production"); len(got) != 0 {
		t.Errorf("In(production) = %v, want nothing", got)
	}
	if p.Empty() {
		t.Error("a descriptor that named production is not empty of permissions")
	}
}

// Names are matched between a target and this block, so case and punctuation differences are two
// environments as far as anything reading them is concerned.
func TestEnvironmentKeysAreChecked(t *testing.T) {
	bad := EffectPermissions{ByEnvironment: map[string][]string{"Production": {"network"}}}
	if errs := bad.validate(); len(errs) != 1 {
		t.Fatalf("got %d errors, want 1", len(errs))
	}
	good := EffectPermissions{ByEnvironment: map[string][]string{"pre-prod-2": {"network"}}}
	if errs := good.validate(); len(errs) != 0 {
		t.Errorf("a valid name was rejected: %v", errs)
	}
}

// Whichever shape was written has to come back out, or re-serializing a model — which is how its
// digest is computed — would depend on which form somebody happened to use.
func TestBothShapesRoundTrip(t *testing.T) {
	for name, doc := range map[string]string{
		"list":    "allowEffects:\n    - network\n",
		"mapping": "allowEffects:\n    staging:\n        - network\n",
		"absent":  "{}\n",
	} {
		t.Run(name, func(t *testing.T) {
			var cfg Config
			if err := yaml.Unmarshal([]byte(doc), &cfg); err != nil {
				t.Fatal(err)
			}
			out, err := yaml.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			var back Config
			if err := yaml.Unmarshal(out, &back); err != nil {
				t.Fatalf("re-reading what we wrote failed: %v\n%s", err, out)
			}
			if !reflect.DeepEqual(cfg.AllowEffects, back.AllowEffects) {
				t.Errorf("round trip changed the permissions:\n%+v\n%+v\n%s",
					cfg.AllowEffects, back.AllowEffects, out)
			}
		})
	}
}

// Anything that is neither list nor mapping is a mistake worth naming, not a silent empty.
func TestAScalarIsRefused(t *testing.T) {
	var cfg Config
	err := yaml.Unmarshal([]byte("allowEffects: network"), &cfg)
	if err == nil {
		t.Fatal("a scalar was accepted")
	}
	if !strings.Contains(err.Error(), "list of effects") {
		t.Errorf("the error does not say what the shapes are: %v", err)
	}
}
