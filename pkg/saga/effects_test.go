package saga

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// One shape, and the one shape parses.
func TestAllowEffectsIsAList(t *testing.T) {
	var m Model
	if err := yaml.Unmarshal([]byte("config:\n  allowEffects: [network, mutate]\n"), &m); err != nil {
		t.Fatal(err)
	}
	if got := []string(m.Config.AllowEffects); len(got) != 2 || got[0] != "network" || got[1] != "mutate" {
		t.Errorf("allowEffects = %v", got)
	}
}

// The shape that used to work is refused by name. Left to the default decoder it produces
// "cannot unmarshal !!map into saga.EffectPermissions" — a Go type nobody reading a descriptor has
// heard of, for a shape our own documentation told them to write.
func TestAllowEffectsRefusesTheOldMappingByName(t *testing.T) {
	var m Model
	err := yaml.Unmarshal([]byte("config:\n  allowEffects:\n    staging: [mutate]\n    production: []\n"), &m)
	if err == nil {
		t.Fatal("a mapping parsed, so a descriptor keeps a permission that no longer applies")
	}
	for _, want := range []string{"config.allowEffects", "is now a list", "second descriptor"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not say %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "saga.EffectPermissions") {
		t.Errorf("the error names a Go type: %q", err)
	}
}

// A value that is neither says what a value should look like, rather than reporting a type.
func TestAllowEffectsRefusesAScalar(t *testing.T) {
	var m Model
	err := yaml.Unmarshal([]byte("config:\n  allowEffects: network\n"), &m)
	if err == nil || !strings.Contains(err.Error(), "must be a list of effects") {
		t.Errorf("err = %v, want a message naming the shape", err)
	}
}

// An effect kind nothing declares is a permission that can never apply, so it is a refusal rather
// than a line that quietly does nothing.
func TestAllowEffectsRejectsAnUnknownKind(t *testing.T) {
	errs := EffectPermissions{"network", "teleport"}.validate()
	if len(errs) != 1 {
		t.Fatalf("errs = %v, want one for the kind nothing declares", errs)
	}
	msg := errs[0].Error()
	if !strings.Contains(msg, `"teleport"`) || !strings.Contains(msg, "mutate") {
		t.Errorf("error %q should name the value and the kinds that exist", msg)
	}
}

// Every kind a scanner can declare has to be accepted here, or a scanner ships an effect no
// descriptor can permit and the control is unreachable.
func TestAllowEffectsAcceptsEveryDeclaredKind(t *testing.T) {
	if errs := (EffectPermissions{"disclosure", "mutate", "network", "privilege"}).validate(); errs != nil {
		t.Errorf("errs = %v, want none", errs)
	}
}

func TestEffectPermissionsEmpty(t *testing.T) {
	if !(EffectPermissions{}).Empty() {
		t.Error("nothing accepted should be empty")
	}
	if (EffectPermissions{"network"}).Empty() {
		t.Error("something accepted should not be empty")
	}
}
