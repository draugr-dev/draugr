package plugin

import "testing"

func TestEffectKindsCoversTheTaxonomy(t *testing.T) {
	// The Saga schema's allowEffects enum is generated from this, so a kind missing here is a
	// value the schema rejects and the binary accepts — an editor disagreeing with Draugr.
	kinds := EffectKinds()
	seen := map[EffectKind]bool{}
	for _, k := range kinds {
		if seen[k] {
			t.Errorf("%q listed twice", k)
		}
		seen[k] = true
		if k.Describe() == "" || k.Describe() == string(k) {
			t.Errorf("%q has no description, so a schema tooltip would show its own name", k)
		}
	}
	for _, k := range []EffectKind{EffectMutate, EffectPrivilege, EffectNetwork, EffectDisclosure} {
		if !seen[k] {
			t.Errorf("%q is declarable but not in EffectKinds()", k)
		}
	}
	if got := EffectKind("invented").Describe(); got != "invented" {
		t.Errorf("an unknown kind should describe itself, got %q", got)
	}
}

func TestOnlyConsequencesToTheTargetRequireConsent(t *testing.T) {
	// Mutating a target or taking elevated access is a decision someone should make on purpose.
	for _, k := range []EffectKind{EffectMutate, EffectPrivilege} {
		if !k.RequiresConsent() {
			t.Errorf("%q should require consent", k)
		}
	}
	// Network and disclosure are declared, not gated: the controls that do them exist to do them,
	// and a prompt for the thing a control is *for* becomes a keystroke people learn to skip.
	for _, k := range []EffectKind{EffectNetwork, EffectDisclosure, ""} {
		if k.RequiresConsent() {
			t.Errorf("%q should be declared rather than gated", k)
		}
	}
}
