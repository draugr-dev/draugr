package plugin

import (
	"testing"
	"time"
)

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

func TestRateInterval(t *testing.T) {
	// The spacing between calls, not the window. A vendor publishes "4 per minute"; Draugr turns
	// that into one call every fifteen seconds rather than four at once, because a burst obeys
	// the letter and trips the throttle — their window rarely starts where ours did.
	if got := (Rate{Requests: 4, Per: time.Minute}).Interval(); got != 15*time.Second {
		t.Errorf("4/minute = %v, want 15s", got)
	}
	if got := (Rate{Requests: 1000, Per: time.Minute}).Interval(); got != 60*time.Millisecond {
		t.Errorf("1000/minute = %v", got)
	}
	// A zero or nonsensical rate means no limit rather than an infinite wait, which would hang a
	// scan on a scanner that declared its rate carelessly.
	for _, r := range []Rate{{}, {Requests: 4}, {Per: time.Minute}, {Requests: -1, Per: time.Minute}} {
		if got := r.Interval(); got != 0 {
			t.Errorf("%+v should mean no limit, got %v", r, got)
		}
	}
}
