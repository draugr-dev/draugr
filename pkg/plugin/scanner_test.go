package plugin

import (
	"testing"
	"time"
)

// An effect with no Option applies to every job; one with an Option only where the job's config
// sets that option to true. A value that is not true, or not a boolean, does not turn it on.
func TestEffectsForReadsTheOption(t *testing.T) {
	always := Effect{Kind: EffectNetwork, Detail: "probes"}
	optional := Effect{Kind: EffectDisclosure, Detail: "sends coordinates", Option: "resolve"}
	info := ScannerInfo{Effects: []Effect{always, optional}}
	for name, tc := range map[string]struct {
		cfg  Config
		want int
	}{
		"no config":   {nil, 1},
		"option off":  {Config{"resolve": false}, 1},
		"not a bool":  {Config{"resolve": "true"}, 1},
		"option on":   {Config{"resolve": true}, 2},
		"other is on": {Config{"other": true}, 1},
	} {
		got := EffectsFor(info, tc.cfg)
		if len(got) != tc.want || got[0] != always {
			t.Errorf("%s: EffectsFor = %+v, want %d starting with the unconditional one", name, got, tc.want)
		}
	}
	if got := EffectsFor(ScannerInfo{}, Config{"resolve": true}); got != nil {
		t.Errorf("a scanner declaring nothing has nothing: %+v", got)
	}
}

func TestEffectKindsCoversTheTaxonomy(t *testing.T) {
	// The Saga schema's allowEffects enum is generated from this, so a kind missing here is a
	// value the schema rejects and the binary accepts, an editor disagreeing with Draugr.
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
	// the letter and trips the throttle, their window rarely starts where ours did.
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
