package plugin

import (
	"slices"
	"testing"
)

// An effect whose option is on by default applies until the config sets it false, and an online
// effect does not apply to an offline run.
func TestEffectsForDefaultAndOnline(t *testing.T) {
	t.Setenv("DRAUGR_OFFLINE", "0")
	info := ScannerInfo{Effects: []Effect{
		{Kind: EffectNetwork},
		{Kind: EffectDisclosure, Option: "callbacks", Default: true, Online: true},
		{Kind: EffectMutate, Option: "writes"},
	}}
	kinds := func(cfg Config) []EffectKind {
		var out []EffectKind
		for _, e := range EffectsFor(info, cfg) {
			out = append(out, e.Kind)
		}
		return out
	}
	for name, c := range map[string]struct {
		cfg  Config
		want []EffectKind
	}{
		"unset":         {nil, []EffectKind{EffectNetwork, EffectDisclosure}},
		"set false":     {Config{"callbacks": false}, []EffectKind{EffectNetwork}},
		"both set true": {Config{"callbacks": true, "writes": true}, []EffectKind{EffectNetwork, EffectDisclosure, EffectMutate}},
		"not a boolean": {Config{"callbacks": "no"}, []EffectKind{EffectNetwork, EffectDisclosure}},
	} {
		if got := kinds(c.cfg); !slices.Equal(got, c.want) {
			t.Errorf("%s: %v, want %v", name, got, c.want)
		}
	}
	t.Setenv("DRAUGR_OFFLINE", "1")
	if got := kinds(nil); !slices.Equal(got, []EffectKind{EffectNetwork}) {
		t.Errorf("offline: %v, want network alone", got)
	}
}
