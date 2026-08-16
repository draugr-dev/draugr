package controllers

import (
	"reflect"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/saga"
)

func names(sels []scannerSelection) []string {
	out := make([]string, len(sels))
	for i, s := range sels {
		out[i] = s.Name
	}
	return out
}

func TestResolveScannersDefault(t *testing.T) {
	// No config → the default scanner, no config.
	sels := resolveScanners(saga.Model{}, &saga.Component{}, "sast", []string{"semgrep"})
	if !reflect.DeepEqual(names(sels), []string{"semgrep"}) {
		t.Fatalf("names = %v, want [semgrep]", names(sels))
	}
	if sels[0].Config != nil {
		t.Errorf("config = %v, want nil", sels[0].Config)
	}
}

func TestResolveScannersDefaultDisabled(t *testing.T) {
	// A default scanner can be turned off with enabled:false.
	comp := &saga.Component{Controllers: map[string]saga.ControllerSettings{
		"sast": {"semgrep": map[string]any{"enabled": false}},
	}}
	sels := resolveScanners(saga.Model{}, comp, "sast", []string{"semgrep"})
	if len(sels) != 0 {
		t.Fatalf("want no scanners, got %v", names(sels))
	}
}

func TestResolveScannersNonDefaultOptIn(t *testing.T) {
	// A non-default scanner runs only when explicitly enabled; order is defaults then extras.
	comp := &saga.Component{Controllers: map[string]saga.ControllerSettings{
		"sast": {"gosec": map[string]any{"enabled": true}},
	}}
	sels := resolveScanners(saga.Model{}, comp, "sast", []string{"semgrep"})
	if !reflect.DeepEqual(names(sels), []string{"semgrep", "gosec"}) {
		t.Fatalf("names = %v, want [semgrep gosec]", names(sels))
	}
}

func TestResolveScannersNonDefaultNotEnabledIgnored(t *testing.T) {
	// A non-default block without enabled:true is not run (config alone doesn't opt in).
	comp := &saga.Component{Controllers: map[string]saga.ControllerSettings{
		"sast": {"gosec": map[string]any{"severity": "medium"}},
	}}
	sels := resolveScanners(saga.Model{}, comp, "sast", []string{"semgrep"})
	if !reflect.DeepEqual(names(sels), []string{"semgrep"}) {
		t.Fatalf("names = %v, want [semgrep]", names(sels))
	}
}

func TestResolveScannersExtrasSorted(t *testing.T) {
	comp := &saga.Component{Controllers: map[string]saga.ControllerSettings{
		"sast": {
			"zeta":  map[string]any{"enabled": true},
			"alpha": map[string]any{"enabled": true},
		},
	}}
	sels := resolveScanners(saga.Model{}, comp, "sast", []string{"semgrep"})
	if !reflect.DeepEqual(names(sels), []string{"semgrep", "alpha", "zeta"}) {
		t.Fatalf("names = %v, want [semgrep alpha zeta]", names(sels))
	}
}

func TestResolveScannersConfig(t *testing.T) {
	// The scanner's config is its block minus "enabled".
	comp := &saga.Component{Controllers: map[string]saga.ControllerSettings{
		"sast": {"semgrep": map[string]any{"enabled": true, "config": "p/ci"}},
	}}
	sels := resolveScanners(saga.Model{}, comp, "sast", []string{"semgrep"})
	if len(sels) != 1 {
		t.Fatalf("want 1 selection, got %d", len(sels))
	}
	want := map[string]any{"config": "p/ci"}
	if !reflect.DeepEqual(map[string]any(sels[0].Config), want) {
		t.Errorf("config = %v, want %v (enabled stripped)", sels[0].Config, want)
	}
}

func TestResolveScannersComponentOverridesProject(t *testing.T) {
	// Component keys deep-merge over project keys.
	model := saga.Model{Config: saga.Config{Controllers: map[string]saga.ControllerSettings{
		"sast": {"semgrep": map[string]any{"config": "p/default", "extra": "keep"}},
	}}}
	comp := &saga.Component{Controllers: map[string]saga.ControllerSettings{
		"sast": {"semgrep": map[string]any{"config": "p/override"}},
	}}
	sels := resolveScanners(model, comp, "sast", []string{"semgrep"})
	got := map[string]any(sels[0].Config)
	want := map[string]any{"config": "p/override", "extra": "keep"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("merged config = %v, want %v", got, want)
	}
}

func TestResolveScannersProjectOnly(t *testing.T) {
	// A nil component still resolves project-level blocks.
	model := saga.Model{Config: saga.Config{Controllers: map[string]saga.ControllerSettings{
		"sast": {"gosec": map[string]any{"enabled": true}},
	}}}
	sels := resolveScanners(model, nil, "sast", []string{"semgrep"})
	if !reflect.DeepEqual(names(sels), []string{"semgrep", "gosec"}) {
		t.Fatalf("names = %v, want [semgrep gosec]", names(sels))
	}
}

func TestControlBlocksSkipsScalars(t *testing.T) {
	// The control's own scalar settings (enabled) are not scanner blocks.
	blocks := controlBlocks(map[string]saga.ControllerSettings{
		"sast": {"enabled": true, "semgrep": map[string]any{"config": "x"}},
	}, "sast")
	if _, ok := blocks["enabled"]; ok {
		t.Error("enabled scalar should not be a scanner block")
	}
	if _, ok := blocks["semgrep"]; !ok {
		t.Error("semgrep block missing")
	}
}

func TestDeepMerge(t *testing.T) {
	dst := map[string]any{"a": 1, "nested": map[string]any{"x": 1, "y": 2}}
	src := map[string]any{"b": 2, "nested": map[string]any{"y": 3, "z": 4}}
	got := deepMerge(dst, src)
	want := map[string]any{"a": 1, "b": 2, "nested": map[string]any{"x": 1, "y": 3, "z": 4}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("deepMerge = %v, want %v", got, want)
	}
	// Inputs are not mutated.
	if len(dst) != 2 || dst["nested"].(map[string]any)["y"] != 2 {
		t.Error("deepMerge mutated dst")
	}
}

func TestDeepMergeScalarOverMap(t *testing.T) {
	// A scalar in src replaces a map in dst (no merge across kinds).
	got := deepMerge(map[string]any{"k": map[string]any{"a": 1}}, map[string]any{"k": "scalar"})
	if got["k"] != "scalar" {
		t.Errorf("k = %v, want scalar", got["k"])
	}
}

func TestEnabledFlag(t *testing.T) {
	if _, ok := enabledFlag(map[string]any{}); ok {
		t.Error("absent enabled should report unset")
	}
	if v, ok := enabledFlag(map[string]any{"enabled": true}); !ok || !v {
		t.Error("enabled:true should report (true, true)")
	}
	if v, ok := enabledFlag(map[string]any{"enabled": false}); !ok || v {
		t.Error("enabled:false should report (false, true)")
	}
	if _, ok := enabledFlag(map[string]any{"enabled": "yes"}); ok {
		t.Error("non-bool enabled should report unset")
	}
}

// TestConfigKeysRoundTrip: the inverse map turns a descriptor's key back into a scanner name, so
// a mapping that does not survive the trip selects the wrong scanner or none — and selecting none
// is silent, producing a scan that ran one fewer scanner and said nothing about it.
func TestConfigKeysRoundTrip(t *testing.T) {
	t.Parallel()

	for name, key := range scannerConfigKey {
		got, ok := scannerNameFor(key)
		if !ok || got != name {
			t.Errorf("scanner %q is configured as %q, which resolves back to %q (ok=%v)",
				name, key, got, ok)
		}
		if strings.Contains(key, "-") {
			t.Errorf("scanner %q maps to %q, which is not camelCase", name, key)
		}
	}
}

// TestAHyphenatedNameIsNotAcceptedAsAKey. Both spellings resolving would make the descriptor
// convention advisory, and a reader copying a scanner name out of a report would get a block that
// works here and fails review everywhere else.
func TestAHyphenatedNameIsNotAcceptedAsAKey(t *testing.T) {
	t.Parallel()

	for name := range scannerConfigKey {
		if _, ok := scannerNameFor(name); ok {
			t.Errorf("the hyphenated name %q was accepted as a descriptor key", name)
		}
	}
}
