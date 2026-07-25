package controllers

import (
	"maps"
	"sort"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// enabledKey is the reserved per-scanner flag under controllers.<control>.<scanner>. It gates
// the scanner; every other key in the block is that scanner's config.
const enabledKey = "enabled"

// scannerSelection is one resolved scanner to run for a control: its name and merged config
// (the scanner's block minus the reserved "enabled" key).
type scannerSelection struct {
	Name   string
	Config plugin.Config
}

// resolveScanners resolves which scanners run for a control and their config from the Saga's
// controllers.<control>.<scanner> blocks. Each scanner is a named block holding an optional
// "enabled" flag plus its config, e.g.:
//
//	controllers:
//	  sast:
//	    semgrep: { config: p/owasp-top-ten }   # a default scanner: runs unless enabled:false
//	    gosec:   { enabled: true }             # a non-default scanner: runs only when enabled:true
//
// Component blocks deep-merge over project blocks (component keys win). A default scanner runs
// unless its block sets enabled:false; a non-default scanner runs only when its block sets
// enabled:true. The result is deterministic: default scanners first (in the given order), then
// any extra enabled scanners sorted by name.
func resolveScanners(model saga.Model, comp *saga.Component, control string, defaults []string) []scannerSelection {
	merged := controlBlocks(model.Config.Controllers, control)
	if comp != nil {
		for name, blk := range controlBlocks(comp.Controllers, control) {
			merged[name] = deepMerge(merged[name], blk)
		}
	}

	defaultSet := make(map[string]bool, len(defaults))
	for _, d := range defaults {
		defaultSet[d] = true
	}

	var out []scannerSelection
	// Default scanners first, in the given order; included unless explicitly disabled.
	for _, d := range defaults {
		if flag, ok := enabledFlag(merged[d]); ok && !flag {
			continue
		}
		out = append(out, scannerSelection{Name: d, Config: configFromBlock(merged[d])})
	}
	// Extra (non-default) scanners, sorted; included only when explicitly enabled.
	extra := make([]string, 0, len(merged))
	for name, blk := range merged {
		if defaultSet[name] {
			continue
		}
		if flag, ok := enabledFlag(blk); ok && flag {
			extra = append(extra, name)
		}
	}
	sort.Strings(extra)
	for _, name := range extra {
		out = append(out, scannerSelection{Name: name, Config: configFromBlock(merged[name])})
	}
	return out
}

// controlBlocks returns the per-scanner blocks under controllers.<control>: each key whose
// value is a map (i.e. a scanner block), keyed by scanner name. The control's own scalar
// settings (e.g. "enabled") are skipped. Always returns a non-nil map.
func controlBlocks(controllers map[string]saga.ControllerSettings, control string) map[string]map[string]any {
	blocks := map[string]map[string]any{}
	for name, v := range controllers[control] {
		if blk, ok := asMap(v); ok {
			blocks[name] = blk
		}
	}
	return blocks
}

// asMap normalizes a decoded config value to map[string]any. YAML (yaml.v3) decodes nested
// mappings into the enclosing named map type (saga.ControllerSettings), which a plain
// map[string]any type assertion would miss; this accepts both.
func asMap(v any) (map[string]any, bool) {
	switch m := v.(type) {
	case map[string]any:
		return m, true
	case saga.ControllerSettings:
		return map[string]any(m), true
	default:
		return nil, false
	}
}

// enabledFlag reads a block's "enabled" flag: (value, true) when present and boolean, else
// (false, false) so callers can distinguish "unset" from "false".
func enabledFlag(block map[string]any) (bool, bool) {
	v, ok := block[enabledKey]
	if !ok {
		return false, false
	}
	b, ok := v.(bool)
	return b, ok
}

// configFromBlock returns a scanner's config: the block without the reserved "enabled" key.
// Returns nil when there is no config, so cache keys and validation see an empty config.
func configFromBlock(block map[string]any) plugin.Config {
	cfg := plugin.Config{}
	for k, v := range block {
		if k == enabledKey {
			continue
		}
		cfg[k] = v
	}
	if len(cfg) == 0 {
		return nil
	}
	return cfg
}

// deepMerge returns dst with src merged in: src keys win, and nested maps merge recursively.
// Neither input is mutated.
func deepMerge(dst, src map[string]any) map[string]any {
	out := make(map[string]any, len(dst)+len(src))
	maps.Copy(out, dst)
	for k, v := range src {
		if dm, ok := asMap(out[k]); ok {
			if sm, ok := asMap(v); ok {
				out[k] = deepMerge(dm, sm)
				continue
			}
		}
		out[k] = v
	}
	return out
}
