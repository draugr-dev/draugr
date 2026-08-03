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

	// Blocks are keyed by the descriptor's camelCase key; defaults are given as scanner names.
	defaultKeys := make(map[string]bool, len(defaults))
	for _, d := range defaults {
		defaultKeys[configKeyFor(d)] = true
	}

	var out []scannerSelection
	// Default scanners first, in the given order; included unless explicitly disabled.
	for _, d := range defaults {
		blk := merged[configKeyFor(d)]
		if flag, ok := enabledFlag(blk); ok && !flag {
			continue
		}
		out = append(out, scannerSelection{Name: d, Config: configFromBlock(blk)})
	}
	// Extra (non-default) scanners, sorted; included only when explicitly enabled.
	extra := make([]string, 0, len(merged))
	for key, blk := range merged {
		if defaultKeys[key] {
			continue
		}
		name, ok := scannerNameFor(key)
		if !ok {
			// A hyphenated key. Validate() rejects these at load, so reaching here means the
			// descriptor bypassed validation; skipping silently is what that guard exists to
			// prevent, but erroring is not this function's contract.
			continue
		}
		if flag, enabled := enabledFlag(blk); enabled && flag {
			extra = append(extra, name)
		}
	}
	sort.Strings(extra)
	for _, name := range extra {
		out = append(out, scannerSelection{Name: name, Config: configFromBlock(merged[configKeyFor(name)])})
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

// scannerConfigKey is the camelCase key a scanner is configured under in the descriptor.
//
// Scanner names are identifiers that appear in reports, `draugr controls` and rule output, and
// several of them are hyphenated. Descriptor fields are camelCase, without exception — so the
// two diverge for any scanner whose name has more than one word, and the descriptor keeps its
// own convention rather than borrowing the report's.
//
// Single-word scanners (semgrep, gosec, trivy, nuclei) need no entry: key and name are equal.
var scannerConfigKey = map[string]string{
	"kube-bench":          "kubeBench",
	"kube-bench-job":      "kubeBenchJob",
	"draugr-k8s-policies": "draugrK8sPolicies",
	"draugr-tls":          "draugrTls",
	"draugr-headers":      "draugrHeaders",
	"trivy-fs":            "trivyFs",
	"trivy-config":        "trivyConfig",
	"trivy-license":       "trivyLicense",
}

// scannerForConfigKey inverts scannerConfigKey.
var scannerForConfigKey = func() map[string]string {
	m := make(map[string]string, len(scannerConfigKey))
	for name, key := range scannerConfigKey {
		m[key] = name
	}
	return m
}()

// configKeyFor returns the descriptor key a scanner is configured under.
func configKeyFor(scanner string) string {
	if key, ok := scannerConfigKey[scanner]; ok {
		return key
	}
	return scanner
}

// scannerNameFor resolves a descriptor key to a scanner name, reporting whether it is known.
//
// A hyphenated key is rejected rather than quietly accepted. The failure it guards against is
// silent: an unrecognized block is simply not selected, so `kube-bench-job: { enabled: true }`
// would produce a scan that ran one fewer scanner and said nothing about it. Someone asking for
// the node sections would get a pass on a benchmark half of which never ran.
func scannerNameFor(key string) (string, bool) {
	if name, ok := scannerForConfigKey[key]; ok {
		return name, true
	}
	if _, hyphenated := scannerConfigKey[key]; hyphenated {
		return "", false
	}
	return key, true
}
