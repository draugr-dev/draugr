package config

import (
	"maps"
	"slices"
	"strings"

	"github.com/draugr-dev/draugr/pkg/saga"
)

// Supplied is a file whose control defaults reached a descriptor, and the settings that did.
type Supplied struct {
	Source Source
	// Settings are dotted from the control's name, as `secrets.gitleaks.history`, in order.
	Settings []string
}

// MergeControls lays a descriptor's controls over the control defaults in effect, and names the
// file behind each default that reached the result. controls is the descriptor's config.controls,
// and components its components, read for the controls they turn on.
//
// A block supplies settings to a control the descriptor turns on, at the top level or on a
// component, and turns a control on itself only with `enabled: true`. A machine-wide scanner option
// would otherwise add its control to every scan on the machine, and the descriptor is what decides
// which controls run. For a control only components turn on, the defaults are laid under an
// `enabled: false` top-level block, so the components that turn it on inherit them and the rest
// stay off, as a descriptor written that way behaves.
//
// The merge and the attribution are one function so they cannot disagree about which value won. A
// default reaches the result where the descriptor sets nothing at that setting or above it, and it
// is the most specific file's, the rule Resolve applies between files. A default the descriptor
// overrode, or one for a control nothing turns on, is attributed to nobody: it changed nothing the
// descriptor's digest is taken over. Files are returned least specific first, and a file that
// supplied nothing is left out.
func (r Resolved) MergeControls(controls map[string]saga.ControllerSettings, components []saga.Component) (map[string]saga.ControllerSettings, []Supplied) {
	if len(r.File.Controls) == 0 {
		return controls, nil
	}
	merged := make(map[string]saga.ControllerSettings, len(controls)+len(r.File.Controls))
	maps.Copy(merged, controls)
	reached := map[string]bool{}
	for control, defaults := range r.File.Controls {
		under, ok := underneath(control, defaults, controls, components)
		if !ok {
			continue
		}
		reached[control] = true
		merged[control] = DeepMerge(defaults, under)
	}

	settings := make([][]string, len(r.Sources))
	for _, path := range leaves(nil, r.File.Controls) {
		if !reached[path[0]] || setAt(controls, path) {
			continue
		}
		owner := -1
		for i, s := range r.Sources {
			if holds(s.File.Controls, path) {
				owner = i
			}
		}
		if owner >= 0 {
			settings[owner] = append(settings[owner], strings.Join(path, "."))
		}
	}
	var out []Supplied
	for i, s := range r.Sources {
		if len(settings[i]) == 0 {
			continue
		}
		slices.Sort(settings[i])
		out = append(out, Supplied{Source: s, Settings: settings[i]})
	}
	return merged, out
}

// underneath is what a control's defaults are merged under, and whether they reach the descriptor
// at all: the descriptor's own block where it has one, an `enabled: false` block where only
// components turn the control on, and nothing where the defaults turn it on themselves.
func underneath(control string, defaults saga.ControllerSettings, controls map[string]saga.ControllerSettings,
	components []saga.Component) (saga.ControllerSettings, bool) {
	project := saga.Config{Controls: controls}
	if on, _ := defaults["enabled"].(bool); on {
		return controls[control], true
	}
	if project.ControllerEnabled(control) {
		return controls[control], true
	}
	for _, comp := range components {
		if _, own := comp.Controls[control]; own && comp.ControllerEnabled(control, project) {
			if block, declared := controls[control]; declared {
				return block, true
			}
			return saga.ControllerSettings{"enabled": false}, true
		}
	}
	return nil, false
}

// leaves lists the path to every value under controls that is not itself a mapping with keys, the
// unit a default is merged at. An empty mapping is a leaf, because it still reaches a descriptor
// that sets nothing there.
func leaves[M ~map[string]V, V any](prefix []string, m M) [][]string {
	var out [][]string
	for _, k := range slices.Sorted(maps.Keys(m)) {
		path := append(slices.Clone(prefix), k)
		if sub, ok := asSettings(any(m[k])); ok && len(sub) > 0 {
			out = append(out, leaves(path, sub)...)
			continue
		}
		out = append(out, path)
	}
	return out
}

// setAt reports whether the descriptor answers for path: a value at path itself, or a value that is
// not a mapping somewhere above it, which DeepMerge keeps whole over the default.
func setAt(descriptor map[string]saga.ControllerSettings, path []string) bool {
	cur := asTree(descriptor)
	for _, seg := range path {
		m, ok := asSettings(cur)
		if !ok {
			return true
		}
		v, present := m[seg]
		if !present {
			return false
		}
		cur = v
	}
	return true
}

// holds reports whether a file's controls carry a value at exactly path.
func holds(controls map[string]saga.ControllerSettings, path []string) bool {
	cur := asTree(controls)
	for _, seg := range path {
		m, ok := asSettings(cur)
		if !ok {
			return false
		}
		v, present := m[seg]
		if !present {
			return false
		}
		cur = v
	}
	return true
}

// asTree is a section of controls as one mapping, so a path is walked from the control's name down
// with one rule at every level.
func asTree(controls map[string]saga.ControllerSettings) any {
	out := make(map[string]any, len(controls))
	for k, v := range controls {
		out[k] = v
	}
	return out
}
