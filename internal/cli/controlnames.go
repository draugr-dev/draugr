package cli

import (
	"fmt"
	"strings"

	"github.com/draugr-dev/draugr/internal/controllers"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// checkControlNames rejects a descriptor that names a control this build cannot run.
//
// Fatal rather than reported. A control name is written because someone decided a check should
// happen or a threshold should differ; if the name is wrong, the decision is not being applied
// and the run goes green anyway. That is a descriptor claiming something it is not doing, and it
// survives review because it looks exactly like a descriptor that works.
//
// Checked against the **registry**, not a fixed list. "Unknown" therefore means *this binary
// cannot run it* — which stays the right question if controls ever arrive from plugins, because
// a descriptor asking for a control the runner does not have should fail there too. Skipping it
// silently would be the green tick that means nothing.
func checkControlNames(reg *engine.Registry, model *saga.Model) error {
	known := map[string]bool{}
	for _, c := range reg.Controllers() {
		known[c.Info().Name] = true
	}

	// Ordered so the message is stable between runs, and grouped so a descriptor with several
	// mistakes reports all of them rather than one per re-run.
	var problems []string
	// Whether any problem was about what a block says rather than what it names, which decides
	// where the closing line sends the reader: the option list, or the control list.
	optionProblem := false
	report := func(where, name string) {
		if name == "" || known[name] {
			return
		}
		msg := fmt.Sprintf("%s: %q is not a control this build of Draugr provides", where, name)
		if near := nearestName(name, known); near != "" {
			msg += fmt.Sprintf(" — did you mean %q?", near)
		}
		problems = append(problems, msg)
	}

	// Which scanners serve each control, by the key a descriptor writes them under.
	keysFor := map[string]map[string]bool{}
	scannerForKey := map[string]map[string]plugin.ScannerInfo{}
	for _, sc := range reg.Scanners() {
		info := sc.Info()
		for _, c := range info.Controls {
			if keysFor[c] == nil {
				keysFor[c] = map[string]bool{}
				scannerForKey[c] = map[string]plugin.ScannerInfo{}
			}
			key := controllers.ScannerConfigKey(info.Name)
			keysFor[c][key] = true
			scannerForKey[c][key] = info
		}
	}

	// A key under a control that names no scanner is ignored today, which is how a descriptor
	// disabling a scanner runs it anyway. Checked here rather than in pkg/saga for the same
	// reason control names are: only the registry knows what exists.
	reportScanners := func(where, control string, settings saga.ControllerSettings) {
		if !known[control] {
			return // the control itself is already reported; its keys would be noise
		}
		for _, key := range sortedKeys(settings) {
			if key == "enabled" || keysFor[control][key] {
				continue
			}
			// A scanner block is a mapping; a scalar is a control-level option and not this
			// check's business. YAML decodes the nested mapping as saga.ControllerSettings
			// rather than a bare map, so both shapes are accepted — asserting only the bare one
			// is why the first version of this check silently matched nothing.
			switch settings[key].(type) {
			case saga.ControllerSettings, map[string]any:
			default:
				continue
			}
			problems = append(problems, fmt.Sprintf(
				"%s.%s: %q is not a scanner of the %q control (it has %s)",
				where, control, key, control, list(sortedKeys(keysFor[control]))))
		}
		// And what the block says, not only whose block it is. The engine checks this again when
		// it plans the run, but by then the descriptor has been accepted by `draugr validate`,
		// merged, and is failing in somebody's pipeline. The whole point of a validate step is
		// that it is the cheap place to find out.
		for _, key := range sortedKeys(settings) {
			scanner, ok := scannerForKey[control][key]
			if !ok {
				continue // already reported above, or the reserved `enabled` flag
			}
			block, ok := blockOf(settings[key])
			if !ok {
				continue
			}
			cfg := plugin.Config{}
			for k, v := range block {
				if k != "enabled" {
					cfg[k] = v
				}
			}
			if err := plugin.ValidateConfig(scanner.ConfigSchema, cfg); err != nil {
				problems = append(problems, fmt.Sprintf("%s.%s.%s: %v", where, control, key, err))
				optionProblem = true
			}
		}
	}

	for _, name := range sortedKeys(model.Config.Controllers) {
		report("config.controllers", name)
		reportScanners("config.controllers", name, model.Config.Controllers[name])
	}
	if g := model.Config.Gate; g != nil {
		for _, name := range sortedKeys(g.Controls) {
			report("config.gate.controls", name)
		}
	}
	for i := range model.Components {
		c := &model.Components[i]
		where := fmt.Sprintf("components[%q].controllers", c.Name)
		for _, name := range sortedKeys(c.Controllers) {
			report(where, name)
			reportScanners(where, name, c.Controllers[name])
		}
	}

	if len(problems) == 0 {
		return nil
	}
	hint := "run `draugr controls` to see what this build provides"
	if optionProblem {
		hint = "run `draugr controls --options` to see what each scanner accepts"
	}
	return fmt.Errorf("%s\n\n%s", strings.Join(problems, "\n"), hint)
}

// nearestName returns the known name closest to name, or "" when nothing is close enough.
//
// The suggestion is most of the value: "iaac is not a control" leaves someone scanning a list,
// and "did you mean iac?" ends it. The threshold keeps it honest — a wild guess beside an error
// is worse than no guess, because it sends the reader somewhere wrong.
//
// Not specific to controls: component names are matched the same way, and a typo costs the reader
// the same either way.
func nearestName(name string, known map[string]bool) string {
	best, bestDist := "", 0
	for candidate := range known {
		d := editDistance(strings.ToLower(name), candidate)
		// At most a third of the name wrong, and never more than three edits: enough for a typo,
		// not enough to match something else entirely.
		limit := min(len(candidate)/3+1, 3)
		if d > limit {
			continue
		}
		if best == "" || d < bestDist || (d == bestDist && candidate < best) {
			best, bestDist = candidate, d
		}
	}
	return best
}

// list renders names for an error message: "a, b or c".
func list(names []string) string {
	switch len(names) {
	case 0:
		return "none"
	case 1:
		return names[0]
	}
	return strings.Join(names[:len(names)-1], ", ") + " or " + names[len(names)-1]
}

// controlNames lists the controls this build can run, which is what a scope is validated against.
func controlNames(reg *engine.Registry) []string {
	ctrls := reg.Controllers()
	out := make([]string, 0, len(ctrls))
	for _, c := range ctrls {
		out = append(out, c.Info().Name)
	}
	return out
}

// blockOf reads a scanner block whichever shape the decoder produced. YAML decodes a nested
// mapping under a control as saga.ControllerSettings rather than a bare map, so both are
// accepted; anything else is a control-level scalar and not a scanner block.
func blockOf(v any) (map[string]any, bool) {
	switch m := v.(type) {
	case saga.ControllerSettings:
		return m, true
	case map[string]any:
		return m, true
	}
	return nil, false
}
