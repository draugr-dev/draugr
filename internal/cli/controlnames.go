package cli

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/draugr-dev/draugr/internal/controllers"
	"github.com/draugr-dev/draugr/internal/suggest"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// controlChecker holds control settings to what this build can run, wherever they were written: a
// descriptor's config.controls, a component's controls, or draugr.config.yaml's controls. One
// checker, so a misspelled control or scanner reads the same in each and none of them is the place
// a mistake slips through.
type controlChecker struct {
	known map[string]bool
	// The settings each control takes itself, as distinct from the ones its scanners take. A key
	// that is one of these is a setting; a key that is neither this nor a scanner is a mistake,
	// whatever shape its value has.
	optionsFor map[string]map[string]bool
	// The schema behind those names, so what a setting *says* can be checked as well as whether
	// it exists. Held separately because the name list is consulted on every key and the schema
	// only on the ones that turn out to be settings.
	optionSchemaFor map[string]json.RawMessage
	// Which scanners serve each control, by the key a descriptor writes them under.
	keysFor       map[string]map[string]bool
	scannerForKey map[string]map[string]plugin.ScannerInfo
	// Reachability analyzers, by the key a descriptor would write them under. Deliberately kept
	// out of keysFor: they serve the control, but they are enabled by config.reachability and
	// naming one in a scanner block has to be an error rather than a second way to say it.
	analyzerKeys map[string]string

	// Ordered so the message is stable between runs, and grouped so a descriptor with several
	// mistakes reports all of them rather than one per re-run.
	problems []string
	// Whether any problem was about what a block says rather than what it names, which decides
	// where the closing line sends the reader: the option list, or the control list.
	optionProblem bool
}

func newControlChecker(reg *engine.Registry) *controlChecker {
	ck := &controlChecker{
		known:           map[string]bool{},
		optionsFor:      map[string]map[string]bool{},
		optionSchemaFor: map[string]json.RawMessage{},
		keysFor:         map[string]map[string]bool{},
		scannerForKey:   map[string]map[string]plugin.ScannerInfo{},
		analyzerKeys:    map[string]string{},
	}
	for _, c := range reg.Controllers() {
		info := c.Info()
		ck.known[info.Name] = true
		if len(info.OptionSchema) > 0 {
			ck.optionSchemaFor[info.Name] = info.OptionSchema
		}
		for _, opt := range plugin.Options(info.OptionSchema) {
			if ck.optionsFor[info.Name] == nil {
				ck.optionsFor[info.Name] = map[string]bool{}
			}
			ck.optionsFor[info.Name][opt.Name] = true
		}
	}
	for _, sc := range reg.Scanners() {
		info := sc.Info()
		key := controllers.ScannerConfigKey(info.Name)
		if info.Reachability {
			ck.analyzerKeys[key] = info.Name
			continue
		}
		for _, c := range info.Controls {
			if ck.keysFor[c] == nil {
				ck.keysFor[c] = map[string]bool{}
				ck.scannerForKey[c] = map[string]plugin.ScannerInfo{}
			}
			ck.keysFor[c][key] = true
			ck.scannerForKey[c][key] = info
		}
	}
	return ck
}

// name reports a control name this build does not provide.
func (ck *controlChecker) name(where, name string) {
	if name == "" || ck.known[name] {
		return
	}
	msg := fmt.Sprintf("%s: %q is not a control this build of Draugr provides", where, name)
	if now, ok := saga.RenamedControls[name]; ok {
		msg += fmt.Sprintf(", it is %q now", now)
	} else if near := nearestName(name, ck.known); near != "" {
		msg += fmt.Sprintf(", did you mean %q?", near)
	}
	ck.problems = append(ck.problems, msg)
}

// settings reports what is wrong under one control's block: a key that names no scanner and no
// setting, a scanner configured with a value rather than a block, and options a schema refuses.
//
// A key under a control that names no scanner is ignored by the run, which is how a block
// disabling a scanner runs it anyway. Checked here rather than in pkg/saga for the same reason
// control names are: only the registry knows what exists.
func (ck *controlChecker) settings(where, control string, settings saga.ControllerSettings) {
	if !ck.known[control] {
		return // the control itself is already reported; its keys would be noise
	}
	for _, key := range sortedKeys(settings) {
		if key == "enabled" || ck.keysFor[control][key] || ck.optionsFor[control][key] {
			continue
		}
		// Every remaining key is unaccounted for, whatever its value looks like. Shape is not a
		// test: a list under a control is not a control-level option merely because it is not a
		// mapping, and `scanners: [gosec]` has to be refused rather than read as one. Controls
		// declare the settings they take, so no guess from shape is needed.
		if analyzer, ok := ck.analyzerKeys[key]; ok {
			// Names something real, in the wrong place. Saying so beats "not a scanner",
			// which sends the reader looking for a typo they did not make.
			ck.problems = append(ck.problems, fmt.Sprintf(
				"%s.%s: %q decides reachability and is enabled under config.reachability, "+
					"not as a scanner. Write `config.reachability.analyzers: [%s]`",
				where, control, key, analyzer))
			continue
		}
		if key == "scanners" {
			// A real key until 0.29.0, and still the natural guess, so it is worth answering
			// with the shape rather than with "not a scanner", which reads as a typo the
			// reader did not make.
			ck.problems = append(ck.problems, fmt.Sprintf(
				"%s.%s: scanners are enabled under their own name, not in a list. "+
					"Write `%s.%s.<scanner>.enabled: true` (it has %s)",
				where, control, where, control, list(sortedKeys(ck.keysFor[control]))))
			continue
		}
		msg := fmt.Sprintf("%s.%s: %q is not a scanner of the %q control (it has %s)",
			where, control, key, control, list(sortedKeys(ck.keysFor[control])))
		if opts := sortedKeys(ck.optionsFor[control]); len(opts) > 0 {
			msg += fmt.Sprintf(", nor one of its settings (%s)", list(opts))
		}
		// A scanner's own name where its key is camelCase, `trivy-fs` for `trivyFs`, is the likeliest
		// mistake of all, and ScannerConfigKey is the rule that maps one to the other.
		if k := controllers.ScannerConfigKey(key); k != key && ck.keysFor[control][k] {
			msg += fmt.Sprintf(", did you mean %q?", k)
		} else if near := nearestName(key, ck.keysFor[control]); near != "" {
			msg += fmt.Sprintf(", did you mean %q?", near)
		}
		ck.problems = append(ck.problems, msg)
	}
	// And what the block says, not only whose block it is. The engine checks this again when
	// it plans the run, but by then the descriptor has been accepted by `draugr validate`,
	// merged, and is failing in somebody's pipeline. The whole point of a validate step is
	// that it is the cheap place to find out.
	for _, key := range sortedKeys(settings) {
		scanner, ok := ck.scannerForKey[control][key]
		if !ok {
			continue // already reported above, or the reserved `enabled` flag
		}
		block, ok := blockOf(settings[key])
		if !ok {
			// A scanner is configured by a block, and only a block is read. `gosec: true`
			// reads as "enable gosec" and enables nothing, which is the same silence as a
			// misspelled key arriving by a different route.
			ck.problems = append(ck.problems, fmt.Sprintf(
				"%s.%s.%s: a scanner is configured with a block, not a value. "+
					"Write `%s: { enabled: true }`", where, control, key, key))
			continue
		}
		cfg := plugin.Config{}
		for k, v := range block {
			if k != "enabled" {
				cfg[k] = v
			}
		}
		if err := plugin.ValidateConfig(scanner.ConfigSchema, cfg); err != nil {
			ck.problems = append(ck.problems, fmt.Sprintf("%s.%s.%s: %v", where, control, key, err))
			ck.optionProblem = true
		}
	}
	// And the control's own settings, held to the same standard as a scanner's.
	//
	// A name that exists is not a value that works. `deny: "AGPL-3.0-only"` names a real
	// setting, reads as a policy, and yields an empty list, so the gate the descriptor was
	// written to apply is not applied and the run is green. A control's settings are policy
	// more often than a scanner's are, which makes a silent one worse here than anywhere else.
	schema, has := ck.optionSchemaFor[control]
	if !has {
		return
	}
	cfg := plugin.Config{}
	for _, key := range sortedKeys(settings) {
		if ck.optionsFor[control][key] {
			cfg[key] = settings[key]
		}
	}
	if len(cfg) == 0 {
		return
	}
	if err := plugin.ValidateConfig(schema, cfg); err != nil {
		ck.problems = append(ck.problems, fmt.Sprintf("%s.%s: %v", where, control, err))
		ck.optionProblem = true
	}
}

// controls checks every control in a map of control settings, under where.
func (ck *controlChecker) controls(where string, controls map[string]saga.ControllerSettings) {
	for _, name := range sortedKeys(controls) {
		ck.name(where, name)
		ck.settings(where, name, controls[name])
	}
}

// hint is the line that closes a report of these problems.
func (ck *controlChecker) hint() string {
	if ck.optionProblem {
		return "run `draugr controls --options` to see what each scanner accepts"
	}
	return "run `draugr controls` to see what this build provides"
}

// checkControlNames rejects a descriptor that names a control this build cannot run.
//
// Fatal rather than reported. A control name is written because someone decided a check should
// happen or a threshold should differ; if the name is wrong, the decision is not being applied
// and the run goes green anyway. That is a descriptor claiming something it is not doing, and it
// survives review because it looks exactly like a descriptor that works.
//
// Checked against the **registry**, not a fixed list. "Unknown" therefore means *this binary
// cannot run it*. Which stays the right question if controls ever arrive from plugins, because a
// descriptor asking for a control the runner does not have should fail there too. Skipping it
// silently would be the green tick that means nothing.
func checkControlNames(reg *engine.Registry, model *saga.Model) error {
	ck := newControlChecker(reg)
	ck.controls("config.controls", model.Config.Controls)
	// What a control's settings mean together, which only the control knows. A schema says whether
	// a signer is well formed; whether an image names one that was declared is a different
	// question, and the answer to it decides whether anything gets checked at all.
	for _, c := range reg.Controllers() {
		v, ok := c.(plugin.Validator)
		if !ok {
			continue
		}
		// Reported as the control wrote it. Each of these already names where in the descriptor
		// it is, and a control's own prefix on top of that reads as two locations for one mistake.
		for _, err := range v.Validate(*model) {
			ck.problems = append(ck.problems, err.Error())
			ck.optionProblem = true
		}
	}
	// An analyzer this build cannot run is the same failure as a control it cannot run: the
	// descriptor says findings will be ranked by reachability, and they silently are not.
	if r := model.Config.Reachability; r != nil {
		analyzers := map[string]bool{}
		for _, name := range ck.analyzerKeys {
			analyzers[name] = true
		}
		for _, name := range r.Analyzers {
			if analyzers[name] {
				continue
			}
			msg := fmt.Sprintf("config.reachability.analyzers: %q is not a reachability analyzer "+
				"this build of Draugr provides", name)
			if near := nearestName(name, analyzers); near != "" {
				msg += fmt.Sprintf(", did you mean %q?", near)
			} else if len(analyzers) > 0 {
				msg += fmt.Sprintf(" (it has %s)", list(sortedKeys(analyzers)))
			}
			ck.problems = append(ck.problems, msg)
		}
	}
	if g := model.Config.Gate; g != nil {
		for _, name := range sortedKeys(g.Controls) {
			ck.name("config.gate.controls", name)
		}
	}
	for i, p := range model.Config.Publishers {
		if p.Select == nil {
			continue
		}
		for _, name := range p.Select.Controls {
			ck.name(fmt.Sprintf("config.publishers[%d].select.controls", i), name)
		}
	}
	for i := range model.Components {
		c := &model.Components[i]
		ck.controls(fmt.Sprintf("components[%q].controls", c.Name), c.Controls)
		// An import names the control its findings go to; a misspelled one would read the file into
		// nothing and the run would pass without it.
		for j, imp := range c.Imports {
			ck.name(fmt.Sprintf("components[%q].imports[%d].control", c.Name, j), imp.Control)
		}
	}

	if len(ck.problems) == 0 {
		return nil
	}
	return fmt.Errorf("%s\n\n%s", strings.Join(ck.problems, "\n"), ck.hint())
}

// nearestName returns the known name closest to name, or "" when nothing is close enough.
//
// Not specific to controls: component names are matched the same way, and a typo costs the reader
// the same either way. The rule itself is suggest.Nearest, which draugr.config.yaml shares.
func nearestName(name string, known map[string]bool) string {
	return suggest.Nearest(name, known)
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
