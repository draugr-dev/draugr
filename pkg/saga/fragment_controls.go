package saga

import (
	"fmt"
	"maps"
	"slices"
)

// FragmentControlOptions is what a `fragments:` entry may set under `config.controls`, by control
// and then by option.
//
// # The test an entry has to pass
//
// The rule a fragment exists under is stated on FragmentRef: including a file cannot quietly lower
// the gate or switch a control off, so the worst a `fragments:` entry can do is add findings, or
// add suppressions that are individually attributed and counted in the report. An option belongs
// here when all four of these hold, and the argument goes in the pull request that adds it:
//
//  1. It unions. Two sources both contribute and neither loses anything, so a fragment adds to the
//     descriptor rather than answering over it.
//  2. It cannot switch a control off, change the gate, or change what is trusted or permitted.
//     Those decide whether a run means anything.
//  3. Where it can loosen, the loosening is attributed to the file it came from and reaches the
//     report. Config.ControlSources is that attribution; an exclusion's Source is the same idea.
//  4. Where the setting is ordered, the merge keeps the stricter value and the command says the
//     fragment's did not apply. NarrowsScope is the existing shape of that answer.
//
// # Why a list rather than a property of the control
//
// The default is that a control carries nothing, and a control added without a thought here gets
// that default. Forgetting means a fragment cannot configure a new control, which somebody
// notices and asks for; the other arrangement fails the other way.
//
// Every option here is a sequence, and merging appends. An option needing different merge
// semantics declares them when it arrives, rather than this map implying it already has them.
var fragmentControlOptions = map[string]map[string]bool{
	// Who signs what a product runs is the policy an organization writes once and includes
	// everywhere, and it unions already: a component's signers are added to the project's rather
	// than replacing them, so one signer cannot stop the rest of the inventory being checked.
	//
	// `trustRoot` is not here, because it decides what is trusted. `unmatched` is not here,
	// because whether an uncovered image is a gap or a fact about the ecosystem is a judgment
	// belonging to whoever answers for the verdict.
	"provenance": {"signers": true},
}

// FragmentControls names the controls a fragment may contribute settings to, in order.
func FragmentControls() []string {
	out := make([]string, 0, len(fragmentControlOptions))
	for name := range fragmentControlOptions {
		out = append(out, name)
	}
	slices.Sort(out)
	return out
}

// FragmentControlOptionsFor names the options a fragment may set for one control, in order. Empty
// for a control a fragment may not configure, which is every control not listed above.
func FragmentControlOptionsFor(control string) []string {
	opts := fragmentControlOptions[control]
	out := make([]string, 0, len(opts))
	for name := range opts {
		out = append(out, name)
	}
	slices.Sort(out)
	return out
}

// validateFragmentControls refuses a control or an option a fragment may not carry.
//
// Named in the error rather than reported as an unknown field: these are real keys of a
// descriptor, so "unknown" would be a lie about why they were refused, and a reader who has just
// copied a working block out of their Saga needs to be told the difference.
func validateFragmentControls(controls map[string]ControllerSettings) []error {
	var errs []error
	for _, name := range slices.Sorted(maps.Keys(controls)) {
		allowed, ok := fragmentControlOptions[name]
		if !ok {
			errs = append(errs, fmt.Errorf("a fragment may not configure `%s`: it adds scope and "+
				"suppressions, and a control's settings stay in the descriptor that names it, "+
				"where a reviewer sees them (a fragment may set %s)",
				name, joinKeyed(FragmentControls())))
			continue
		}
		for _, opt := range slices.Sorted(maps.Keys(controls[name])) {
			if !allowed[opt] {
				errs = append(errs, fmt.Errorf("a fragment may not set `%s.%s`, only %s: the rest "+
					"decide what is trusted and what a finding is worth, which stays with whoever "+
					"answers for the verdict", name, opt,
					joinKeyed(prefixed(name, FragmentControlOptionsFor(name)))))
				continue
			}
			if _, isList := asSequence(controls[name][opt]); !isList {
				errs = append(errs, fmt.Errorf("`%s.%s` in a fragment must be a list: a fragment "+
					"adds to what the descriptor declares, and a single value would answer over it",
					name, opt))
			}
		}
	}
	return errs
}

// mergeFragmentControls appends a fragment's control settings to what the model already carries,
// recording which file each contribution came from.
//
// Appended rather than assigned, including where the descriptor set nothing: a descriptor
// declaring no signers and a fragment declaring three is a descriptor with three, and the report
// has to be able to say where they came from.
func mergeFragmentControls(cfg *Config, frag map[string]ControllerSettings, source string) {
	for _, name := range slices.Sorted(maps.Keys(frag)) {
		for _, opt := range slices.Sorted(maps.Keys(frag[name])) {
			added, ok := asSequence(frag[name][opt])
			if !ok || len(added) == 0 {
				continue
			}
			if cfg.Controls == nil {
				cfg.Controls = map[string]ControllerSettings{}
			}
			if cfg.Controls[name] == nil {
				cfg.Controls[name] = ControllerSettings{}
			}
			existing, _ := asSequence(cfg.Controls[name][opt])
			cfg.Controls[name][opt] = append(append([]any{}, existing...), added...)
			if source == "" {
				continue
			}
			if cfg.ControlSources == nil {
				cfg.ControlSources = map[string][]string{}
			}
			key := name + "." + opt
			if !slices.Contains(cfg.ControlSources[key], source) {
				cfg.ControlSources[key] = append(cfg.ControlSources[key], source)
			}
		}
	}
}

// asSequence reads a settings value as a list, and reports whether it was one. A missing value
// counts, so a control block naming an option and leaving it empty is not an error.
func asSequence(v any) ([]any, bool) {
	switch s := v.(type) {
	case nil:
		return nil, true
	case []any:
		return s, true
	default:
		return nil, false
	}
}

func prefixed(control string, opts []string) []string {
	out := make([]string, 0, len(opts))
	for _, o := range opts {
		out = append(out, control+"."+o)
	}
	return out
}

// joinKeyed renders a list of allowed keys for an error message.
func joinKeyed(keys []string) string {
	switch len(keys) {
	case 0:
		return "nothing"
	case 1:
		return "`" + keys[0] + "`"
	}
	out := ""
	for i, k := range keys {
		switch {
		case i == 0:
			out = "`" + k + "`"
		case i == len(keys)-1:
			out += " and `" + k + "`"
		default:
			out += ", `" + k + "`"
		}
	}
	return out
}

// AppendFragmentControls adds one fragment's control settings to another's, for a caller merging
// fragments before any of them reaches a descriptor.
//
// The same append mergeFragmentControls performs into a Config, against a FragmentConfig. Two
// surveys proposing signers both contribute, which is the rule every option on the list is
// admitted under. No attribution, because neither side is a file yet: a fragment a surveyor built
// in memory has no Source to name.
func AppendFragmentControls(into *FragmentConfig, from map[string]ControllerSettings) {
	for _, name := range slices.Sorted(maps.Keys(from)) {
		for _, opt := range slices.Sorted(maps.Keys(from[name])) {
			added, ok := asSequence(from[name][opt])
			if !ok || len(added) == 0 {
				continue
			}
			if into.Controls == nil {
				into.Controls = map[string]ControllerSettings{}
			}
			if into.Controls[name] == nil {
				into.Controls[name] = ControllerSettings{}
			}
			existing, _ := asSequence(into.Controls[name][opt])
			into.Controls[name][opt] = append(append([]any{}, existing...), added...)
		}
	}
}
