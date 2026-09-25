package engine

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/draugr-dev/draugr/pkg/saga"
)

// Scope narrows a run to named components and controls, without changing the descriptor.
//
// The distinction it exists for: `config.controls` records a decision. This project does not
// need `dast`. And a filter is a view over one run. Editing the first to get the second is how a
// temporary change gets committed, and how a control ends up disabled in main because somebody
// was debugging.
//
// The zero value scans everything, so a caller that never sets one is unaffected. An empty list
// means "no restriction on this axis", not "nothing": `Scope{Components: []string{"app"}}` runs
// every control against one component.
//
// A scoped run is still gated and still produces a verdict. The alternative is answering "is my
// fix good?" with "no verdict", which sends the reader back to a full scan and makes the filter
// useless for the loop it exists for. What a scoped run must never do is look like an unscoped
// one, so the scope travels with the result and into every artifact that result becomes.
type Scope struct {
	Components []string
	Controls   []string
	// Labels, Exposure and Criticality select components by what they are rather than by name.
	//
	// A monorepo is the case they exist for. A team knows the label it files under; it does not
	// know which of two hundred component names carry that label this week, and a list written out
	// by hand goes stale the first time somebody adds one.
	//
	// All three resolve into Components before a run starts, so everything downstream sees a
	// concrete set and nothing else has to learn a second way of being narrowed.
	//
	// Labels are `key=value` over the component's own metadata, which is the organization's
	// vocabulary: Draugr reads no key here and attaches no meaning to one. Exposure and
	// Criticality are Draugr's own, a closed set, so a value that is not one of them is rejected by
	// name rather than left to match nothing.
	//
	// Within a selector the values are alternatives, and across selectors they narrow together:
	// `Labels: ["team=web"], Exposure: ["public"]` is the web team's public components.
	Labels      []string
	Exposure    []saga.Exposure
	Criticality []saga.Criticality
	// SkippedComponents are the declared components this scope leaves out, filled in by Resolve.
	//
	// Carried rather than recomputed because the descriptor is not available everywhere the scope is
	// read. A rendered report knows what ran, not what was declared. Naming them rather than
	// counting them: "10 not scanned" tells a reader they are missing something and not which thing,
	// and the answer is one the run already had.
	SkippedComponents []string
}

// Resolve returns a copy of this scope with the selectors turned into component names and
// SkippedComponents filled in from the descriptor, so everything downstream can say what ran and
// what was left out without needing the descriptor again.
//
// Selecting by label or by classification produces a concrete list here rather than staying a rule
// evaluated later. Two things depend on that and neither would be obvious from the flag: the scope
// a report states is what was actually covered, and the SARIF automation id a run publishes under
// is built from the component list, so two teams scanning one commit stay in separate categories
// instead of replacing each other's alerts.
func (s Scope) Resolve(model saga.Model) Scope {
	out := s
	if s.selects() {
		out.Components = s.selected(model)
	}
	if len(out.Components) == 0 {
		return out
	}
	out.SkippedComponents = nil
	for i := range model.Components {
		if name := model.Components[i].Name; !out.IncludesComponent(name) {
			out.SkippedComponents = append(out.SkippedComponents, name)
		}
	}
	return out
}

// selects reports whether anything narrows by what a component is rather than by its name.
func (s Scope) selects() bool {
	return len(s.Labels) > 0 || len(s.Exposure) > 0 || len(s.Criticality) > 0
}

// selected is the components the selectors match, intersected with any names already given.
func (s Scope) selected(model saga.Model) []string {
	var out []string
	for i := range model.Components {
		c := &model.Components[i]
		if !s.IncludesComponent(c.Name) {
			continue // a name was given as well, and this is not one of them
		}
		if !matchesLabels(c, s.Labels) {
			continue
		}
		if len(s.Exposure) > 0 && !slices.Contains(s.Exposure, c.Exposure) {
			continue
		}
		if len(s.Criticality) > 0 && !slices.Contains(s.Criticality, c.Criticality) {
			continue
		}
		out = append(out, c.Name)
	}
	return out
}

// matchesLabels reports whether a component carries every selector, where several selectors on one
// key are alternatives.
//
// Keys narrow and values widen, which is the convention anybody who has written a label selector
// already knows: `team=web team=api` is either team, and `team=web tier=1` is the web team's
// tier-1 components.
func matchesLabels(c *saga.Component, selectors []string) bool {
	if len(selectors) == 0 {
		return true
	}
	wanted := map[string][]string{}
	for _, sel := range selectors {
		k, v, ok := strings.Cut(sel, "=")
		if !ok {
			return false // rejected by Validate; here it matches nothing rather than everything
		}
		wanted[k] = append(wanted[k], v)
	}
	for k, values := range wanted {
		if !slices.Contains(values, c.Labels[k]) {
			return false
		}
	}
	return true
}

// Empty reports whether this scope restricts nothing, which is the ordinary case.
//
// Read after Resolve, where a selector has become a component list. Before it, a scope that
// selects restricts something even though Components is still empty.
func (s Scope) Empty() bool {
	return len(s.Components) == 0 && len(s.Controls) == 0 && !s.selects()
}

// IncludesComponent reports whether a component is in scope.
//
// Exported because the report has the same question to answer: a component the scope left out
// must be rendered as not scanned rather than as passing, and only this type knows which those
// are.
func (s Scope) IncludesComponent(name string) bool {
	return len(s.Components) == 0 || slices.Contains(s.Components, name)
}

// includesControl reports whether a control is in scope.
func (s Scope) includesControl(name string) bool {
	return len(s.Controls) == 0 || slices.Contains(s.Controls, name)
}

// Validate rejects a scope naming something the descriptor or the registry does not have.
//
// A misspelling is the whole failure this guards: `--components frontnd` matches nothing, scans
// nothing, and passes. The same "we did not look" verdict a filter is otherwise careful not to
// produce, reached by typo. The error lists what is available, because the reader is one
// character away from the answer and should not have to go and find it.
func (s Scope) Validate(model saga.Model, controls []string) error {
	var errs []string
	declared := make([]string, 0, len(model.Components))
	for i := range model.Components {
		declared = append(declared, model.Components[i].Name)
	}
	if bad := missing(s.Components, declared); len(bad) > 0 {
		errs = append(errs, fmt.Sprintf("--components: this descriptor declares no %s (it has: %s)",
			quoteList("component", bad), atMost(sorted(declared), listCap)))
	}
	if bad := missing(s.Controls, controls); len(bad) > 0 {
		errs = append(errs, fmt.Sprintf("--controls: no such %s (run `draugr controls`, this build has: %s)",
			quoteList("control", bad), strings.Join(sorted(controls), ", ")))
	}
	for _, sel := range s.Labels {
		// Both halves required. An empty value would otherwise match a component that declares no
		// labels at all, since a missing key and an empty one read the same from a map, so
		// `--labels team=` would quietly select the components nobody has labeled.
		if k, v, ok := strings.Cut(sel, "="); !ok || k == "" || v == "" {
			errs = append(errs, fmt.Sprintf("--labels: %q is not a selector (want key=value, as the "+
				"descriptor writes them under a component's `labels`)", sel))
		}
	}
	// Draugr's own vocabulary, so a wrong value is answered with the right ones rather than left to
	// match nothing. A label cannot be checked this way: the keys and values are the
	// organization's, and Draugr has no list to check them against.
	if bad := missingEnum(s.Exposure, saga.Exposures); len(bad) > 0 {
		errs = append(errs, fmt.Sprintf("--exposure: no such %s (want one of: %s)",
			quoteList("exposure", bad), strings.Join(stringsOf(saga.Exposures), ", ")))
	}
	if bad := missingEnum(s.Criticality, saga.Criticalities); len(bad) > 0 {
		errs = append(errs, fmt.Sprintf("--criticality: no such %s (want one of: %s)",
			quoteList("criticality", bad), strings.Join(stringsOf(saga.Criticalities), ", ")))
	}
	// A selector that matches nothing scans nothing and passes, which is the verdict this whole
	// type is careful not to produce by accident. Checked after the values themselves, so a typo in
	// a known field is reported as a typo rather than as an empty result.
	if len(errs) == 0 && s.selects() && len(s.selected(model)) == 0 {
		errs = append(errs, fmt.Sprintf("%s matches no component%s",
			s.describeSelectors(), s.nearMiss(model)))
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "\n"))
	}
	return nil
}

// listCap is how many names a message may enumerate before it stops being help.
//
// A descriptor with two components can print both; one with three hundred prints a wall, and the
// reader is looking for the one word they mistyped. The tail is counted rather than dropped, so
// nobody reads a truncated list as the whole set.
const listCap = 8

// atMost renders a list, keeping it short enough to read.
func atMost(names []string, most int) string {
	if len(names) <= most {
		return strings.Join(names, ", ")
	}
	return fmt.Sprintf("%s, and %d more", strings.Join(names[:most], ", "), len(names)-most)
}

// nearMiss is what the descriptor does say about the keys a selector asked for, or "" where
// naming anything would be noise.
//
// For a label, the values in use for that key. A reader who typed `team=paymnets` is one word from
// the answer, and the component names are not it: they may not carry the key at all, and there can
// be hundreds. For an exposure or a criticality there is nothing to add, because the valid values
// are Draugr's own and every message about them already lists all of them.
func (s Scope) nearMiss(model saga.Model) string {
	keys := map[string]bool{}
	for _, sel := range s.Labels {
		if k, _, ok := strings.Cut(sel, "="); ok {
			keys[k] = true
		}
	}
	if len(keys) == 0 {
		return ""
	}
	var known []string
	for k := range keys {
		seen := map[string]bool{}
		for i := range model.Components {
			if v := model.Components[i].Labels[k]; v != "" && !seen[v] {
				seen[v] = true
				known = append(known, k+"="+v)
			}
		}
	}
	if len(known) == 0 {
		return " (no component declares " + quoteList("label", sortedKeys(keys)) + ")"
	}
	return " (this descriptor uses " + atMost(sorted(known), listCap) + ")"
}

// sortedKeys is the keys of a set, ordered, so a message reads the same twice.
func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	return sorted(out)
}

// Selector is one narrowing a caller asked for by what a component is rather than by its name.
type Selector struct{ Key, Value string }

// Selectors is what was asked for, for a report that has to state the request as well as the
// result. Empty where the scope named components outright.
func (s Scope) Selectors() []Selector {
	var out []Selector
	if len(s.Labels) > 0 {
		out = append(out, Selector{"labels", strings.Join(s.Labels, " ")})
	}
	if len(s.Exposure) > 0 {
		out = append(out, Selector{"exposure", strings.Join(stringsOf(s.Exposure), ",")})
	}
	if len(s.Criticality) > 0 {
		out = append(out, Selector{"criticality", strings.Join(stringsOf(s.Criticality), ",")})
	}
	return out
}

// describeSelectors renders what was asked for, so an empty result names the request rather than
// only its outcome.
func (s Scope) describeSelectors() string {
	var parts []string
	// Named first when it is set, because it narrows before any selector does. Without it the
	// message can report a label that is genuinely in use as matching nothing, which reads as a
	// contradiction and offers no next step.
	if len(s.Components) > 0 {
		parts = append(parts, "--components "+strings.Join(s.Components, ","))
	}
	if len(s.Labels) > 0 {
		parts = append(parts, "--labels "+strings.Join(s.Labels, " "))
	}
	if len(s.Exposure) > 0 {
		parts = append(parts, "--exposure "+strings.Join(stringsOf(s.Exposure), ","))
	}
	if len(s.Criticality) > 0 {
		parts = append(parts, "--criticality "+strings.Join(stringsOf(s.Criticality), ","))
	}
	return strings.Join(parts, " ")
}

// missingEnum returns the entries of want that are not in have, for a closed vocabulary.
func missingEnum[T ~string](want, have []T) []string {
	var out []string
	for _, w := range want {
		if !slices.Contains(have, w) {
			out = append(out, string(w))
		}
	}
	return out
}

// stringsOf renders a closed vocabulary for a message.
func stringsOf[T ~string](vals []T) []string {
	out := make([]string, 0, len(vals))
	for _, v := range vals {
		out = append(out, string(v))
	}
	return out
}

// missing returns the entries of want that are not in have.
func missing(want, have []string) []string {
	var out []string
	for _, w := range want {
		if !slices.Contains(have, w) {
			out = append(out, w)
		}
	}
	return out
}

// quoteList renders names as `component "a", "b"`, pluralising the noun for the count.
func quoteList(noun string, names []string) string {
	quoted := make([]string, len(names))
	for i, n := range names {
		quoted[i] = fmt.Sprintf("%q", n)
	}
	if len(names) > 1 {
		noun += "s"
	}
	return noun + " " + strings.Join(quoted, ", ")
}

// sorted returns a copy of names in order, so an error message reads the same twice.
func sorted(names []string) []string {
	out := slices.Clone(names)
	sort.Strings(out)
	return out
}
