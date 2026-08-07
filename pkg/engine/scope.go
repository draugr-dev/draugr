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
// The distinction it exists for: `config.controllers` records a decision — this project does not
// need `dast` — and a filter is a view over one run. Editing the first to get the second is how a
// temporary change gets committed, and how a control ends up disabled in main because somebody
// was debugging.
//
// The zero value scans everything, so a caller that never sets one is unaffected. An empty list
// means "no restriction on this axis", not "nothing": `Scope{Components: []string{"app"}}` runs
// every control against one component.
//
// A scoped run is still gated and still produces a verdict — the alternative is answering "is my
// fix good?" with "no verdict", which sends the reader back to a full scan and makes the filter
// useless for the loop it exists for. What a scoped run must never do is look like an unscoped
// one, so the scope travels with the result and into every artifact that result becomes.
type Scope struct {
	Components []string
	Controls   []string
	// SkippedComponents are the declared components this scope leaves out, filled in by Resolve.
	//
	// Carried rather than recomputed because the descriptor is not available everywhere the
	// scope is read — a rendered report knows what ran, not what was declared. Naming them
	// rather than counting them: "10 not scanned" tells a reader they are missing something and
	// not which thing, and the answer is one the run already had.
	SkippedComponents []string
}

// Resolve returns a copy of this scope with SkippedComponents filled in from the descriptor, so
// everything downstream can say what was left out without needing the descriptor again.
func (s Scope) Resolve(model saga.Model) Scope {
	if len(s.Components) == 0 {
		return s
	}
	out := s
	out.SkippedComponents = nil
	for i := range model.Components {
		if name := model.Components[i].Name; !s.IncludesComponent(name) {
			out.SkippedComponents = append(out.SkippedComponents, name)
		}
	}
	return out
}

// Empty reports whether this scope restricts nothing, which is the ordinary case.
func (s Scope) Empty() bool { return len(s.Components) == 0 && len(s.Controls) == 0 }

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
// nothing, and passes — the same "we did not look" verdict a filter is otherwise careful not to
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
			quoteList("component", bad), strings.Join(sorted(declared), ", ")))
	}
	if bad := missing(s.Controls, controls); len(bad) > 0 {
		errs = append(errs, fmt.Sprintf("--controls: no such %s (run `draugr controls` — this build has: %s)",
			quoteList("control", bad), strings.Join(sorted(controls), ", ")))
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "\n"))
	}
	return nil
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
