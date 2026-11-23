package diff

import (
	"slices"

	"github.com/draugr-dev/draugr/internal/english"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/prioritization"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// Ranker is the band a finding takes on a component classified with exposure and criticality,
// ranked the way the scan that reported it ranked it.
type Ranker func(res sarif.Result, exposure saga.Exposure, criticality saga.Criticality) string

// Held is what a comparison's base declaration decided beyond what the head's declared.
//
// The head's descriptor is part of the change under review. Read alone, a pull request that declares
// its component less exposed, turns a control off or excludes the finding it adds is judged by the
// declaration it introduces, and passes a gate its base would have failed it on. So the base's
// declaration stands beside the head's until the change merges: a new finding ranks by the more
// exposed and more critical of the two classifications, a control the base turned on is still
// expected, and only an exclusion the base already had accepts a new finding.
type Held struct {
	// Unrecorded is set where the base report recorded no declaration, a report written by a
	// release that did not record one. The head's declaration then decides alone, and a reader is
	// told so rather than left to assume the base's applied.
	Unrecorded bool
	// Raised are the new findings the base's classification ranks above the head's, each at the band
	// it now has, with the band the head's classification gave it.
	Raised []Rerank
	// Dropped are the controls the base turned on that the head does not, where the head still
	// declares what they covered or has stopped declaring it.
	Dropped []Dropped
	// Unscanned are the base's findings from a dropped control. They are not fixed: nobody looked.
	Unscanned []sarif.Result
	// SelfAccepted are new findings set aside by an exclusion the base did not have. They are listed
	// as accepted, and the gate counts them as new until the exclusion merges.
	SelfAccepted []sarif.Result
}

// Dropped is a control the base ran that the head does not.
type Dropped struct {
	// Component is the base component the control was on, empty for a project-wide control.
	Component string
	// Control is the control's name.
	Control string
}

// Fails reports whether what the base held decides the verdict by itself: a control the base ran
// is not running, so what the change adds where it ran was never looked for.
func (h Held) Fails() bool { return len(h.Dropped) > 0 }

// HoldToBase holds the comparison to the declaration its base recorded, as Held describes.
//
// base and head are what each scan declared, baseRecorded whether the base report recorded it at all,
// and rank ranks a finding as its scan did under another classification.
func (r Result) HoldToBase(base, head engine.Declarations, baseRecorded bool, rank Ranker) Result {
	if !baseRecorded {
		r.Held = Held{Unrecorded: true}
		return r
	}
	var h Held
	from := r.movedFrom()
	baseOf := byName(base.Components)
	headOf := byName(head.Components)

	// Exclusions first, so a finding the change excused for itself is ranked like any other new one.
	accepted := r.Accepted[:0:0]
	for _, f := range r.Accepted {
		if r.arrivedHere(f) && excusedBy(f) && !slices.ContainsFunc(base.Exclusions, func(rule saga.ExcludeRule) bool {
			return rule.Matches(f.Location.URI, f.RuleID)
		}) {
			h.SelfAccepted = append(h.SelfAccepted, f)
		}
		accepted = append(accepted, f)
	}
	r.Accepted = accepted

	raise := func(f *sarif.Result) {
		e, c := stricterOf(f, candidates(f.Component, baseOf, headOf, base.Components, from))
		if e == "" {
			return
		}
		band := rank(*f, e, c)
		if prioritization.Priority(band).Rank() <= prioritization.Priority(f.Priority).Rank() {
			return
		}
		was := f.Priority
		f.Priority, f.Exposure, f.Criticality = band, string(e), string(c)
		h.Raised = append(h.Raised, Rerank{Result: *f, From: was})
	}
	for i := range r.New {
		raise(&r.New[i])
	}
	for i := range h.SelfAccepted {
		raise(&h.SelfAccepted[i])
	}

	h.Dropped = dropped(base, head)
	if len(h.Dropped) > 0 {
		fixed := r.Fixed[:0:0]
		for _, f := range r.Fixed {
			if slices.ContainsFunc(h.Dropped, func(d Dropped) bool {
				return d.Control == f.Control && (d.Component == "" || d.Component == f.Component)
			}) {
				h.Unscanned = append(h.Unscanned, f)
				continue
			}
			fixed = append(fixed, f)
		}
		r.Fixed = fixed
	}
	sortReranks(h.Raised)
	sortResults(h.SelfAccepted)
	sortResults(h.Unscanned)
	r.Held = h
	return r
}

// arrivedHere reports whether f is one of the accepted findings the base had no finding of.
func (r Result) arrivedHere(f sarif.Result) bool {
	return slices.ContainsFunc(r.arrived, func(a sarif.Result) bool { return identity(a) == identity(f) })
}

// excusedBy reports whether a descriptor rule set f aside, the one kind of acceptance a change's
// own descriptor can grant itself. A supplier's VEX statement, a control's setting and a directive
// in the source are recorded under their own origins.
func excusedBy(f sarif.Result) bool {
	return f.Suppression != nil && (f.Suppression.Origin == "" || f.Suppression.Origin == sarif.OriginSaga)
}

// movedFrom is, per head component, the base components a finding moved to it from.
func (r Result) movedFrom() map[string][]string {
	from := map[string][]string{}
	for _, m := range r.Moved {
		if !slices.Contains(from[m.Component], m.Was.Component) {
			from[m.Component] = append(from[m.Component], m.Was.Component)
		}
	}
	return from
}

func byName(cs []engine.ComponentDeclaration) map[string]engine.ComponentDeclaration {
	out := make(map[string]engine.ComponentDeclaration, len(cs))
	for _, c := range cs {
		out[c.Name] = c
	}
	return out
}

// candidates are the base declarations whose classification a finding on the head component
// named name is held to: the base component of the same name, every base component that declared a
// repository this one did not declare at the base, and every base component a finding moved to it
// from. The second and third follow a component renamed or a repository moved to another
// component, which would otherwise arrive with no base declaration at all.
func candidates(name string, baseOf, headOf map[string]engine.ComponentDeclaration, base []engine.ComponentDeclaration,
	movedFrom map[string][]string) []engine.ComponentDeclaration {
	var out []engine.ComponentDeclaration
	same, inBase := baseOf[name]
	if inBase {
		out = append(out, same)
	}
	for _, repo := range headOf[name].Repositories {
		if inBase && slices.Contains(same.Repositories, repo) {
			continue
		}
		for _, b := range base {
			if b.Name != name && slices.Contains(b.Repositories, repo) {
				out = append(out, b)
			}
		}
	}
	for _, was := range movedFrom[name] {
		if b, ok := baseOf[was]; ok && was != name {
			out = append(out, b)
		}
	}
	return out
}

// stricterOf is the most exposed and the most critical classification among f's own and the
// candidates', each read the way the ranking reads it, so an undeclared one is the most exposed or
// most critical. Empty where there are no candidates.
func stricterOf(f *sarif.Result, cands []engine.ComponentDeclaration) (saga.Exposure, saga.Criticality) {
	if len(cands) == 0 {
		return "", ""
	}
	e, _ := prioritization.RankedExposure(saga.Exposure(f.Exposure))
	c, _ := prioritization.RankedCriticality(saga.Criticality(f.Criticality))
	for _, b := range cands {
		be, _ := prioritization.RankedExposure(b.Exposure)
		bc, _ := prioritization.RankedCriticality(b.Criticality)
		if slices.Index(saga.Exposures, be) < slices.Index(saga.Exposures, e) {
			e = be
		}
		if slices.Index(saga.Criticalities, bc) < slices.Index(saga.Criticalities, c) {
			c = bc
		}
	}
	return e, c
}

// dropped are the controls the base turned on that the head does not.
//
// A per-component control is read by what it covered: each repository the base component declared,
// or the component itself where it declared none. A control still covers a repository at the head
// where any component declaring it there runs the control, so a repository moved to another
// component, or a component renamed, keeps its controls; one no head component declares any more
// has lost them all.
func dropped(base, head engine.Declarations) []Dropped {
	var out []Dropped
	for _, c := range base.Controls {
		if !slices.Contains(head.Controls, c) {
			out = append(out, Dropped{Control: c})
		}
	}
	headOf := byName(head.Components)
	covers := func(unit string, byRepo bool, control string) bool {
		if !byRepo {
			h, ok := headOf[unit]
			return ok && slices.Contains(h.Controls, control)
		}
		for _, h := range head.Components {
			if slices.Contains(h.Repositories, unit) && slices.Contains(h.Controls, control) {
				return true
			}
		}
		return false
	}
	for _, b := range base.Components {
		for _, control := range b.Controls {
			lost := false
			if len(b.Repositories) == 0 {
				lost = !covers(b.Name, false, control)
			}
			for _, repo := range b.Repositories {
				if !covers(repo, true, control) {
					lost = true
				}
			}
			if lost {
				out = append(out, Dropped{Component: b.Name, Control: control})
			}
		}
	}
	return out
}

// Notes are the sentences that say what the base's declaration decided, in the order a reader needs
// them: what failed the change first, then what moved a finding's rank or count. Empty where the
// base decided nothing beyond the head.
func (h Held) Notes() []string {
	var notes []string
	if h.Unrecorded {
		return []string{"The base report records no exposure, criticality, controls or exclusions, " +
			"so this change's own decide"}
	}
	if len(h.Dropped) > 0 {
		note := "The base ran " + droppedList(h.Dropped) + " and this change does not, so nothing it adds there was looked for"
		if n := len(h.Unscanned); n > 0 {
			note += ", and " + english.Count(n, "finding") + " from the base " + english.Choose(n, "reads", "read") + " as not scanned rather than fixed"
		}
		notes = append(notes, note)
	}
	if n := len(h.Raised); n > 0 {
		notes = append(notes, english.Count(n, "new finding")+" "+english.Choose(n, "ranks", "rank")+
			" by the base's exposure and criticality, which this change lowers, until it merges")
	}
	if n := len(h.SelfAccepted); n > 0 {
		notes = append(notes, english.Count(n, "new finding")+" "+english.Choose(n, "is", "are")+
			" excused by an exclusion this change adds, and "+english.Choose(n, "counts", "count")+" as new until it merges")
	}
	return notes
}

// droppedList names dropped controls as a reader says them: "sca on api, and secrets".
func droppedList(ds []Dropped) string {
	parts := make([]string, 0, len(ds))
	for _, d := range ds {
		if d.Component == "" {
			parts = append(parts, d.Control)
			continue
		}
		parts = append(parts, d.Control+" on "+d.Component)
	}
	return english.And(parts)
}

// DroppedSentence is the clause a failing run exits with for the controls the base ran and the head
// does not, empty where there are none.
func (h Held) DroppedSentence() string {
	if len(h.Dropped) == 0 {
		return ""
	}
	return "this change stops " + droppedList(h.Dropped) + ", which the base ran"
}
