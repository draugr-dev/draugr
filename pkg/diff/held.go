package diff

import (
	"slices"
	"strings"

	"github.com/draugr-dev/draugr/internal/english"
	"github.com/draugr-dev/draugr/internal/git"

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
// its component less exposed, turns a control off, narrows what its scan reads or excludes the
// finding it adds is judged by the declaration it introduces, and passes a gate its base would have
// failed it on. So the base's declaration stands beside the head's until the change merges: a new
// finding ranks by the more exposed and more critical of the two classifications, a control the base
// turned on is still expected over everything it read, and only an exclusion the base already had
// accepts a new finding.
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
	// Trusted is set where the run was told to trust the change's descriptor, as
	// --trust-descriptor-change tells it. The head's declaration then decides the gate: Raised,
	// Dropped and SelfAccepted say what the base's would have decided, and decide nothing.
	Trusted bool
	// Digest names the head's declaration, the value --trust-descriptor-change takes to trust it.
	// Empty where the caller did not set it.
	Digest string
	// TrustNamedOther is a --trust-descriptor-change value that names another declaration than the
	// head's, so the base's decided. A switch left in a pipeline after its pull request merged
	// names the descriptor that merged, and the next change to it is held to the base again.
	TrustNamedOther string
}

// Dropped is a control the base ran that the head does not.
type Dropped struct {
	// Component is the base component the control was on, empty for a project-wide control.
	Component string
	// Control is the control's name.
	Control string
	// Narrowed says how the head stopped reading part of what the base read, where a component still
	// runs the control there: its paths, an ignore entry, its revision or the control's settings.
	// Zero where the control no longer runs on some part the base read, which the reader is told as
	// the control stopped.
	Narrowed Narrowing
}

// Narrowing is how a change narrowed what a control reads of a repository a component declares, or
// changed how the control runs, while still running it.
//
// A reader told "this change stops secrets on api" after adding one ignore line would look for a
// control turned off and find none, so the run names what narrowed instead.
type Narrowing struct {
	// Paths are the base's paths the head no longer reads all of, as a checkout selects them, with
	// wholeRepository standing for a base that read the whole repository.
	Paths []string
	// Ignore are the ignore entries the head added over the part, as written.
	Ignore []string
	// Revisions are the revisions the head reads the repository at in place of the base's.
	Revisions []RevisionChange
	// Settings are the keys of the control's settings the head added, removed or changed, sorted:
	// a scanner's block or a setting of the control's own.
	Settings []string
}

// RevisionChange is a repository's revision as the base pinned it and as the head pins it, each
// empty where it pins none.
type RevisionChange struct {
	From, To string
}

// wholeRepository is the entry Narrowing.Paths holds where the base read the whole repository.
const wholeRepository = ""

// narrowed reports whether n says anything.
func (n Narrowing) narrowed() bool {
	return len(n.Paths) > 0 || len(n.Ignore) > 0 || len(n.Revisions) > 0 || len(n.Settings) > 0
}

// with is n and o together, each entry once, in the order they were met.
func (n Narrowing) with(o Narrowing) Narrowing {
	for _, p := range o.Paths {
		if !slices.Contains(n.Paths, p) {
			n.Paths = append(n.Paths, p)
		}
	}
	for _, e := range o.Ignore {
		if !slices.Contains(n.Ignore, e) {
			n.Ignore = append(n.Ignore, e)
		}
	}
	for _, r := range o.Revisions {
		if !slices.Contains(n.Revisions, r) {
			n.Revisions = append(n.Revisions, r)
		}
	}
	for _, k := range o.Settings {
		if !slices.Contains(n.Settings, k) {
			n.Settings = append(n.Settings, k)
		}
	}
	slices.Sort(n.Settings)
	return n
}

// String names what changed as a reader says it: "paths no longer reading all of services/api;
// ignore src/client.py; revision pinned to v2; settings retirejs and trivyFs changed".
func (n Narrowing) String() string {
	var parts []string
	if len(n.Paths) > 0 {
		paths := make([]string, 0, len(n.Paths))
		for _, p := range n.Paths {
			if p == wholeRepository {
				p = "the repository"
			}
			paths = append(paths, p)
		}
		parts = append(parts, "paths no longer reading all of "+english.And(paths))
	}
	if len(n.Ignore) > 0 {
		parts = append(parts, "ignore "+english.And(n.Ignore))
	}
	for _, r := range n.Revisions {
		from, to := shortRevision(r.From), shortRevision(r.To)
		switch {
		case from == "":
			parts = append(parts, "revision pinned to "+to)
		case to == "":
			parts = append(parts, "revision "+from+" unpinned")
		default:
			parts = append(parts, "revision "+to+", not "+from)
		}
	}
	if k := len(n.Settings); k > 0 {
		parts = append(parts, english.Choose(k, "setting ", "settings ")+english.And(n.Settings)+" changed")
	}
	return strings.Join(parts, "; ")
}

// scannerOnly names a setting whose whole value is {"enabled": true}: a scanner block that only
// turns on another scanner.
var scannerOnly = engine.SettingDigest(map[string]any{"enabled": true})

// changedSettings are the keys of a control's settings that differ between base and head, sorted:
// those the head added, removed or holds another value for.
//
// A key the head adds that only turns on another scanner is not counted. By itself it leaves every
// scanner the base ran as it was and adds one more beside them, so nothing the base would have found
// goes unlooked for; a base key changed beside it is counted on its own. Every other change counts,
// a stricter one too, because the diff cannot tell from a setting which way it moves what a scanner
// finds.
//
// A report from a release that recorded no settings reads as declaring none, so a head with settings
// is held as though it added them.
func changedSettings(base, head engine.ControlSettings) []string {
	var keys []string
	for k, b := range base {
		if h, ok := head[k]; !ok || h != b {
			keys = append(keys, k)
		}
	}
	for k, h := range head {
		if _, ok := base[k]; !ok && h != scannerOnly {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	return keys
}

// shortRevision is a full commit id cut to the twelve characters a reader compares, and any other
// revision, a tag or a branch, as written.
func shortRevision(r string) string {
	if len(r) == 40 && strings.Trim(r, "0123456789abcdef") == "" {
		return r[:12]
	}
	return r
}

// Fails reports whether what the base held decides the verdict by itself: a control the base ran
// is not running, so what the change adds where it ran was never looked for. Never on a run told to
// trust the change's descriptor.
func (h Held) Fails() bool { return len(h.Dropped) > 0 && !h.Trusted }

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
	// Copied before any rank is raised in place, so the caller's result keeps the head's ranks.
	r.New = slices.Clone(r.New)
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

// TrustChange is the comparison judged by the head's declaration, as --trust-descriptor-change asks
// for a change that edits its own descriptor on purpose. Held still says what the base's
// declaration would have decided, so the run states what the trust waived, and a base finding from a
// dropped control still reads as not scanned rather than fixed, because nobody looked for it.
func (r Result) TrustChange(base, head engine.Declarations, baseRecorded bool, rank Ranker) Result {
	held := r.HoldToBase(base, head, baseRecorded, rank)
	r.Fixed = held.Fixed
	r.Held = held.Held
	r.Held.Trusted = true
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
// A per-component control is read by what it covered: each part of a repository the base component
// declared, or the component itself where it declared none. A control still covers a part at the
// head where the components running it there select every path the base component selected, at the
// revision it read and ignoring nothing it did not, so a repository moved to another component, or a
// component renamed or merged with a neighbor, keeps its controls. A part nobody running the control
// reads that way any more has lost it, whether the component stopped the control, narrowed its
// paths, added an ignore entry or changed its revision. The control's settings count too, here and
// for a project-wide control: one left on but run with another scanner, a narrower ruleset or any
// other setting changed is not the control the base ran, as changedSettings describes.
//
// Components often share one repository and split it by paths. Read by its URL alone, a repository
// is still covered while any one of them runs the control, and a component that stops the control on
// its own part would pass. The scopes decide where both reports recorded them; a report from a
// release that recorded only the URL is compared by URL.
//
// A part lost while a component still runs the control on it is lost to a narrowed scope, and the
// Dropped says how. Where the control no longer runs on one of the parts at all, it reads as
// stopped, the stronger of the two.
func dropped(base, head engine.Declarations) []Dropped {
	var out []Dropped
	for _, c := range base.Controls {
		if !slices.Contains(head.Controls, c) {
			out = append(out, Dropped{Control: c})
		} else if keys := changedSettings(base.Settings[c], head.Settings[c]); len(keys) > 0 {
			out = append(out, Dropped{Control: c, Narrowed: Narrowing{Settings: keys}})
		}
	}
	headOf := byName(head.Components)
	byScope := recordsScopes(base) && recordsScopes(head)
	for _, b := range base.Components {
		for _, control := range b.Controls {
			var lost bool
			var narrowed Narrowing
			switch {
			case len(b.Repositories) == 0:
				h, ok := headOf[b.Name]
				lost = !ok || !slices.Contains(h.Controls, control)
				if !lost {
					narrowed.Settings = changedSettings(b.Settings[control], h.Settings[control])
					lost = len(narrowed.Settings) > 0
				}
			case byScope:
				stopped := false
				for _, s := range b.Scopes {
					covered, how := coversScope(head, b.Name, s, b.Settings[control], control)
					if covered {
						continue
					}
					lost = true
					stopped = stopped || !how.narrowed()
					narrowed = narrowed.with(how)
				}
				if stopped {
					narrowed = Narrowing{}
				}
			default:
				lost, narrowed = lostByURL(head, b.Name, b.Repositories, b.Settings[control], control)
			}
			if lost {
				out = append(out, Dropped{Component: b.Name, Control: control, Narrowed: narrowed})
			}
		}
	}
	return out
}

// recordsScopes reports whether d recorded the paths of every repository it declares, which a report
// from a release before they were recorded does not.
func recordsScopes(d engine.Declarations) bool {
	return !slices.ContainsFunc(d.Components, func(c engine.ComponentDeclaration) bool {
		return len(c.Repositories) > 0 && len(c.Scopes) == 0
	})
}

// lostByURL reports whether control is lost on the base component named name, which declared repos
// with settings, read by URL alone as a report that recorded no scopes is: a repository is still
// covered where a head component declaring it runs the control with the same settings. Where every
// repository still has the control running but some only with other settings, the Narrowing names
// the keys that changed, read from the component named name where it still runs the control there,
// as coversScope reads them, and from the others otherwise.
func lostByURL(head engine.Declarations, name string, repos []string, settings engine.ControlSettings,
	control string) (bool, Narrowing) {
	var lost, stopped bool
	var narrowed Narrowing
	for _, repo := range repos {
		running := false
		var own, others Narrowing
		if slices.ContainsFunc(head.Components, func(h engine.ComponentDeclaration) bool {
			if !slices.Contains(h.Repositories, repo) || !slices.Contains(h.Controls, control) {
				return false
			}
			running = true
			keys := changedSettings(settings, h.Settings[control])
			if h.Name == name {
				own = own.with(Narrowing{Settings: keys})
			} else {
				others = others.with(Narrowing{Settings: keys})
			}
			return len(keys) == 0
		}) {
			continue
		}
		lost = true
		stopped = stopped || !running
		if !own.narrowed() {
			own = others
		}
		narrowed = narrowed.with(own)
	}
	if stopped {
		narrowed = Narrowing{}
	}
	return lost, narrowed
}

// coversScope reports whether the head components running control still read everything s read of
// its repository, with settings, and where they do not but still read some of it, how they narrowed
// it.
//
// Paths are read the way a checkout reads them, so `services/web` and `services/web/**` are one
// subtree and an entry naming the root is the whole repository. The whole repository is covered only
// by a component that selects it whole, since paths cannot show that a set of subtrees adds up to
// every file.
//
// A head scope counts only where it reads the revision s read and ignores nothing s did not. Each
// narrows the scan as surely as a path: an ignore entry over the file a change adds a finding to
// takes the finding out, and a revision pinned to another commit reads a tree without the change.
// Ignore entries are compared as written, so an entry spelled differently counts as new; that is the
// direction to be wrong in, and --trust-descriptor-change passes a change that means it.
//
// How it narrowed is read from the head component named name where that component still runs the
// control over the part, since a neighbor's own entries were never what read it; from the others
// otherwise.
//
// The control's settings count the same way: a head component that runs it with another scanner,
// a narrower ruleset or any other key changed reads the part differently from the base, and does not
// cover it.
//
// A report from 0.189.1 recorded scopes without ignore entries or revisions, and reads as declaring
// none. Both scans of a pull request run on one binary, so the base and the head record alike.
func coversScope(head engine.Declarations, name string, s engine.RepositoryScope, settings engine.ControlSettings,
	control string) (bool, Narrowing) {
	want := git.Selected(s.Paths)
	// held is what the head scopes reading as s did select, and reached what every head scope
	// running the control over this part selects. own and others are what the rest changed, in
	// the component named name and in the others.
	var held, reached []string
	var heldWhole, reachedWhole bool
	var own, others Narrowing
	for _, h := range head.Components {
		if !slices.Contains(h.Controls, control) {
			continue
		}
		for _, hs := range h.Scopes {
			if hs.URL != s.URL {
				continue
			}
			sel := git.Selected(hs.Paths)
			if !overlaps(want, sel) {
				continue
			}
			added := slices.DeleteFunc(slices.Clone(hs.Ignore), func(e string) bool { return slices.Contains(s.Ignore, e) })
			keys := changedSettings(settings, h.Settings[control])
			same := len(added) == 0 && hs.Revision == s.Revision && len(keys) == 0
			if !same {
				this := Narrowing{Ignore: added, Settings: keys}
				if hs.Revision != s.Revision {
					this.Revisions = []RevisionChange{{From: s.Revision, To: hs.Revision}}
				}
				if h.Name == name {
					own = own.with(this)
				} else {
					others = others.with(this)
				}
			}
			if sel == nil {
				reachedWhole = true
				heldWhole = heldWhole || same
				continue
			}
			reached = append(reached, sel...)
			if same {
				held = append(held, sel...)
			}
		}
	}
	if heldWhole || within(want, held) {
		return true, Narrowing{}
	}
	if !reachedWhole && len(reached) == 0 {
		return false, Narrowing{}
	}
	how := own
	if !how.narrowed() {
		how = others
	}
	how.Paths = nil
	if !reachedWhole {
		how.Paths = lostPaths(want, reached)
	}
	return false, how
}

// lostPaths are the paths of want that reached no longer selects all of, wholeRepository where want
// is the whole repository.
func lostPaths(want, reached []string) []string {
	if want == nil {
		return []string{wholeRepository}
	}
	var lost []string
	for _, p := range want {
		if !within([]string{p}, reached) {
			lost = append(lost, p)
		}
	}
	return lost
}

// within reports whether every path of want lies inside one of selected. Never for the whole
// repository, a nil want.
func within(want, selected []string) bool {
	if want == nil {
		return false
	}
	for _, p := range want {
		if !slices.ContainsFunc(selected, func(h string) bool { return p == h || strings.HasPrefix(p, h+"/") }) {
			return false
		}
	}
	return true
}

// overlaps reports whether two selections share any path, nil standing for the whole repository.
func overlaps(a, b []string) bool {
	if a == nil || b == nil {
		return true
	}
	return slices.ContainsFunc(a, func(p string) bool {
		return slices.ContainsFunc(b, func(h string) bool {
			return p == h || strings.HasPrefix(p, h+"/") || strings.HasPrefix(h, p+"/")
		})
	})
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
	if h.Trusted {
		return h.trustedNotes()
	}
	if h.TrustNamedOther != "" {
		notes = append(notes, "--trust-descriptor-change "+h.TrustNamedOther+
			" names another descriptor than this change's ("+h.Digest+"), so the base's decides")
	}
	notes = append(notes, h.droppedNotes(func(stopped string) string {
		return "The base ran " + stopped + " and this change does not"
	})...)
	if n := len(h.Raised); n > 0 {
		notes = append(notes, english.Count(n, "new finding")+" "+english.Choose(n, "ranks", "rank")+
			" by the base's exposure and criticality, which this change lowers, until it merges")
	}
	if n := len(h.SelfAccepted); n > 0 {
		notes = append(notes, english.Count(n, "new finding")+" "+english.Choose(n, "is", "are")+
			" excused by an exclusion this change adds, and "+english.Choose(n, "counts", "count")+" as new until it merges")
	}
	if h.Digest != "" && len(h.Raised)+len(h.Dropped)+len(h.SelfAccepted) > 0 {
		notes = append(notes, "If this change to the descriptor is intended, add --trust-descriptor-change "+h.Digest+
			" to the pipeline file in this pull request; it trusts this descriptor only, not a later edit")
	}
	return notes
}

// trustedNotes are Notes for a run told to trust the change's descriptor: that it was told, and what
// the base's declaration would have decided had it not been.
func (h Held) trustedNotes() []string {
	if len(h.Raised)+len(h.Dropped)+len(h.SelfAccepted) == 0 {
		return []string{"--trust-descriptor-change changed nothing: this change declares what the base did, " +
			"so the switch can come out of the pipeline"}
	}
	notes := []string{"--trust-descriptor-change: this change's descriptor decides the gate, not the base's"}
	notes = append(notes, h.droppedNotes(func(stopped string) string {
		return "This change stops " + stopped + ", which the base ran"
	})...)
	if n := len(h.Raised); n > 0 {
		notes = append(notes, english.Count(n, "new finding")+" would rank higher by the base's exposure and criticality, which this change lowers")
	}
	if n := len(h.SelfAccepted); n > 0 {
		notes = append(notes, english.Count(n, "new finding")+" "+english.Choose(n, "is", "are")+" excused by an exclusion this change adds")
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

// droppedNotes are the notes for the controls the head stopped and those it narrowed, with the
// count of the base's findings left unscanned on the last. stopped words the first from the list of
// stopped controls; the second reads the same whether or not the run trusts the change.
func (h Held) droppedNotes(stopped func(list string) string) []string {
	off, narrowed := splitDropped(h.Dropped)
	var notes []string
	if len(off) > 0 {
		notes = append(notes, stopped(droppedList(off))+", so nothing it adds there was looked for")
	}
	if len(narrowed) > 0 {
		notes = append(notes, "This change alters "+narrowedList(narrowed)+
			", so what it adds there may not have been looked for")
	}
	if n := len(h.Unscanned); n > 0 && len(notes) > 0 {
		notes[len(notes)-1] += ", and " + english.Count(n, "finding") + " from the base " +
			english.Choose(n, "reads", "read") + " as not scanned rather than fixed"
	}
	return notes
}

// splitDropped parts ds into the controls the head stopped and the ones it narrowed.
func splitDropped(ds []Dropped) (stopped, narrowed []Dropped) {
	for _, d := range ds {
		if d.Narrowed.narrowed() {
			narrowed = append(narrowed, d)
			continue
		}
		stopped = append(stopped, d)
	}
	return stopped, narrowed
}

// narrowedList names narrowed controls as a reader says them: "what secrets reads on api (ignore
// src/client.py) and what sca reads on web (revision v2, not v1)", and a project-wide control
// without a component: "what secrets reads (setting gitleaks changed)".
func narrowedList(ds []Dropped) string {
	parts := make([]string, 0, len(ds))
	for _, d := range ds {
		where := ""
		if d.Component != "" {
			where = " on " + d.Component
		}
		parts = append(parts, "what "+d.Control+" reads"+where+" ("+d.Narrowed.String()+")")
	}
	return english.And(parts)
}

// DroppedSentence is the clause a failing run exits with for the controls the base ran and the head
// does not, empty where there are none: those it stopped, then those it narrowed.
func (h Held) DroppedSentence() string {
	if len(h.Dropped) == 0 {
		return ""
	}
	off, narrowed := splitDropped(h.Dropped)
	var parts []string
	if len(off) > 0 {
		parts = append(parts, "stops "+droppedList(off)+", which the base ran")
	}
	if len(narrowed) > 0 {
		parts = append(parts, "alters "+narrowedList(narrowed))
	}
	return "this change " + strings.Join(parts, ", and ")
}
