package report

import (
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"

	"github.com/draugr-dev/draugr/internal/english"

	"github.com/draugr-dev/draugr/pkg/prioritization"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// The states a finding can be in against the base, as `draugr diff` names them, in the order it
// lists them: the change first, then what it left as it was.
const (
	stateNew           = "new"
	stateUnaccepted    = "unaccepted"
	stateAccepted      = "accepted"
	stateFixed         = "fixed"
	stateMoved         = "moved"
	stateUnchanged     = "unchanged"
	stateStillAccepted = "still accepted"
)

// stateWhen says when a finding is in each state, for the definitions behind the states table's one
// mark. The same terms docs/guides/pr-diff.md defines, which the definitions link to for the rest.
var stateWhen = map[string]string{
	stateNew:           "in this run and not in the base",
	stateUnaccepted:    "excused in the base and counting again here: an exclusion was removed or reached its expiry, so a decision about it has to be made again",
	stateAccepted:      "excused here and not in the base: somebody chose to live with it, which is not fixing it",
	stateFixed:         "in the base and not in this run",
	stateMoved:         "reported under another component than in the base, and otherwise the same",
	stateUnchanged:     "in both, counting in both",
	stateStillAccepted: "in both, excused in both",
}

// stateGuide is where the states are defined in full.
const stateGuide = "https://draugr.dev/docs/latest/guides/pr-diff/"

// stateMarks is the sign each changed state wears in a listing, the one `draugr diff` prints.
var stateMarks = map[string]string{
	stateNew: "+", stateUnaccepted: "!", stateAccepted: "~", stateFixed: "-", stateMoved: "→",
}

// statesOf is the run's findings sorted by what happened to each against the base. A caller that
// passed no change view still gets the new findings the gate judged, and nothing else.
func statesOf(d Data) ChangeStates {
	if d.Change != nil {
		return d.Change.States()
	}
	if d.Gate.New == nil {
		return ChangeStates{}
	}
	return ChangeStates{New: d.Gate.New.Introduced}
}

// inState is each state with its findings, in the order the report lists them.
func (c ChangeStates) inState() []struct {
	key string
	fs  []sarif.Result
} {
	return []struct {
		key string
		fs  []sarif.Result
	}{
		{stateNew, c.New}, {stateUnaccepted, c.Unaccepted}, {stateAccepted, c.Accepted}, {stateFixed, c.Fixed},
		{stateMoved, c.Moved}, {stateUnchanged, c.Unchanged}, {stateStillAccepted, c.StillAccepted},
	}
}

// headStates is the state of each finding the head still counts, by fingerprint: the ones the
// Findings list holds. An excused finding is in the Accepted section instead, and a fixed one is in
// neither.
func headStates(c ChangeStates) map[string]string {
	out := map[string]string{}
	for _, s := range c.inState() {
		if s.key == stateAccepted || s.key == stateFixed || s.key == stateStillAccepted {
			continue
		}
		for _, r := range s.fs {
			out[r.Fingerprint()] = s.key
		}
	}
	return out
}

// judgedNote is a judged run's line under its verdict: the base, the new findings and the gate, and
// the caveats that fail the run beside them, which are a second reason for its verdict.
func judgedNote(d Data) string {
	note := changeNote(d.Gate)
	if n := failingCaveatCount(d); n > 0 {
		note += " · " + caveatsFailWords(n)
	}
	return note
}

// failingCaveatCount is how many caveats fail the run, none where the run accepted its errors.
func failingCaveatCount(d Data) int {
	if d.AcceptedErrors {
		return 0
	}
	failing, _ := splitCaveats(d)
	return len(failing)
}

// caveatsFailWords says that n caveats fail the run.
func caveatsFailWords(n int) string {
	verb := "fail"
	if n == 1 {
		verb = "fails"
	}
	return fmt.Sprintf("%s %s the run", english.Count(n, "caveat"), verb)
}

// caveatControls are the controls a caveat that fails the run concerns. On a run judged on its
// change such a control has not passed, whatever the change added to it.
func caveatControls(d Data) map[string]bool {
	out := map[string]bool{}
	if d.AcceptedErrors {
		return out
	}
	failing, _ := splitCaveats(d)
	for _, c := range failing {
		for _, name := range c.controls {
			out[name] = true
		}
	}
	return out
}

// changeView is the Change section of a report judged on its change: everything that changed
// against the base, the way `draugr diff` reports it, with the gate on new findings and its verdict
// first. Everywhere else the report counts the whole run, as any report does.
type changeView struct {
	Base string
	// Threshold is the gate on new findings as the report words a setting, "P2" or "high severity".
	Threshold string
	// Fail is the gate on new findings' verdict alone. A caveat that fails the run is said beside it.
	Fail bool
	// Said is the verdict's sentence: how many new findings there are and how many met the gate.
	Said string
	// Caveats says that caveats fail the run too, empty where none does.
	Caveats     string
	CaveatCount int
	// States are the states that hold a finding, each with its count by band.
	States []changeState
	// Guide is where the states are defined in full.
	Guide string
	// Actions are the most urgent of the fix list's rows that clear a new or an unaccepted finding:
	// what the change asks somebody to do, and where. The rest are in the fix list itself, which
	// OnNew and OnUnaccepted count and lead to, narrowed to the change, with search and paging.
	Actions             []htmlAction
	ActionsMore         int
	OnNew, OnUnaccepted int
	// Listed are the accepted and fixed findings. No other section lists them as the change's: an
	// excused finding sits among every other excused one, and a fixed one is in the head nowhere.
	Listed []changeList
	// Cols are the changed states the controls and components tables count, those with a finding.
	Cols []string
	// Controls and Components are the rows the change touched, in the report's own order.
	Controls, Components []changeRow
}

// changeState is one state's strip.
type changeState struct {
	Key, Mark string
	// When says when a finding is in this state, for the definitions behind the table's mark.
	When  string
	N     int
	Bands []htmlChip
	// Listed says the Findings list holds this state's findings, so its count is a way to them.
	// Every state but still accepted, whose findings the Accepted section holds among the rest.
	Listed bool
}

// changeList is the findings in one state, listed.
type changeList struct {
	Key, Mark string
	Rows      []changedRow
	// More counts the findings past the rows shown.
	More int
}

// changedRow is one listed finding.
type changedRow struct {
	Priority, RuleID, Message, Component, Location string
}

// changeRow is one control or component the change touched, with a cell for each of Cols.
type changeRow struct {
	Name string
	// Fail says a new finding here met the gate on new findings.
	Fail  bool
	Cells [][]htmlChip
}

// changeListCap is how many findings of a state the Change section lists before it counts the rest.
const changeListCap = 25

// changeActionCap is how many actions the Change section shows. A change can touch many; the fix
// list, narrowed to the change, holds them all and can be searched and paged.
const changeActionCap = 5

// capActions keeps the first changeActionCap of the change's actions, ordered, and counts the rest
// and how many touch a new and an unaccepted finding.
func (c *changeView) capActions(acts []htmlAction) {
	for _, a := range acts {
		if a.New > 0 {
			c.OnNew++
		}
		if a.Unaccepted > 0 {
			c.OnUnaccepted++
		}
	}
	if len(acts) > changeActionCap {
		c.ActionsMore = len(acts) - changeActionCap
		acts = acts[:changeActionCap]
	}
	c.Actions = acts
}

// changeViewFor builds the Change section, nil on a run the gate on new findings did not judge.
func changeViewFor(d Data, prioritized bool) *changeView {
	if !d.Gate.judgesChange() {
		return nil
	}
	n, tripped := len(d.Gate.New.Introduced), len(d.Gate.New.Tripped)
	threshold := ThresholdWords(d.Gate.FailOnNew)
	c := &changeView{Base: d.Gate.baseName(), Threshold: threshold, Fail: tripped > 0, Guide: stateGuide,
		Said: changeSaid(n, tripped, threshold, d.Gate.baseName())}
	if k := failingCaveatCount(d); k > 0 {
		c.Caveats, c.CaveatCount = caveatsFailWords(k), k
	}
	states := statesOf(d)
	cells := func(fs []sarif.Result, key string) []htmlChip {
		if len(fs) == 0 {
			return nil
		}
		if !prioritized {
			return []htmlChip{{Class: "plain", Text: strconv.Itoa(len(fs))}}
		}
		chips := nonZeroChips(newBandChips(bandsOf(fs)))
		// A fix is the one state nobody has to act on, so its counts do not wear the bands' fill.
		if key == stateFixed {
			for i := range chips {
				chips[i].Class = "plain"
			}
		}
		if len(chips) == 0 {
			return []htmlChip{{Class: "plain", Text: strconv.Itoa(len(fs))}}
		}
		return chips
	}
	for _, s := range states.inState() {
		if len(s.fs) == 0 {
			continue
		}
		c.States = append(c.States, changeState{Key: s.key, Mark: stateMarks[s.key],
			When: stateWhen[s.key], N: len(s.fs), Bands: cells(s.fs, s.key), Listed: s.key != stateStillAccepted})
	}
	for _, s := range []struct {
		key string
		fs  []sarif.Result
	}{{stateAccepted, states.Accepted}, {stateFixed, states.Fixed}} {
		if len(s.fs) == 0 {
			continue
		}
		l := changeList{Key: s.key, Mark: stateMarks[s.key]}
		for i, r := range sortedByBand(s.fs) {
			if i == changeListCap {
				l.More = len(s.fs) - i
				break
			}
			l.Rows = append(l.Rows, changedRow{Priority: dash(r.Priority), RuleID: r.RuleID,
				Message: findingSummary(r.Message), Component: r.Component, Location: locationOf(r)})
		}
		c.Listed = append(c.Listed, l)
	}

	changed := []struct {
		key string
		fs  []sarif.Result
	}{{stateNew, states.New}, {stateUnaccepted, states.Unaccepted}, {stateAccepted, states.Accepted}, {stateFixed, states.Fixed}}
	for _, s := range changed {
		if len(s.fs) > 0 {
			c.Cols = append(c.Cols, s.key)
		}
	}
	trippedSet := map[string]bool{}
	for _, r := range d.Gate.New.Tripped {
		trippedSet[r.Fingerprint()] = true
	}
	row := func(name string, of func(sarif.Result) string) (changeRow, bool) {
		r := changeRow{Name: name}
		touched := false
		for _, s := range changed {
			if len(s.fs) == 0 {
				continue
			}
			var mine []sarif.Result
			for _, f := range s.fs {
				if of(f) == name {
					mine = append(mine, f)
					if s.key == stateNew && trippedSet[f.Fingerprint()] {
						r.Fail = true
					}
				}
			}
			touched = touched || len(mine) > 0
			r.Cells = append(r.Cells, cells(mine, s.key))
		}
		return r, touched
	}
	seen := map[string]bool{}
	var controls []string
	for _, v := range d.Verdict.Controls {
		controls = append(controls, v.Control)
	}
	// A fixed finding's control may have produced nothing this run, and still belongs in the table.
	for _, s := range changed {
		for _, f := range s.fs {
			if !slices.Contains(controls, f.Control) {
				controls = append(controls, f.Control)
			}
		}
	}
	for _, name := range controls {
		if seen[name] {
			continue
		}
		seen[name] = true
		if r, ok := row(name, func(f sarif.Result) string { return f.Control }); ok {
			c.Controls = append(c.Controls, r)
		}
	}
	for _, comp := range d.Components {
		if r, ok := row(comp.Name, func(f sarif.Result) string { return f.Component }); ok {
			c.Components = append(c.Components, r)
		}
	}
	return c
}

// bandsOf counts findings by band, P1 first.
func bandsOf(fs []sarif.Result) [4]int {
	var out [4]int
	for _, f := range fs {
		if rank := prioritization.Priority(f.Priority).Rank(); rank >= 1 && rank <= 4 {
			out[4-rank]++
		}
	}
	return out
}

// sortedByBand is the findings worst band first, otherwise in the order given.
func sortedByBand(fs []sarif.Result) []sarif.Result {
	out := slices.Clone(fs)
	slices.SortStableFunc(out, func(a, b sarif.Result) int {
		return prioritization.Priority(b.Priority).Rank() - prioritization.Priority(a.Priority).Rank()
	})
	return out
}

// changeSaid is the Change section's verdict sentence.
func changeSaid(n, tripped int, threshold, base string) string {
	at := "at " + threshold + " or above"
	switch {
	case n == 0:
		return "Nothing new since " + base + "."
	case tripped == 0 && n == 1:
		return "1 new finding, below " + threshold + "."
	case tripped == 0:
		return strconv.Itoa(n) + " new findings, none " + at + "."
	case n == 1:
		return "1 new finding, " + at + "."
	case tripped == n:
		return strconv.Itoa(n) + " new findings, every one " + at + "."
	}
	return fmt.Sprintf("%d new findings, %d of them %s.", n, tripped, at)
}

// writeChangeSection is the Change section in markdown, first under the title, because the verdict
// above it is the change's: the gate on new findings and its verdict, every state against the base,
// what to do about the new findings, the accepted and fixed ones listed, and the controls and
// components the change touched. The tables after it count the whole run.
func writeChangeSection(w io.Writer, c *changeView) {
	if c == nil {
		return
	}
	verdict := "pass"
	if c.Fail {
		verdict = "**FAIL**"
	}
	_, _ = fmt.Fprintf(w, "### Change since `%s`\n\n", c.Base)
	_, _ = fmt.Fprintf(w, "%s · %s Fails on a finding new since `%s` at %s or above.\n\n", verdict, c.Said, c.Base, c.Threshold)
	if c.CaveatCount > 0 {
		which, them := fmt.Sprintf("%d caveats, which count", c.CaveatCount), "them"
		if c.CaveatCount == 1 {
			which, them = "a caveat, which counts", "it"
		}
		_, _ = fmt.Fprintf(w, "**FAIL** · The run also fails on %s whether or not `%s` had %s, listed under Caveats.\n\n", which, c.Base, them)
	}
	if len(c.States) > 0 {
		_, _ = fmt.Fprintln(w, "| Change | Findings | By band |")
		_, _ = fmt.Fprintln(w, "|---|---:|---|")
		for _, s := range c.States {
			name := s.Key
			if s.Mark != "" {
				name = s.Mark + " " + name
			}
			_, _ = fmt.Fprintf(w, "| %s | %d | %s |\n", name, s.N, nonZeroChipText(s.Bands))
		}
		_, _ = fmt.Fprintf(w, "\n[What each state means](%s)\n\n", c.Guide)
	}
	if len(c.Actions) > 0 {
		_, _ = fmt.Fprintln(w, "**What to do about this change**")
		_, _ = fmt.Fprintln(w)
		for _, a := range c.Actions {
			where := ""
			if a.Component != "" {
				where += " · " + a.Component
			}
			if a.Where != "" {
				where += " · " + a.Where
			}
			_, _ = fmt.Fprintf(w, "- **%s** %s%s%s\n", a.Priority, a.Title, changeCounts(a), where)
		}
		if c.ActionsMore > 0 {
			_, _ = fmt.Fprintf(w, "- _…and %s, in the HTML report's What to do_\n", english.Count(c.ActionsMore, "more action"))
		}
		_, _ = fmt.Fprintln(w)
	}
	for _, l := range c.Listed {
		_, _ = fmt.Fprintf(w, "**%s %s**\n\n", l.Mark, strings.ToUpper(l.Key[:1])+l.Key[1:])
		_, _ = fmt.Fprintln(w, "| Priority | Rule | Component | Location | Finding |")
		_, _ = fmt.Fprintln(w, "|---|---|---|---|---|")
		for _, r := range l.Rows {
			_, _ = fmt.Fprintf(w, "| %s | %s | %s | %s | %s |\n", r.Priority, r.RuleID, dash(r.Component), dash(r.Location), r.Message)
		}
		if l.More > 0 {
			_, _ = fmt.Fprintf(w, "\n_…and %s more._\n", english.Count(l.More, "finding"))
		}
		_, _ = fmt.Fprintln(w)
	}
	table := func(kind string, rows []changeRow) {
		if len(rows) == 0 {
			return
		}
		head, sep := "| "+kind+" | Gate |", "|---|---|"
		for _, col := range c.Cols {
			head += " " + stateMarks[col] + " " + col + " |"
			sep += "---|"
		}
		_, _ = fmt.Fprintf(w, "%s\n%s\n", head, sep)
		for _, r := range rows {
			v := "pass"
			if r.Fail {
				v = "**FAIL**"
			}
			line := "| " + r.Name + " | " + v + " |"
			for _, cell := range r.Cells {
				line += " " + nonZeroChipText(cell) + " |"
			}
			_, _ = fmt.Fprintln(w, line)
		}
		_, _ = fmt.Fprintln(w)
	}
	table("Control", c.Controls)
	table("Component", c.Components)
	_, _ = fmt.Fprintln(w, "_Everything below is of the whole run._")
	_, _ = fmt.Fprintln(w)
}

// nonZeroChips are the chips that count something: a band the change added nothing to is left out
// rather than drawn as a zero.
func nonZeroChips(chips []htmlChip) []htmlChip {
	var out []htmlChip
	for _, c := range chips {
		if !c.Zero {
			out = append(out, c)
		}
	}
	return out
}

// changeActions are the fix list's actions that clear a new or an unaccepted finding, each with how
// many of each it clears, built as the HTML report's fix list is so the two name the same rows.
func changeActions(d Data, s summary) []htmlAction {
	if !d.Gate.judgesChange() {
		return nil
	}
	introduced := map[string]bool{}
	for _, r := range d.Gate.New.Introduced {
		introduced[r.Fingerprint()] = true
	}
	stateOf := headStates(statesOf(d))
	grouped, _ := groupActions(s.findings, d.Run.Stats.UnpinnedCacheHits, s.copies...)
	nameComponents := actionsNameComponents(grouped)
	var out []htmlAction
	for _, a := range foldLines(grouped) {
		ha := toHTMLAction(a)
		if !nameComponents {
			ha.Component = ""
		}
		ha.New, ha.NewPriority = countNew(a, introduced)
		for _, f := range a.findings {
			if stateOf[f.fingerprint] == stateUnaccepted {
				ha.Unaccepted++
			}
		}
		if ha.New > 0 || ha.Unaccepted > 0 {
			out = append(out, ha)
		}
	}
	return newestFirst(out)
}

// countNew is how many of an action's findings the change introduced, and the worst band among
// them, which is the band the change asks the action to be done at: an action whose old findings are
// P1 and whose one new finding is P3 is P3 work as far as the change goes.
func countNew(a action, introduced map[string]bool) (n int, worst string) {
	rank := -1
	for _, f := range a.findings {
		if !introduced[f.fingerprint] {
			continue
		}
		n++
		if r := prioritization.Priority(f.priority).Rank(); r > rank {
			rank, worst = r, f.priority
		}
	}
	if n > 0 && worst == "" {
		worst = "-"
	}
	return n, worst
}

// newestFirst orders the Change section's actions: those clearing a new finding first, worst band of
// what the change added first, then those clearing an unaccepted one, otherwise as the fix list has
// them. Each keeps the fix list's own badge, so one action reads alike on both tabs, and says the
// band of what the change added beside its count.
func newestFirst(acts []htmlAction) []htmlAction {
	out := slices.Clone(acts)
	rank := func(a htmlAction) int {
		if a.New == 0 {
			return 0
		}
		return 1 + prioritization.Priority(a.NewPriority).Rank()
	}
	slices.SortStableFunc(out, func(a, b htmlAction) int { return rank(b) - rank(a) })
	return out
}

// nonZeroChipText joins the chips that count something, "1 P1 · 2 P2".
func nonZeroChipText(chips []htmlChip) string {
	var out []string
	for _, c := range chips {
		if !c.Zero {
			out = append(out, c.Text)
		}
	}
	return strings.Join(out, " · ")
}

// changeCounts is what an action clears of the change, as a row says it: " · 3 new at P1 · 1
// unaccepted".
func changeCounts(a htmlAction) string {
	out := ""
	if a.New > 0 {
		out += fmt.Sprintf(" · %d new at %s", a.New, a.NewPriority)
	}
	if a.Unaccepted > 0 {
		out += fmt.Sprintf(" · %d unaccepted", a.Unaccepted)
	}
	return out
}
