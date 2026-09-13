package diff

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/draugr-dev/draugr/pkg/prioritization"
	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/tui"
)

// Formats lists the diff output formats, sorted.
func Formats() []string { return []string{"console", "json", "markdown", "sarif"} }

// Render writes the diff in the named format. Unknown formats error.
func Render(w io.Writer, format string, r Result, opts Options) error {
	switch format {
	case "", "console":
		return renderConsole(w, r, opts)
	case "markdown":
		return renderMarkdown(w, r, opts)
	case "json":
		return renderJSON(w, r)
	case "sarif":
		return renderSARIF(w, r)
	default:
		return fmt.Errorf("unknown diff format %q (available: %v)", format, Formats())
	}
}

// renderSARIF writes the new findings, and only those, as a SARIF report.
//
// For code scanning on a pull request. An upload of the whole repository annotates a reviewer with
// hundreds of findings the branch did not cause, and the ones it did are indistinguishable among
// them. Which is how a review surface stops being read. This is the answer to the question a pull
// request actually asks.
//
// Fixed and unchanged are deliberately absent rather than empty. A fixed finding is no longer
// there to annotate, and an unchanged one is the pre-existing noise this exists to remove; a
// consumer wanting the whole picture has the head scan's own report.
func renderSARIF(w io.Writer, r Result) error {
	// With the rules those findings cite. Without them a code-scanning alert arrives as a bare
	// identifier: no description, and whatever link can be guessed from the id's shape rather than
	// the advisory the scanner actually named.
	rules := map[string]sarif.Rule{}
	for _, f := range r.New {
		if rule, ok := r.Rules[f.RuleID]; ok {
			rules[f.RuleID] = rule
		}
	}
	rep := sarif.Report{Tool: "draugr-diff", Results: r.New, Rules: rules}
	data, err := rep.MarshalSARIF()
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

// View is how much of each row a listing draws, the same three names `draugr scan` takes and with
// the same meaning, so a reader who has learned one has learned the other.
type View string

// The three views.
const (
	ViewFindings View = "findings"
	ViewActions  View = "actions"
	ViewCompact  View = "compact"
)

// Views lists them, sorted, for the flag's own help.
func Views() []string { return []string{"actions", "compact", "findings"} }

// Options are what the caller asked for, beyond the comparison itself.
type Options struct {
	View View
	// Top caps the listing. Zero shows everything, which is the default here and not on `scan`:
	// a diff is already narrowed to what one change did, and hiding part of that removes the thing
	// the command exists to show. The flag is for the dependency bump that introduces forty.
	Top int
}

// changeStates is the four states in the order a reader meets them, with the mark each one wears
// in a forge comment.
//
// Emoji only in markdown. A terminal has the priority ramp to find a row by and a comment has
// nothing, so the mark is what separates four counts in one line of a paragraph somebody skims.
var changeStates = []struct {
	change Change
	emoji  string
}{
	{ChangeNew, "🔺"},
	{ChangeUnaccepted, "⚠️"},
	{ChangeAccepted, "🤝"},
	{ChangeFixed, "✅"},
}

// counts is how many findings are in each state, in order.
func counts(r Result) []int {
	return []int{len(r.New), len(r.Unaccepted), len(r.Accepted), len(r.Fixed)}
}

// headline counts the states, naming only the ones that happened.
//
// A run with nothing accepted should not have to read past "0 accepted" to find the number that is
// not zero. Unchanged is always named, because zero there is the answer rather than noise: a diff
// of two identical scans has to say it compared something.
func headline(r Result, emoji bool) []string {
	var parts []string
	for i, n := range counts(r) {
		if n == 0 {
			continue
		}
		part := fmt.Sprintf("%d %s", n, changeStates[i].change)
		if emoji {
			part = changeStates[i].emoji + " " + part
		}
		parts = append(parts, part)
	}
	return append(parts, fmt.Sprintf("%d unchanged", len(r.Unchanged)))
}

// verdict is what the gate decided, or empty where nothing was asked of this run.
func verdict(r Result) (string, bool) {
	if !r.Gate.Stated() {
		return "", false
	}
	return map[bool]string{true: "FAIL", false: "pass"}[len(r.Tripped) > 0], len(r.Tripped) > 0
}

func loc(f string, line int) string {
	if f == "" {
		return "-"
	}
	if line > 0 {
		return fmt.Sprintf("%s:%d", f, line)
	}
	return f
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// upgrade is the package this finding is about and the release that clears it.
//
// The target is advice, so it is drawn only where something is still to be done. On a fixed row it
// would name a version nobody may have gone to: the diff knows the finding is gone, not how it
// left, and removing the dependency outright produces the same row.
func upgrade(e Entry) (label, fix string) {
	pkg := e.Package
	if pkg == nil || pkg.Name == "" {
		return "", ""
	}
	label = pkg.Name
	if pkg.Version != "" {
		label += " " + pkg.Version
	}
	if e.Change == ChangeFixed || pkg.FixedVersion == "" {
		return label, ""
	}
	return label + " →", pkg.FixedVersion
}

// manyComponents reports whether the rows name more than one, which is the rule the scan report
// follows and the only time the column says anything.
//
// It matters most here: a pull-request comment is the multi-component case, one change touches one
// service in a monorepo, and the first question is whether the finding is yours. Two components
// sharing a dependency otherwise produce rows identical in every visible column. A project with
// one component gets a column repeating itself, and in a comment that width is scarce.
//
// Read over every state rather than over the new and fixed ones alone. A change whose only news is
// an acceptance ending used to lose the column entirely.
func manyComponents(es []Entry) bool {
	var first string
	for i, e := range es {
		if i == 0 {
			first = e.Component
			continue
		}
		if e.Component != first {
			return true
		}
	}
	return false
}

// anyUpgrade reports whether any row has a package to name. A column every row leaves empty is a
// heading paid for and never used.
func anyUpgrade(es []Entry) bool {
	for _, e := range es {
		if label, _ := upgrade(e); label != "" {
			return true
		}
	}
	return false
}

// --- console ---

func renderConsole(w io.Writer, r Result, opts Options) error {
	col := tui.For(w)

	line := []string{col.Paint(tui.StyleMuted, "DRAUGR DIFF")}
	if v, failed := verdict(r); v != "" {
		style := tui.StylePass
		if failed {
			style = tui.StyleFail
		}
		line = append(line, col.Chip(style, v))
	}
	// The first count is what the reader came for and the rest is context.
	counts := headline(r, false)
	line = append(line, col.Paint(tui.StyleStrong, counts[0]))
	for _, part := range counts[1:] {
		line = append(line, col.Paint(tui.StyleMuted, part))
	}
	_, _ = fmt.Fprintf(w, "%s\n\n", strings.Join(line, "  "))

	if bands := newBands(r.New); bands != ([4]int{}) {
		_, _ = fmt.Fprintf(w, " %s  %s\n\n", col.Paint(tui.StyleMuted, "new"), col.BandChips(bands))
	}

	entries := r.Changed()
	if len(entries) == 0 {
		_, _ = fmt.Fprintln(w, col.Paint(tui.StylePass, "Nothing changed. Every finding was already there."))
		writeGate(w, col, r)
		return nil
	}

	if opts.View == ViewActions {
		writeDiffActions(w, col, entries, opts)
	} else {
		writeChanged(w, col, r, entries, opts)
	}
	writeGate(w, col, r)
	writeTry(w, col, r, opts, entries)
	return nil
}

// writeChanged lists every finding the change touched, in one table.
func writeChanged(w io.Writer, col tui.Painter, r Result, entries []Entry, opts Options) {
	shown := entries
	heading := fmt.Sprintf("%d, by priority", len(entries))
	if opts.Top > 0 && len(entries) > opts.Top {
		shown = entries[:opts.Top]
		heading = fmt.Sprintf("top %d of %d, by priority", opts.Top, len(entries))
	}
	_, _ = fmt.Fprintf(w, "%s  %s\n", col.Paint(tui.StyleMuted, "CHANGED"), col.Paint(tui.StyleMuted, heading))

	withComponent := manyComponents(shown)
	cols := []string{"Change", "Priority", "Severity", "Rule", "Scanner"}
	if withComponent {
		cols = append(cols, "Component")
	}
	cols = append(cols, "Location")
	withUpgrade := anyUpgrade(shown)
	if withUpgrade {
		cols = append(cols, "Upgrade")
	}
	t := tui.NewTable(col, cols...).Indent("  ").StyledNotes()

	for _, e := range shown {
		// Bold is what a reader reads first and costs no color, which keeps the ramp the band's.
		// A hue here would collide with the severities two columns over.
		mark := tui.Styled(tui.StyleMuted, e.Change.Mark()+" "+string(e.Change))
		if e.Change.NeedsSomebody() {
			mark = tui.Styled(tui.StyleStrong, e.Change.Mark()+" "+string(e.Change))
		}
		label, fix := upgrade(e)
		cells := []tui.Cell{
			mark,
			tui.Styled(tui.PriorityStyle(e.Priority), dash(e.Priority)),
			tui.PlainCell(string(e.Severity(""))),
			{Text: e.RuleID, URL: r.HelpURI(e.RuleID)},
			tui.PlainCell(dash(e.Tool)),
		}
		if withComponent {
			cells = append(cells, tui.PlainCell(dash(e.Component)))
		}
		cells = append(cells, tui.Styled(tui.StyleMuted, loc(e.Location.URI, e.Location.StartLine)))
		if withUpgrade {
			cells = append(cells, tui.Cell{Text: label, Style: tui.StyleMuted, Note: fix, NoteStyle: tui.StyleFixed})
		}
		if opts.View == ViewCompact {
			t.Row(cells...)
			continue
		}
		t.RowWithNotes([]string{findingTitle(e)}, cells...)
	}
	t.Render(w)
	if len(shown) < len(entries) {
		_, _ = fmt.Fprintf(w, "\n%s\n", col.Paint(tui.StyleMuted,
			fmt.Sprintf("… and %d changed findings not listed.", len(entries)-len(shown))))
	}
}

// action is one thing to do and the findings it covers.
type action struct {
	what  string
	lead  Entry
	group []Entry
}

// groupChanges turns what a change did into the things somebody would do about it.
//
// One remediation usually covers many findings: six advisories in one library are one upgrade.
// Only where the fix genuinely is one fix, which for a diff means the package, and an acceptance
// that ended is its own kind of work because the thing to do is decide again rather than upgrade.
//
// Shared by both formats. A work list that is a different shape depending on where it is read is
// two answers to one question.
func groupChanges(entries []Entry) (actions []action, covered int) {
	index := map[string]*action{}
	for _, e := range entries {
		if !e.Change.NeedsSomebody() {
			continue
		}
		label, _ := upgrade(e)
		key := strings.TrimSuffix(label, " →")
		if key == "" {
			key = e.RuleID
		}
		key = string(e.Change) + "\x00" + key
		if got, ok := index[key]; ok {
			got.group = append(got.group, e)
			covered++
			continue
		}
		// The verb is the change's, not the package's. An accepted finding is a decision somebody
		// already made and the thing to do is read it, not upgrade anything; an acceptance that
		// ended has to be made again. Presenting either as an upgrade tells a reviewer to do work
		// that is not theirs and hides the decision that is.
		subject := strings.TrimSuffix(label, " →")
		if subject == "" {
			subject = e.RuleID
		}
		what := "Upgrade " + subject
		switch e.Change {
		case ChangeUnaccepted:
			what = "Decide on " + subject + " again"
		case ChangeAccepted:
			what = "Review the acceptance of " + subject
		default:
			if label == "" {
				what = "Fix " + subject
			}
		}
		a := &action{what: what, lead: e, group: []Entry{e}}
		index[key] = a
		actions = append(actions, *a)
		covered++
	}
	// The slice holds copies, so the groups have to be read back from the index.
	for i := range actions {
		lead := actions[i].lead
		label, _ := upgrade(lead)
		key := strings.TrimSuffix(label, " →")
		if key == "" {
			key = lead.RuleID
		}
		actions[i].group = index[string(lead.Change)+"\x00"+key].group
	}
	return actions, covered
}

// writeDiffActions groups what a change introduced into the things somebody would do about it.
func writeDiffActions(w io.Writer, col tui.Painter, entries []Entry, opts Options) {
	actions, covered := groupChanges(entries)
	// The same sentence the scan report's fix list uses, so one reader has learned both.
	// Nothing to do is a result, and a heading of zeros over a blank space is not how to say it.
	if len(actions) == 0 {
		_, _ = fmt.Fprintf(w, "%s\n  %s\n", col.Paint(tui.StyleMuted, "WHAT TO DO"),
			col.Paint(tui.StylePass, fmt.Sprintf("Nothing. %s changed and none of it needs anybody.",
				plural(len(entries), "finding"))))
		return
	}

	// --top caps the listing, and in this view the listing is the actions. A flag that quietly did
	// nothing in one view would be the same silence as a scanner that did not run.
	shown, held := actions, 0
	if opts.Top > 0 && len(actions) > opts.Top {
		shown, held = actions[:opts.Top], len(actions)-opts.Top
	}
	verb := "clear"
	if len(actions) == 1 {
		verb = "clears"
	}
	heading := fmt.Sprintf("%s %s %s", plural(len(actions), "action"), verb, plural(covered, "finding"))
	if held > 0 {
		heading = fmt.Sprintf("top %d of %s · %s", opts.Top, plural(len(actions), "action"),
			plural(covered, "finding"))
	}
	_, _ = fmt.Fprintf(w, "%s  %s\n", col.Paint(tui.StyleMuted, "WHAT TO DO"),
		col.Paint(tui.StyleMuted, heading))
	for _, a := range shown {
		_, _ = fmt.Fprintf(w, "  %s  %s  %s\n",
			col.Paint(tui.PriorityStyle(a.lead.Priority), dash(a.lead.Priority)),
			col.Paint(tui.StyleStrong, a.what),
			col.Paint(tui.StyleMuted, fmt.Sprintf("%s · %s", dash(a.lead.Control), plural(len(a.group), "finding"))))
		// One rule named and the rest counted, because a row listing six identifiers is six things
		// to read to learn one thing to do.
		rules := a.lead.RuleID
		if more := len(a.group) - 1; more > 0 {
			rules += fmt.Sprintf(" +%d", more)
		}
		_, _ = fmt.Fprintf(w, "      %s\n", col.Paint(tui.StyleMuted,
			loc(a.lead.Location.URI, a.lead.Location.StartLine)+" · "+rules))
	}
	if held > 0 {
		_, _ = fmt.Fprintf(w, "\n  %s\n", col.Paint(tui.StyleMuted,
			fmt.Sprintf("… and %s not listed.", plural(held, "action"))))
	}
	if rest := len(entries) - covered; rest > 0 {
		_, _ = fmt.Fprintf(w, "\n  %s\n", col.Paint(tui.StyleMuted,
			fmt.Sprintf("%s nobody has to act on.", plural(rest, "finding"))))
	}
}

// writeGate states the rule the verdict came from, or says none was asked for.
func writeGate(w io.Writer, col tui.Painter, r Result) {
	if !r.Gate.Stated() {
		return
	}
	_, _ = fmt.Fprintf(w, "\n%s\n", col.Paint(tui.StyleMuted, "Gate: "+r.Gate.Sentence()+"."))
}

// writeTry offers what else this run can be asked, and only what applies to it.
func writeTry(w io.Writer, col tui.Painter, r Result, opts Options, entries []Entry) {
	t := tui.NewTable(col).Indent("  ")
	row := func(what, does string) {
		t.Row(tui.Styled(tui.StyleMuted, what), tui.Styled(tui.StyleMuted, does))
	}
	if opts.Top > 0 && len(entries) > opts.Top {
		row("--top 0", "every one of them, not the first "+fmt.Sprint(opts.Top))
	}
	if opts.View != ViewCompact {
		row("--view compact", "one line each, to see how much there is")
	}
	if opts.View != ViewActions && len(r.New) > 0 {
		row("--view actions", "the same findings as a list of things to do")
	}
	if !r.Gate.Stated() {
		row("--fail-on-new P1", "no gate was set; this makes the diff decide the exit code")
	}
	row("--format markdown", "the comment a pull request gets")
	_, _ = fmt.Fprintf(w, "\n%s\n", col.Paint(tui.StyleMuted, "TRY"))
	t.Render(w)
}

// --- markdown ---

func renderMarkdown(w io.Writer, r Result, opts Options) error {
	if opts.View == ViewActions {
		return renderMarkdownActions(w, r, opts)
	}
	return renderMarkdownTable(w, r, opts)
}

// renderMarkdownActions is the comment for a pipeline that wants the work rather than the list.
//
// Six advisories in one library are one upgrade, and a comment that says so is one a reviewer acts
// on where a table of six rows is one they scroll past. Set it in the pipeline template rather than
// per run: which of the two a team wants is a property of how they review, not of the change.
func renderMarkdownActions(w io.Writer, r Result, opts Options) error {
	_, _ = fmt.Fprintln(w, "## Draugr diff")
	_, _ = fmt.Fprintln(w)
	writeMarkdownVerdict(w, r)

	entries := r.Changed()
	if len(entries) == 0 {
		_, _ = fmt.Fprintln(w, "Nothing changed. Every finding was already there.")
		writeMarkdownGate(w, r)
		return nil
	}

	actions, covered := groupChanges(entries)
	if len(actions) == 0 {
		_, _ = fmt.Fprintf(w, "Nothing here is work. %s changed and none of it needs anybody.\n",
			plural(len(entries), "finding"))
		writeMarkdownGate(w, r)
		return nil
	}
	shown, held := actions, 0
	if opts.Top > 0 && len(actions) > opts.Top {
		shown, held = actions[:opts.Top], len(actions)-opts.Top
	}
	verb := "clear"
	if len(actions) == 1 {
		verb = "clears"
	}
	heading := fmt.Sprintf("%s %s %s", plural(len(actions), "action"), verb, plural(covered, "finding"))
	if held > 0 {
		heading = fmt.Sprintf("top %d of %s · %s", opts.Top, plural(len(actions), "action"),
			plural(covered, "finding"))
	}
	_, _ = fmt.Fprintf(w, "### What to do · %s\n\n", heading)
	_, _ = fmt.Fprintln(w, "| Priority | What to do | Control | Findings | Where |")
	_, _ = fmt.Fprintln(w, "|---|---|---|---:|---|")
	for _, a := range shown {
		rules := "`" + a.lead.RuleID + "`"
		if more := len(a.group) - 1; more > 0 {
			rules += fmt.Sprintf(" +%d", more)
		}
		_, _ = fmt.Fprintf(w, "| %s | %s | %s | %d | %s · %s |\n",
			dash(a.lead.Priority), a.what, dash(a.lead.Control), len(a.group),
			loc(a.lead.Location.URI, a.lead.Location.StartLine), rules)
	}
	if held > 0 {
		_, _ = fmt.Fprintf(w, "\n_…and %s not listed._\n", plural(held, "action"))
	}
	if rest := len(entries) - covered; rest > 0 {
		_, _ = fmt.Fprintf(w, "\n_%s nobody has to act on._\n", plural(rest, "finding"))
	}
	writeMarkdownGate(w, r)
	return nil
}

// writeMarkdownVerdict states what the gate decided, or nothing where none was asked for.
func writeMarkdownVerdict(w io.Writer, r Result) {
	if v, failed := verdict(r); v != "" {
		mark := "✅"
		if failed {
			mark = "❌"
		}
		_, _ = fmt.Fprintf(w, "%s **%s** · %s\n\n", mark, v, strings.Join(headline(r, true), " · "))
		return
	}
	_, _ = fmt.Fprintf(w, "**%s**\n\n", strings.Join(headline(r, true), " · "))
}

func renderMarkdownTable(w io.Writer, r Result, opts Options) error {
	_, _ = fmt.Fprintln(w, "## Draugr diff")
	_, _ = fmt.Fprintln(w)
	writeMarkdownVerdict(w, r)

	entries := r.Changed()
	if len(entries) == 0 {
		_, _ = fmt.Fprintln(w, "Nothing changed. Every finding was already there.")
		writeMarkdownGate(w, r)
		return nil
	}

	shown := entries
	heading := fmt.Sprintf("%d, by priority", len(entries))
	if opts.Top > 0 && len(entries) > opts.Top {
		shown = entries[:opts.Top]
		heading = fmt.Sprintf("top %d of %d, by priority", opts.Top, len(entries))
	}
	_, _ = fmt.Fprintf(w, "### Changed · %s\n\n", heading)

	// No column for the finding's own sentence. This is the comment a pull request gets, where a
	// reviewer has the inline annotations and the rule's own link, and a column of prose is what
	// makes the table too wide to read in the width a comment is given.
	withComponent := manyComponents(shown)
	cols := []string{"Change", "Priority", "Severity", "Rule", "Scanner"}
	if withComponent {
		cols = append(cols, "Component")
	}
	cols = append(cols, "Location")
	withUpgrade := anyUpgrade(shown)
	if withUpgrade {
		cols = append(cols, "Upgrade")
	}
	head := "| " + strings.Join(cols, " | ") + " |"
	rule := "|" + strings.Repeat("---|", len(cols))
	_, _ = fmt.Fprintln(w, head)
	_, _ = fmt.Fprintln(w, rule)
	for _, e := range shown {
		component := ""
		if withComponent {
			component = " " + dash(e.Component) + " |"
		}
		// Linked to what the scanner published. A reader deciding whether a new finding matters is
		// one click from the advisory rather than one search, and in a comment the link is the only
		// way there.
		id := "`" + e.RuleID + "`"
		if u := r.HelpURI(e.RuleID); u != "" {
			id = "[" + id + "](" + u + ")"
		}
		label, fix := upgrade(e)
		if fix != "" {
			label += " " + fix
		}
		change := string(e.Change)
		if e.Change.NeedsSomebody() {
			change = "**" + change + "**"
		}
		up := ""
		if withUpgrade {
			up = " " + dash(label) + " |"
		}
		_, _ = fmt.Fprintf(w, "| %s | %s | %s | %s | %s |%s %s |%s\n",
			change, dash(e.Priority), e.Severity(""), id, dash(e.Tool), component,
			loc(e.Location.URI, e.Location.StartLine), up)
	}
	if len(shown) < len(entries) {
		_, _ = fmt.Fprintf(w, "\n_…and %d changed finding(s) not listed._\n", len(entries)-len(shown))
	}
	writeMarkdownGate(w, r)
	return nil
}

// writeMarkdownGate states what the verdict was measured against, for a comment read by somebody
// who was not there when it ran.
func writeMarkdownGate(w io.Writer, r Result) {
	if !r.Gate.Stated() {
		return
	}
	_, _ = fmt.Fprintf(w, "\n_Gate: %s._\n", r.Gate.Sentence())
}

// --- json ---

type jsonDiff struct {
	Summary jsonSummary    `json:"summary"`
	New     []sarif.Result `json:"new"`
	Fixed   []sarif.Result `json:"fixed"`
}

type jsonSummary struct {
	New       int `json:"new"`
	Fixed     int `json:"fixed"`
	Unchanged int `json:"unchanged"`

	NewBySeverity   SeverityCounts `json:"newBySeverity"`
	FixedBySeverity SeverityCounts `json:"fixedBySeverity"`
	NewByPriority   PriorityCounts `json:"newByPriority"`
	FixedByPriority PriorityCounts `json:"fixedByPriority"`
}

func renderJSON(w io.Writer, r Result) error {
	doc := jsonDiff{
		Summary: jsonSummary{
			New: len(r.New), Fixed: len(r.Fixed), Unchanged: len(r.Unchanged),
			NewBySeverity: countSeverities(r.New), FixedBySeverity: countSeverities(r.Fixed),
			NewByPriority: countPriorities(r.New), FixedByPriority: countPriorities(r.Fixed),
		},
		New:   r.New,
		Fixed: r.Fixed,
	}
	if doc.New == nil {
		doc.New = []sarif.Result{}
	}
	if doc.Fixed == nil {
		doc.Fixed = []sarif.Result{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

// newBands counts the findings this change introduced, by band.
//
// Over the new ones alone, because that is what the chips are asked about: a strip covering fixed
// findings too would put the good news in the same red as the bad.
func newBands(fs []sarif.Result) [4]int {
	var out [4]int
	for _, f := range fs {
		switch prioritization.Priority(f.Priority) {
		case prioritization.P1:
			out[0]++
		case prioritization.P2:
			out[1]++
		case prioritization.P3:
			out[2]++
		case prioritization.P4:
			out[3]++
		}
	}
	return out
}

// findingTitle is what the finding says, with the package prefix the Upgrade column already shows
// removed, so a row does not quote a third of its own explanation back at the reader.
//
// Stripped from the message rather than rebuilt from the row: a fixed row draws no target, and a
// prefix assembled from what is drawn missed the one the scanner actually wrote, leaving the
// sentence repeating a version the column beside it had just stated.
func findingTitle(e Entry) string {
	msg := strings.Join(strings.Fields(strings.ReplaceAll(e.Message, "\n", " ")), " ")
	if e.Package == nil || e.Package.Name == "" {
		return elide(msg, messageWidth)
	}
	// Only where the message opens with this package, so a sentence that happens to contain a colon
	// keeps all of itself.
	if head, rest, found := strings.Cut(msg, ": "); found && strings.HasPrefix(head, e.Package.Name) {
		msg = rest
	}
	return elide(msg, messageWidth)
}

// messageWidth is how much of a finding's own sentence a row carries, the same as the scan report
// so one finding reads the same length in both.
const messageWidth = 96

func elide(s string, width int) string {
	if len(s) <= width {
		return s
	}
	return strings.TrimRight(s[:width-1], " ") + "…"
}

// plural renders a count with its noun, pluralized the simple way.
func plural(n int, word string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, word)
	}
	return fmt.Sprintf("%d %ss", n, word)
}
