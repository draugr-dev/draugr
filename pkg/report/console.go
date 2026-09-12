package report

import (
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/draugr-dev/draugr/pkg/ci"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/sbom"
	"github.com/draugr-dev/draugr/pkg/skald"
	"github.com/draugr-dev/draugr/pkg/tui"
)

// consoleReporter renders a human-readable terminal summary: verdict, priority counts,
// per-control severity, and a ranked "fix first" list. It colorizes when writing to a TTY
// (unless NO_COLOR is set). The gate and machine formats (json/sarif) still speak SARIF levels;
// this human view speaks severity bands and priority.
type consoleReporter struct{}

func (consoleReporter) Format() string { return "console" }

const consoleTopN = 10

// consoleFixFirstLimit resolves how many findings the "Fix first" table shows from Data.TopN:
// 0 → the default (consoleTopN), a negative value → all (returned as -1), a positive value → n.
func consoleFixFirstLimit(topN int) int {
	switch {
	case topN == 0:
		return consoleTopN
	case topN < 0:
		return -1
	default:
		return topN
	}
}

// The report's vocabulary maps onto the shared palette, so a "critical" here looks like a
// "critical" everywhere else Draugr writes.
const (
	cFail     = tui.StyleFail
	cPass     = tui.StylePass
	cCritical = tui.StyleCritical
	cHigh     = tui.StyleHigh
	cMedium   = tui.StyleMedium
	cLow      = tui.StyleLow
	cDim      = tui.StyleMuted
	cAccent   = tui.StyleAccent
	cInfo     = tui.StyleInfo
)

func (consoleReporter) Render(w io.Writer, d Data) error {
	s := summarize(d)
	col := tui.For(w)

	verdict, vcol := "PASS", cPass
	if s.verdict == norn.Fail {
		verdict, vcol = "FAIL", cFail
	}
	// The verdict is filled rather than colored, the shape it wears in the dashboard and in the
	// HTML report. A word in red is one of several red words on the screen; a filled one is the
	// answer, and a reader who takes a single line from this report takes this one.
	_, _ = fmt.Fprintf(w, "%s  %s", col.Paint(cDim, "DRAUGR"), col.Chip(vcol, verdict))
	if rel := d.ProjectName(); rel != "" {
		if d.Release.Version != "" {
			rel += " " + d.Release.Version
		}
		_, _ = fmt.Fprintf(w, "  %s", col.Paint(tui.StyleStrong, rel))
	}
	// Beside the verdict rather than below it. A PASS covering a fifth of the release must not be
	// readable on its own.
	if note := scopeNote(d); note != "" {
		_, _ = fmt.Fprintf(w, "  %s", col.Paint(cAccent, note))
	}
	// What the run cost, where somebody asking is looking. It was reported only under --evidence,
	// which is the flag for "can I trust this" rather than for "how long did that take", so the
	// one question every reader has was the one answered furthest from the top.
	if t := d.Run.Stats.Duration; t > 0 {
		_, _ = fmt.Fprintf(w, "  %s", col.Paint(cDim, t.Round(time.Millisecond).String()))
	}
	_, _ = fmt.Fprint(w, "\n\n")

	truncated := false
	if s.prioritized {
		_, _ = fmt.Fprintln(w, bandChips(col, s))
		// Beside the counts, because it is a caveat on every one of them and a caveat printed away
		// from the thing it qualifies is one the reader meets too late. Not dimmed, for the same
		// reason: somebody reading these bands as a statement about their application has the
		// wrong idea of the run, which is a different kind of gap from an incomplete one.
		if d.Unclassified {
			_, _ = fmt.Fprintf(w, " %s\n", col.Paint(cAccent,
				"No component declares exposure or criticality, so every one is read as public and critical."))
			_, _ = fmt.Fprintf(w, " %s\n", col.Paint(cDim,
				"These bands rank severity alone. `draugr classify` makes them describe this application."))
		}
		_, _ = fmt.Fprintln(w)
	}

	// The work, above everything that describes the run. Asked for, because leading with it is the
	// right answer for somebody who already knows what Draugr found and the wrong one for somebody
	// meeting a verdict for the first time: a list of fixes to apply, before the controls that
	// produced them, reads as instructions from a tool the reader has not yet decided to trust.
	if d.View == ViewActions && len(s.findings) > 0 {
		truncated = writeActions(w, col, s, d, consoleFixFirstLimit(d.TopN))
	}

	// Controls that errored are listed alongside the ones that ran. A control that produced no report
	// has no verdict entry to hang a row on, so listing only the ones that succeeded makes the output
	// shorter exactly when something has gone wrong. Which reads as a clean run to anyone who does not
	// already know how many controls to expect.
	// In the dense view, only the ones with something to say. What each control found is already
	// in the band counts above, and this is the block that repeats them broken down; a control
	// that could not run is the other half, and it stays, because an empty report from it is not
	// evidence of anything.
	errored := d.Run.ScanErrors
	if len(d.Verdict.Controls) > 0 && !dense(d) || len(errored) > 0 {
		_, _ = fmt.Fprintln(w, heading(col, "Controls"))
		width := 0
		for _, c := range d.Verdict.Controls {
			if len(c.Control) > width {
				width = len(c.Control)
			}
		}
		for name := range errored {
			if len(name) > width {
				width = len(name)
			}
		}
		// why prints a control's failures directly beneath that control's own row.
		//
		// Position is the only thing that says which control a message belongs to: it is indented
		// under a row and names a scanner rather than a control, so gathered after the table it
		// sits against whichever control happens to be listed last and reads as that one's
		// problem. Nothing in the sentence contradicts the misreading, which is what makes it
		// worth the extra pass rather than a footnote.
		why := func(control string) {
			for _, msg := range dedupeMessages(errored[control]) {
				// Wrapped rather than clamped to one line. A clamp suits a tool's own stderr, which can be a
				// whole usage screen. But these are Draugr's sentences too, and the half a reader acts on is
				// the end of them.
				for i, line := range wrapMessage(msg, messageWidth) {
					prefix := strings.Repeat(" ", width+2)
					if i > 0 {
						prefix += "  "
					}
					_, _ = fmt.Fprintf(w, "  %s%s\n", prefix, col.Paint(cDim, line))
				}
			}
		}
		for _, c := range d.Verdict.Controls {
			_, bad := errored[c.Control]
			if dense(d) && !bad {
				continue
			}
			v, vc := "pass", cDim
			if c.Verdict == norn.Fail {
				v, vc = "FAIL", cFail
			}
			if bad {
				// It produced findings *and* something failed: what it did report is partial.
				v, vc = "ERROR", cFail
			}
			_, _ = fmt.Fprintf(w, "  %s  %s  %s\n",
				fmt.Sprintf("%-*s", width, c.Control),
				col.Paint(vc, fmt.Sprintf("%-5s", v)),
				controlCounts(col, s, c.Control))
			why(c.Control)
		}
		// Controls that produced nothing at all have no verdict entry, so they're listed here.
		// Between them these two loops cover every key in errored, so no failure loses its
		// explanation by having no row to sit under.
		for _, name := range s.errored {
			_, _ = fmt.Fprintf(w, "  %s  %s  %s\n",
				fmt.Sprintf("%-*s", width, name),
				col.Paint(cFail, fmt.Sprintf("%-5s", "ERROR")),
				col.Paint(cDim, "did not run"))
			why(name)
		}
		// Both stay in the default view. They are coverage rather than provenance: what a control was
		// measured against carries what it did *not* cover, a spec-driven scan that skipped the methods
		// it was not allowed to send, a benchmark that could decide 20 of 34 checks, and a partial scan
		// reading as a complete one is the failure this whole block exists to prevent. The tool builds,
		// job counts and scanned revision are the provenance, and those travel with the evidence.
		if !dense(d) {
			writeMeasuredAgainst(w, col, d, width)
		}
		// What a scanner could not narrow stays: it says the run covered less than it looks like.
		writeNotMeasured(w, col, d, width)
		_, _ = fmt.Fprintln(w)
	}

	if !dense(d) {
		writeComponents(w, col, d)
	}

	// Everything that argued with a band, in one place and counted.
	//
	// Three things move a ranking and each accounted for itself somewhere else: a feed said what it
	// was and how much it raised at the foot of the evidence, an analyzer said what it decided
	// halfway up, and a control's floor said nothing anywhere. A reader asking what moved their
	// ranking was reading three answers in three registers and could not compare them.
	if !dense(d) {
		writeSignals(w, col, d, s)
	}

	// Evidence, not a control, so a line rather than a row in the table above, where every entry means
	// "checked, and here is the verdict". Printed before the early returns below, because a clean
	// scan still produced the inventory and should say so. Silent suppression is the thing to
	// avoid: an excluded finding that leaves no trace reads exactly like one that was never found.
	// The count says otherwise, and each reason travels in the SARIF next to the result it
	// justifies.
	writeAccepted(w, col, d, d.Evidence)

	if !d.Evidence {
		writeGate(w, col, d, false, "")
	}

	if len(s.findings) == 0 {
		// A clean run still did whatever it did and still produced whatever it produced, and
		// both are worth saying: an SBOM nobody is told about is one nobody uses, and a scan
		// that created something in a cluster owes a record of it whatever the verdict.
		// "No findings ✓" after a control that didn't run would be the same false reassurance
		// the ERROR row exists to prevent.
		if len(errored) > 0 {
			_, _ = fmt.Fprintln(w, col.Paint(cDim,
				"No findings from the controls that ran. See the errors reported above."))
		} else {
			_, _ = fmt.Fprintln(w, col.Paint(cPass, "No findings. ✓"))
		}
		_, _ = fmt.Fprintln(w)
		// A clean run still did whatever it did and still produced whatever it produced, and all of
		// it is worth saying: an SBOM nobody is told about is one nobody uses, a scan that created
		// something in a cluster owes a record of it whatever the verdict, and somebody asking what
		// stands behind a pass is asking what somebody asking about a fail is asking.
		writeTail(w, col, s, d, false)
		return nil
	}

	if d.View != ViewActions {
		limit := consoleFixFirstLimit(d.TopN)
		shown := s.findings
		if limit >= 0 && len(shown) > limit {
			shown = shown[:limit]
		}
		_, _ = fmt.Fprintln(w, fixFirstHeading(col, s, len(shown), len(s.findings)))
		renderFixFirst(w, col, shown, d.View == ViewCompact, blobLinks(d))

		// Two different readers, two different answers. Somebody looking at a truncated list wants
		// the rest of *this* list, and answering that with a machine format sends them to a
		// document they did not ask for. Human-readable is the default here, so the follow-up
		// should be too.
		if len(shown) < len(s.findings) {
			_, _ = fmt.Fprintf(w, "\n… and %s not listed.\n",
				plural(len(s.findings)-len(shown), "finding"))
			truncated = true
		}
		_, _ = fmt.Fprint(w, "\n")
	}
	writeTail(w, col, s, d, truncated)
	return nil
}

// dense reports whether this view drops what describes the run rather than what it found.
//
// The compact view is for somebody who already knows what they are looking at and wants to see how
// much there is. What goes is context: which components the findings belong to, how much of the
// code an analyzer could reach, what each control was measured against, and what the run produced.
// What stays is the answer and anything saying the answer is less than it appears, because a
// listing that hides what was set aside is a shorter listing of a different run.
func dense(d Data) bool { return d.View == ViewCompact }

// heading labels a section of the report.
//
// Set in muted capitals rather than in sentence case with a colon, which is how a section is
// labeled in the dashboard and in the HTML report. It reads as a label instead of as the start of
// a sentence, and it separates the report's own structure from everything it quotes: a control is
// named in lower case because that is how it is written in the descriptor, and a heading that
// looked the same made the two hard to tell apart in a column of text.
func heading(col tui.Painter, name string) string {
	return col.Paint(cDim, strings.ToUpper(name))
}

// bandChips is the four priority counts, each filled with its own band's color.
//
// One object per band rather than a colored number beside a plain label: the band and its count
// answer together and a reader picking the row out of a screen of text is looking for the shape
// rather than reading the words. A band with nothing in it is not filled, so the ink on the line
// is the work there is.
func bandChips(col tui.Painter, s summary) string {
	counts := [4]int{s.p1, s.p2, s.p3, s.p4}
	labels := [4]string{"P1", "P2", "P3", "P4"}
	parts := make([]string, 0, len(counts))
	for i, n := range counts {
		text := fmt.Sprintf("%s %d", labels[i], n)
		if n == 0 {
			parts = append(parts, col.Paint(cDim, text))
			continue
		}
		parts = append(parts, col.Chip(priorityColor(labels[i]), text))
	}
	// One space, because a filled chip carries its own. Where there is no fill to carry it, the
	// destination is a log rather than a terminal and the indent is not what makes it readable.
	return " " + strings.Join(parts, " ")
}

// writeEffects records what the run did to its targets beyond reading them.
//
// Not evidence and not hidden: this is what Draugr did to somebody's systems, and a scan that
// created a Job in a cluster or sent traffic to a live endpoint should say so where the verdict is
// read. Near the end because it is a receipt rather than an instruction, the reader acts on the
// findings above and wants this on the way past.
func writeEffects(w io.Writer, col tui.Painter, s summary, d Data) {
	wrote := false
	for _, e := range s.effects {
		_, _ = fmt.Fprintf(w, "%s\n", col.Paint(cDim, fmt.Sprintf("%s: %s", e.Kind, e.Detail)))
		wrote = true
	}
	// What the descriptor asked for and this run could not deliver. With the receipts because it
	// is one: a record of what did not happen, where somebody would otherwise assume it did.
	// Below the findings, not above them. It qualifies what was just read rather than introducing
	// it, and a caveat placed before the fix list competes with the thing it is a caveat about.
	// Not dim, unlike its neighbors here: a reader deciding whether to trust these findings
	// should not have to notice it.
	if line := unpinnedCacheLine(d.Run.Stats.UnpinnedCacheHits); line != "" {
		_, _ = fmt.Fprintf(w, "%s\n", col.Paint(cMedium, line))
		wrote = true
	}
	if wrote {
		_, _ = fmt.Fprintln(w)
	}
}

// fixFirstHeading names what the table below it actually contains.
//
// "Fix first" describes a shortlist, and the default is one, ten of however many, worst first. With
// --top 0 the same words sit above every finding in the run, where they stop being a recommendation
// and become a label, and the reader loses the thing the default was telling them: that these few
// are where to start.
//
// Both headings say the order is meaningful, because that is true either way and is not obvious
// from a table that otherwise looks like any other scanner's dump.
func fixFirstHeading(col tui.Painter, s summary, shown, total int) string {
	filter := ""
	if s.minPriority != "" {
		// Say what was filtered, or a short list reads as a contradiction of the counts above.
		filter = fmt.Sprintf(", %s and above", strings.ToUpper(s.minPriority))
		if s.hidden > 0 {
			filter += fmt.Sprintf("; %d lower-priority finding(s) hidden", s.hidden)
		}
	}
	switch {
	case shown < total:
		return heading(col, "Fix first") + "  " +
			col.Paint(cDim, fmt.Sprintf("top %d of %d, by priority%s", shown, total, filter))
	case total == 1:
		return heading(col, "The finding") + "  " + col.Paint(cDim, "by priority"+filter)
	default:
		return heading(col, "Fix first") + "  " +
			col.Paint(cDim, fmt.Sprintf("all %d, by priority%s", total, filter))
	}
}

// fixFirstColumns is the frame for a set of findings: the columns that tell these findings apart,
// and none that do not.
//
// Severity stays next to priority because they answer different questions and a reader deciding
// whether to trust a band needs the rating it was computed from. The scanner stays because a
// finding is somebody else's tool's claim, and a reader new to Draugr is deciding whether to
// believe it; naming the tool is most of that. What went is the score, which is a number the
// severity already summarizes, and the control, which the block above lists in full and which the
// scanner nearly always implies.
//
// Component sits before Location because a path answers "where inside" and, once a descriptor has
// more than one component, the reader needs "which one" first; two components can carry the same
// path. Both it and Repository appear only where they tell rows apart, so the common project keeps
// the narrow frame.
func fixFirstColumns(fs []finding, compact bool) []string {
	cols := []string{"Priority", "Severity", "Rule", "Scanner"}
	if manyComponents(fs) {
		cols = append(cols, "Component")
	}
	// A component may hold several repositories, and paths are repository-relative, so the same
	// file in two of them produces rows identical in every column. The reader sees a duplicate and
	// has no way to learn otherwise.
	if manyRepositories(fs) {
		cols = append(cols, "Repository")
	}
	cols = append(cols, "Location")
	// What to upgrade, last, where a column costs no padding: nothing follows it, so its width is
	// whatever each row needs. It was the first half of the line underneath, taking the room the
	// advisory's own sentence needed and pushing the end of that sentence off the screen.
	if slices.ContainsFunc(fs, func(f finding) bool { return upgradeLabel(f) != "" }) {
		cols = append(cols, "Upgrade")
	}
	// The explanation, for a listing that has no line underneath to put it on. Absent where no
	// finding carries one, which is every run of a scanner that reports rule ids and nothing else.
	if compact && slices.ContainsFunc(fs, func(f finding) bool { return f.message != "" }) {
		cols = append(cols, "Summary")
	}
	return cols
}

// manyComponents reports whether the findings span more than one component.
//
// One component repeats the same value on every row and answers a question nobody has. The release
// header already says what was scanned. The column earns its width only when it distinguishes
// findings from each other, which is the case that prompted it: several components with paths that
// look alike.
func manyComponents(fs []finding) bool {
	seen := ""
	for _, f := range fs {
		if f.component == "" {
			continue
		}
		if seen == "" {
			seen = f.component
			continue
		}
		if f.component != seen {
			return true
		}
	}
	return false
}

// manyRepositories reports whether the findings span more than one repository.
//
// Same test as manyComponents and for the same reason: a column earns its width only when it
// distinguishes findings from each other. Almost every descriptor has one repository per
// component, and a column repeating it costs width to say nothing.
func manyRepositories(fs []finding) bool {
	seen := ""
	for _, f := range fs {
		if f.repository == "" {
			continue
		}
		if seen == "" {
			seen = f.repository
			continue
		}
		if f.repository != seen {
			return true
		}
	}
	return false
}

// shortRepository is a repository named as a reader would say it: the last two path segments,
// without the scheme or the .git suffix. A column of full clone URLs is a column of one prefix
// repeated, and the part that differs is at the end.
func shortRepository(url string) string {
	s := strings.TrimSuffix(url, ".git")
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	parts := strings.Split(strings.Trim(s, "/"), "/")
	if len(parts) > 2 {
		parts = parts[len(parts)-2:]
	}
	return strings.Join(parts, "/")
}

// renderFixFirst prints the ranked findings as an aligned table with a header row, each
// finding's own message on a dimmed line beneath it.
func renderFixFirst(w io.Writer, col tui.Painter, fs []finding, compact bool, blobs blobLinker) {
	cols := fixFirstColumns(fs, compact)
	has := func(name string) bool { return slices.Contains(cols, name) }
	t := tui.NewTable(col, cols...).Indent("  ").StyledNotes()
	if compact {
		// The one listing whose last column is prose, and the one that has to fit: its whole
		// argument is that a reader can see how much there is, which a row wrapping onto two lines
		// takes away. Zero where the destination has no width to respect, and then the summary is
		// bounded by messageWidth like every other sentence Draugr prints.
		t.Fit(tui.Columns(w))
	}
	for _, f := range fs {
		sev := rankedSeverity(f)
		cells := []tui.Cell{
			band(f, compact),
			tui.Styled(severityColor(sev), string(sev)),
		}
		cells = append(cells,
			// A rule id names a finding; it doesn't explain it. The link is where a reader
			// finds out what it means, and it costs no width.
			tui.Cell{Text: shortRuleID(f.ruleID), URL: f.helpURI},
			// Lowercased. Half these names are what the tool calls itself in its own report
			// ("Trivy") and half are what Draugr runs it as ("trivy"), so one column showed one
			// tool under two spellings and read as two different scanners.
			tui.PlainCell(strings.ToLower(dash(f.tool))))
		if has("Component") {
			cells = append(cells, tui.PlainCell(dash(f.component)))
		}
		if has("Repository") {
			cells = append(cells, tui.PlainCell(dash(shortRepository(f.repository))))
		}
		cells = append(cells, tui.Cell{Text: dash(f.location), URL: blobs.forFinding(f)})
		if has("Upgrade") {
			cells = append(cells, upgradeCell(f))
		}
		if compact {
			// The explanation on the row rather than under it. That is what this view buys: one
			// line per finding, so a reader can see how much there is without scrolling.
			cells = append(cells, tui.PlainCell(elide(findingTitle(f), messageWidth)))
			// One line, and no more. A band something argued with is marked beside the band
			// itself, so the listing still says which rows were argued with; what it gives up is
			// the name of the argument, which is what the default view is for.
			t.Row(cells...)
			continue
		}
		t.RowWithNotes(notesFor(col, f), cells...)
	}
	t.Render(w)
}

// upgradeLabel is the dependency this finding is about and what to do with it, or "" for a
// finding that is not about one.
//
// The version to move to is the only instruction on the row, so it is stated rather than left in
// the middle of a sentence somebody else wrote. Its absence is a real answer and says so.
func upgradeLabel(f finding) string {
	if f.pkg == nil || f.pkg.Name == "" {
		return ""
	}
	label := f.pkg.Name
	if f.pkg.Version != "" {
		label += " " + f.pkg.Version
	}
	if f.pkg.FixedVersion != "" {
		return label + " → " + f.pkg.FixedVersion
	}
	return label + ", no fix available"
}

// upgradeCell paints it: the release that ends the finding wears the color a passing verdict
// wears, which is what the dashboard does with the same fact for the same reason.
func upgradeCell(f finding) tui.Cell {
	label := upgradeLabel(f)
	if f.pkg == nil || f.pkg.FixedVersion == "" {
		return tui.Styled(cDim, label)
	}
	return tui.Cell{
		Text:      strings.TrimSuffix(label, " → "+f.pkg.FixedVersion) + " →",
		Style:     cDim,
		Note:      f.pkg.FixedVersion,
		NoteStyle: tui.StyleFixed,
	}
}

// notesFor is the lines under a row: what the finding is, and anything that argued with its band.
//
// One line where it fits. A mark is two words and a line of its own for it is a line of mostly
// nothing, which on a listing of several hundred is most of the screen.
func notesFor(col tui.Painter, f finding) []string {
	// Everything except the finding's own sentence. These are short, fixed statements, and it is
	// the sentence that gives way to fit them rather than the other way round.
	fixed := make([]notePart, 0, 4)
	// The mark first, so the marks align down the list and how much of a backlog has been argued
	// with is readable without reading a row. The same placement, and the same reason, as the
	// dashboard's.
	if m := movedBy(f); m != nil {
		text := m.glyph + " " + m.label
		fixed = append(fixed, notePart{plain: text, painted: col.Paint(m.style, text)})
	}
	fixed = append(fixed, reasoning(col, f)...)

	room := messageWidth
	painted := make([]string, 0, len(fixed)+1)
	for _, p := range fixed {
		room -= len(p.plain) + len(" · ")
		painted = append(painted, p.painted)
	}
	sep := col.Paint(cDim, " · ")

	title := findingTitle(f)
	switch {
	case title == "":
		if len(painted) == 0 {
			return nil
		}
		return []string{strings.Join(painted, sep)}

	// The sentence, cut to what the rest of the line leaves it.
	//
	// Cut rather than moved to a line of its own. A mark is two words, and a two-word line between
	// two rows that are one line each reads as a row that broke rather than one that is long,
	// which is worse than losing the tail of a sentence already being cut at a fixed width.
	case room >= minTitleWidth:
		// After the mark, so the sentence follows what argued with its band, and before anything
		// that stands behind it.
		with := make([]string, 0, len(painted)+1)
		if len(painted) > 0 {
			with = append(with, painted[0])
		}
		with = append(with, col.Paint(cDim, elide(title, room)))
		if len(painted) > 1 {
			with = append(with, painted[1:]...)
		}
		return []string{strings.Join(with, sep)}

	// Several things argued about one finding and nothing is left for the sentence beside them, so
	// it takes a line. Cutting it to a fragment would read as a different sentence, and a fragment
	// somebody cannot place is worth less than a line.
	default:
		return append(painted, col.Paint(cDim, findingSummary(title)))
	}
}

// minTitleWidth is the least room a finding's own sentence is worth keeping on a shared line.
//
// Below it the sentence is cut to a fragment that reads as a different sentence, which is the
// point at which a line of its own costs less than the ambiguity.
const minTitleWidth = 40

// notePart is one statement under a row, in plain text for measuring and painted for writing.
type notePart struct{ plain, painted string }

// findingTitle is the finding's own sentence with the part the row already states removed.
//
// A dependency finding's message opens by naming the package and the version to move to, because
// the message has to stand alone in a report with no columns. On a row that shows both, repeating
// them costs a third of the line and the end of the sentence is what falls off.
func findingTitle(f finding) string {
	// Trimmed before it is shortened, or the sentence is cut to make room for the words about to
	// be removed, and a row whose prefix is long ends up quoting a third of its own explanation.
	msg := strings.Join(strings.Fields(strings.ReplaceAll(f.message, "\n", " ")), " ")
	if prefix := upgradeLabel(f) + ": "; prefix != ": " {
		msg = strings.TrimPrefix(msg, prefix)
	}
	return findingSummary(msg)
}

// reasoning is what stands behind a band beyond the mark that opens the line: the route that keeps
// a finding where it is, who lowered one, what a second scanner said, and the floor a control
// insisted on.
func reasoning(col tui.Painter, f finding) []notePart {
	var parts []notePart
	for _, note := range []string{
		reachabilityPath(f.reachability),
		unreachableCredit(f.reachability),
		agreementNote(f.alsoFoundBy, f.severity),
		f.priorityFloor,
		historicalNote(f.historical),
	} {
		if note != "" {
			parts = append(parts, notePart{plain: note, painted: col.Paint(cDim, note)})
		}
	}
	return parts
}

// signalColor is the dataset's own color: the pair the dashboard reserves for exploitability,
// deliberately outside the priority ramp, because those four colors already mean a band. A reader
// learns them once and meets them everywhere.
func signalColor(signal string) tui.Style {
	switch signal {
	case "kev":
		return cAccent
	case "epss":
		return cInfo
	default:
		return tui.StyleStrong
	}
}

// blobLinker turns a finding's location into a URL somebody can open.
type blobLinker struct {
	// revisions is the commit each repository was read at, keyed by the URL the descriptor named.
	revisions map[string]string
}

// blobLinks reads the run's own record of what was scanned.
func blobLinks(d Data) blobLinker {
	revs := make(map[string]string, len(d.Repositories))
	for _, r := range d.Repositories {
		// A working-tree scan read files that are in nobody's commit, so a link to the revision
		// would point at content that is not what was scanned.
		if r.Revision != "" && !r.WorkingTree {
			revs[r.URL] = r.Revision
		}
	}
	return blobLinker{revisions: revs}
}

// forFinding is where the reader can see the line this finding is about, or "" when there is
// nowhere honest to point.
//
// Pinned to the commit that was read rather than to a branch. A repository scan reads a revision,
// and a link to the tip shows whatever is there now: the same path, a different file, and a line
// number that lands somewhere unrelated. A link that is silently wrong is worse than no link,
// which is also why nothing is linked when the revision is unknown.
func (b blobLinker) forFinding(f finding) string {
	rev, ok := b.revisions[f.repository]
	if !ok || f.location == "" {
		return ""
	}
	path, line, _ := strings.Cut(f.location, ":")
	base, ok := blobBase(f.repository)
	if !ok {
		return ""
	}
	url := base + "/" + rev + "/" + path
	if line != "" {
		// The two hosts that serve most repositories agree on the anchor, and one that does not
		// understand it still opens the file.
		url += "#L" + line
	}
	return url
}

// blobBase is the part of a file's URL before the revision, for the hosting a URL can be read as.
//
// Only https remotes, and only the path shape both GitHub and GitLab use. An SSH remote names a
// host that may serve nothing over the web, and a self-hosted forge may use another shape
// entirely; guessing produces a link that opens something wrong rather than nothing.
func blobBase(repo string) (string, bool) {
	if !strings.HasPrefix(repo, "https://") {
		return "", false
	}
	trimmed := strings.TrimSuffix(strings.TrimSuffix(repo, "/"), ".git")
	host, path, ok := strings.Cut(strings.TrimPrefix(trimmed, "https://"), "/")
	if !ok || path == "" {
		return "", false
	}
	switch host {
	case "github.com", "gitlab.com":
		return trimmed + "/blob", true
	}
	return "", false
}

// movement is the one mark on a row whose band was argued with: which way it went, what argued,
// and the sentence behind it.
type movement struct {
	glyph string
	label string
	style tui.Style
}

// rankedSeverity is the rating the band was computed from, which is the scanner's own only where
// nothing argued with it.
//
// The column used to show the scanner's word whatever happened to it, so a finding on KEV read
// "P1 · high" with "ranked as critical" three lines below, and the reader had to assemble one fact
// out of a value in one place and its history in another. Worse, the row read as a contradiction
// first and resolved itself second, which is the order that costs trust.
//
// What the scanner said is not lost: the row is marked, and the line underneath says what it was
// raised or lowered from and what did it. The machine formats carry the scanner's rating
// unchanged, because that is what the scanner claimed.
func rankedSeverity(f finding) sarif.Severity {
	if f.escalation != nil && f.escalation.To != "" {
		return f.escalation.To
	}
	if f.reachability != nil && f.reachability.State == sarif.ReachabilityUnreachable &&
		f.reachability.RankedAs != "" {
		return f.reachability.RankedAs
	}
	return f.severity
}

// band is the priority cell.
//
// What argued with the band is on the line under the row rather than in this column: a column is
// as wide as its widest row, so "P1 (↑ EPSS 0.87)" sets it at sixteen characters and every row
// without a mark then carries fourteen spaces before the next column, a gap running the length of
// the table to label two rows.
func band(f finding, marked bool) tui.Cell {
	c := tui.Styled(priorityColor(f.priority), dash(f.priority))
	if !marked {
		return c
	}
	// The glyph alone, and only where there is no line underneath to name what moved the band. It
	// fits inside the heading's own width, so a column of two-character values does not grow to
	// carry it and no row pays for the ones that have one.
	if m := movedBy(f); m != nil {
		c.Note, c.NoteStyle = m.glyph, m.style
	}
	return c
}

// movedBy is what moved this finding's band, in the order the engine applies them.
//
// One mark, not one per input. A row has space for the answer and not for the working, and every
// input still states itself in full on the line underneath; the mark is what makes a listing of
// several hundred readable, because how much of a backlog has been argued with is then visible
// without reading a single row.
//
// Exploitation first because it is the only one that can overrule another: an analyzer finding no
// route does not lower a finding that is being exploited. The same order, and the same glyphs, as
// the dashboard.
func movedBy(f finding) *movement {
	if e := f.escalation; e != nil {
		label := "KEV"
		if e.Signal != "kev" {
			label = "EPSS"
			if e.Detail != "" {
				label = e.Detail
			}
		}
		return &movement{glyph: "↑", label: label, style: signalColor(e.Signal)}
	}
	// A control that declares its findings are not bounded by where the component sits.
	if f.priorityFloor != "" {
		return &movement{glyph: "↑", label: "floor", style: cHigh}
	}
	if f.reachability != nil && f.reachability.State == sarif.ReachabilityUnreachable &&
		f.reachability.RankedAs != "" {
		return &movement{glyph: "↓", label: "unreachable", style: cInfo}
	}
	// Not a band that moved, and marked here for the same reason the others are: the location is a
	// path in a commit rather than in the tree, and a reader who takes it for the current tree
	// reads a finding that is still live as one already cleaned up.
	if f.historical {
		return &movement{glyph: "↩", label: "history", style: cAccent}
	}
	return nil
}

// ruleIDWidth caps the Rule column. Some scanners use long namespaced ids. Semgrep's run past a
// hundred characters, and one of those pushes every column after it off the screen, which costs the
// reader the location and the scanner to show a namespace they didn't need.
const ruleIDWidth = 44

// shortRuleID fits a rule id into the column by dropping the front. Namespaced ids put the
// general part first and the specific part last ("yaml.github-actions.security.<name>"), so the
// tail is the half worth keeping. The full id stays in the JSON and SARIF reports, and the
// hyperlink on it still resolves.
//
// It cuts on a dot where one fits. Cutting purely by width lands mid-word and the result reads as
// corruption rather than truncation, "…ction-tag.github-actions-mutable-action-tag" invites the
// reader to wonder what went wrong, where "…github-actions-mutable-action-tag" plainly says there
// is more in front.
func shortRuleID(id string) string {
	r := []rune(id)
	if len(r) <= ruleIDWidth {
		return id
	}
	cut := len(r) - (ruleIDWidth - 1) // the widest tail that fits after the ellipsis
	if dot := strings.IndexRune(string(r[cut:]), '.'); dot >= 0 {
		// A dot inside the visible tail; start just after it so the fragment is whole segments.
		if tail := string(r[cut:])[dot+1:]; tail != "" {
			return "…" + tail
		}
	}
	return "…" + string(r[cut:])
}

// messageWidth keeps the explanation to one line. Wrapping it would compete with the table for
// the eye; a reader who needs the whole text has --format json.
const messageWidth = 96

// findingSummary condenses a finding's message to a single readable line.
func findingSummary(msg string) string {
	msg = strings.TrimSpace(strings.ReplaceAll(msg, "\n", " "))
	msg = strings.Join(strings.Fields(msg), " ")
	if msg == "" {
		return ""
	}
	if len(msg) > messageWidth {
		msg = strings.TrimSpace(msg[:messageWidth-1]) + "…"
	}
	return msg
}

// wrapMessage folds a message onto lines of at most width, breaking on spaces.
//
// Capped at three lines: a scanner that fails by printing its whole usage screen would otherwise
// bury the report under it, and past three lines a reader wants --log-level trace rather than
// more of the same in a summary.
func wrapMessage(msg string, width int) []string {
	msg = strings.Join(strings.Fields(strings.ReplaceAll(msg, "\n", " ")), " ")
	if msg == "" {
		return nil
	}
	var lines []string
	for len(msg) > width {
		cut := strings.LastIndex(msg[:width], " ")
		if cut <= 0 {
			// One unbroken token longer than the line, a URL, or a path with no spaces in it. Emitted whole
			// and overflowing rather than split at the margin: the reason a URL is in a failure message is
			// so somebody can paste it somewhere, and one broken across two lines cannot be pasted. A long
			// line is untidy; a severed URL is unusable.
			cut = len(msg)
			if end := strings.IndexByte(msg, ' '); end > 0 {
				cut = end
			}
		}
		lines = append(lines, strings.TrimSpace(msg[:cut]))
		msg = strings.TrimSpace(msg[cut:])
		if len(lines) == maxMessageLines-1 {
			break
		}
	}
	if len(msg) > width {
		msg = elide(msg, width)
	}
	return append(lines, msg)
}

// maxMessageLines bounds how much of one failure the summary will show.
const maxMessageLines = 3

// writeComponents breaks the verdict down by the part of the application it belongs to.
//
// The controls table answers "is the project shippable". A component is the unit a team owns and
// the unit exposure and criticality are declared on, so it is the unit someone is deciding about,
// and with several of them, "sca FAIL" says the project has a problem and stops.
//
// The clean ones are the point as much as the failing ones: PASS against a named component is
// what someone can take back to their team, and reading it off a truncated findings table by eye
// was the alternative.
func writeComponents(w io.Writer, col tui.Painter, d Data) {
	if len(d.Components) == 0 {
		return
	}
	width := 0
	for _, c := range d.Components {
		width = max(width, len(c.Name))
	}
	if d.Scope != nil {
		for _, name := range d.Scope.SkippedComponents {
			width = max(width, len(name))
		}
	}

	_, _ = fmt.Fprintln(w, heading(col, "Components"))
	for _, c := range d.Components {
		verdict, style := "pass", cPass
		if c.Verdict == norn.Fail {
			verdict, style = "FAIL", cFail
		}
		// A component nothing was able to look at has not passed. Its scans failed, so "no findings" is
		// true only in the sense that none were possible. Which is the reading this row must not invite,
		// and the same reason a component the scope excluded is listed apart rather than among the
		// passes.
		if len(c.Unscanned) > 0 && c.Findings == 0 {
			verdict, style = "ERROR", cFail
		}
		detail := col.Paint(cDim, "no findings")
		if c.Findings > 0 {
			detail = componentBands(col, c.Priorities)
		}
		// Appended rather than substituted. A component that was partly scanned has findings
		// worth acting on *and* a gap, and either reading alone is wrong: the findings are not
		// the whole picture, and the gap does not mean nothing was found.
		if len(c.Unscanned) > 0 {
			if c.Findings == 0 {
				detail = ""
			} else {
				detail += "  "
			}
			detail += col.Paint(cFail, unscannedDetail(c.Unscanned, c.Declared))
		}
		_, _ = fmt.Fprintf(w, "  %s  %s  %s\n",
			fmt.Sprintf("%-*s", width, c.Name),
			col.Paint(style, fmt.Sprintf("%-5s", verdict)),
			detail)
	}
	// Listed, not omitted. A component absent from this block renders identically to one that
	// passed, and absence is exactly how a reader concludes there was nothing to find.
	if d.Scope != nil {
		for _, name := range d.Scope.SkippedComponents {
			_, _ = fmt.Fprintf(w, "  %s  %s\n",
				fmt.Sprintf("%-*s", width, name),
				col.Paint(cDim, "not scanned"))
		}
	}
	if d.UnattributedFindings > 0 {
		// Project-scoped controls produce these. Omitting them silently would make the parts
		// look like the whole.
		_, _ = fmt.Fprintf(w, "  %s\n", col.Paint(cDim,
			fmt.Sprintf("%s not tied to a component (project-wide controls)",
				plural(d.UnattributedFindings, "finding"))))
	}
	_, _ = fmt.Fprintln(w)
}

// componentBands renders a component's P1–P4 counts, omitting empty ones.
func componentBands(col tui.Painter, p [4]int) string {
	labels := [4]string{"P1", "P2", "P3", "P4"}
	var parts []string
	for i, n := range p {
		if n == 0 {
			continue
		}
		parts = append(parts, col.Chip(priorityColor(labels[i]), fmt.Sprintf("%s %d", labels[i], n)))
	}
	if len(parts) == 0 {
		return col.Paint(cDim, "no priorities set")
	}
	return strings.Join(parts, " ")
}

// excludeSummary describes an exclusion by what it selects, so a reader can find it in the Saga.
func excludeSummary(e saga.ExcludeRule) string {
	var parts []string
	if len(e.Rules) > 0 {
		parts = append(parts, "rules "+strings.Join(e.Rules, ", "))
	}
	if len(e.Paths) > 0 {
		parts = append(parts, "paths "+strings.Join(e.Paths, ", "))
	}
	return strings.Join(parts, "; ") + " · " + findingSummary(e.Reason)
}

// controlCounts is what a control accounts for, in bands.
//
// Bands rather than severities, because that is what the rest of the report is about: the verdict
// is a band, the components are broken down by band, and the gate is set in bands by default. A
// row answering in what the scanner called the flaw asked a reader to hold two vocabularies and
// map between them, in the block that is supposed to be the summary.
//
// A run that ranked nothing has no bands to show, and falls back to what it does have.
func controlCounts(col tui.Painter, s summary, control string) string {
	if !s.prioritized {
		return bandsText(col, s.bands[control])
	}
	return componentBands(col, s.controlBands[control])
}

// bandsText renders per-control severity counts, omitting empty bands, each filled with its own
// severity's color.
//
// Filled for the same reason the priority counts are: the count and the word it counts are one
// fact, and a control row is read by shape rather than word by word.
func bandsText(col tui.Painter, b sevCounts) string {
	var parts []string
	if b.critical > 0 {
		parts = append(parts, col.Chip(cCritical, fmt.Sprintf("%d critical", b.critical)))
	}
	if b.high > 0 {
		parts = append(parts, col.Chip(cHigh, fmt.Sprintf("%d high", b.high)))
	}
	if b.medium > 0 {
		parts = append(parts, col.Chip(cMedium, fmt.Sprintf("%d medium", b.medium)))
	}
	if b.low > 0 {
		parts = append(parts, col.Chip(cLow, fmt.Sprintf("%d low", b.low)))
	}
	if len(parts) == 0 {
		return col.Paint(cDim, "no findings")
	}
	return strings.Join(parts, " ")
}

func priorityColor(p string) tui.Style {
	switch strings.ToUpper(p) {
	case "P1":
		return cFail
	case "P2":
		return cMedium
	case "P3":
		// The band had no color of its own and was drawn in whatever the terminal's text color is,
		// which is also what an unranked row and a heading look like. Three of the four bands being
		// distinguishable is not a ramp.
		return cInfo
	case "P4":
		return cDim
	default:
		return tui.StyleNone
	}
}

func severityColor(s sarif.Severity) tui.Style {
	switch s {
	case sarif.SeverityCritical:
		return cCritical
	case sarif.SeverityHigh:
		return cHigh
	case sarif.SeverityMedium:
		return cMedium
	default:
		return cLow
	}
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func scoreStr(f finding) string {
	if f.hasScore {
		return fmt.Sprintf("%.1f", f.score)
	}
	return "-"
}

// sortedKeys orders map keys so the report is stable run to run.
func sortedKeys(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// plural renders a count with its noun, pluralized the simple way. Only used for the SBOM
// summary line, where "1 documents" would look like a bug in the tool.
func plural(n int, word string) string {
	return fmt.Sprintf("%d %s", n, noun(n, word))
}

// writeMeasuredAgainst records what each scanner measured and against what, under the controls it
// describes.
//
// A fact about the run rather than about any finding, and for a compliance control it is the
// first thing asked of the evidence: a report that does not name the standard it applied cannot
// be defended. Aligned to the controls block above it, because it is a continuation of that list
// rather than a new one.
func writeMeasuredAgainst(w io.Writer, col tui.Painter, d Data, width int) {
	lines := provenanceLines(d)
	if len(lines) == 0 {
		return
	}
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, heading(col, "Measured against"))
	for _, l := range lines {
		text := l.Label()
		if l.Detail != "" {
			text += " · " + l.Detail
		}
		writeUnder(w, col, width, l.Control, text)
	}
}

// writeNotMeasured names a scanner that was planned for a component and then not run.
//
// Beside "Measured against" because it is the same question answered the other way, and a reader
// deciding what a PASS is worth needs both halves. Without it a scanner that could not answer the
// question a component asked looks exactly like one that answered it and found nothing. Which is
// the difference this report exists to make visible.
func writeNotMeasured(w io.Writer, col tui.Painter, d Data, width int) {
	if len(d.Run.Skipped) == 0 {
		return
	}
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, heading(col, "Not measured"))
	for _, sk := range d.Run.Skipped {
		text := sk.Scanner
		if sk.Component != "" {
			text += " on " + sk.Component
		}
		if sk.Reason != "" {
			text += " · " + sk.Reason
		}
		writeUnder(w, col, width, sk.Control, text)
	}
}

// writeUnder prints a control's row and wraps what it has to say under itself.
//
// Wrapped rather than left to run off the edge. These carry a sentence explaining what a scanner
// covered or could not, and the half a reader acts on is the end of it: a line that leaves the
// screen has taken away the reason and kept the name. The same treatment a control's errors get,
// and for the same reason.
func writeUnder(w io.Writer, col tui.Painter, width int, control, text string) {
	for i, line := range wrapMessage(text, messageWidth-width-4) {
		name := fmt.Sprintf("%-*s", width, control)
		if i > 0 {
			name = strings.Repeat(" ", width)
		}
		_, _ = fmt.Fprintf(w, "  %s  %s\n", name, col.Paint(cDim, line))
	}
}

// exploitabilityLine summarizes the feeds a run's severities were enriched from, or "" when
// there were none.
//
// Beside the SBOM line rather than in the findings table: it describes the run, and a reader asking
// "is this data current" is asking about the whole scan rather than any one result.
// exploitabilityLine names the feeds, their dates, and, the part a reader actually wants. What they
// did to this run.
//
// Dates alone say enrichment ran, not whether it changed anything, so the only way to find out
// was to read every finding looking for an escalation note and then wonder whether one had been
// missed. "nothing raised" is a real answer and it takes one word to give.
func exploitabilityLine(feeds []FeedProvenance) string {
	if len(feeds) == 0 {
		return ""
	}
	parts := make([]string, 0, len(feeds))
	for _, f := range feeds {
		part := strings.ToUpper(f.Name)
		if !f.FetchedAt.IsZero() {
			part += " " + f.FetchedAt.UTC().Format(time.DateOnly)
		} else {
			part += " (file)" // supplied by hand: there is no fetch date to give
		}
		if f.Stale {
			part += ", stale"
		}
		parts = append(parts, part)
	}
	return "Exploitability: " + strings.Join(parts, " · ")
}

// unpinnedCacheLine names the images whose findings came from a cache entry that could not be
// content-addressed, or "" when none did.
//
// The cache is content-addressed, and a report that does not say where that held is a report
// claiming more than it knows. An image named by a tag alone has a stable key and unstable bytes:
// the tag may have been rebuilt since the entry was written, and the findings then describe an
// image that is no longer there, a pass over code nobody is running.
//
// It says what to do rather than only what happened, because both answers are one step away: pin
// the digest in the descriptor and the entry becomes content-addressed, or refuse the entry with
// --cache-require-digest and take the re-scan.
func unpinnedCacheLine(refs []string) string {
	if len(refs) == 0 {
		return ""
	}
	// A count, never a list. The rows carry the mark and say which findings this applies to, so naming
	// the references again here answers a question already answered, and on a descriptor with dozens
	// of images it is a list nobody reads at the foot of the one they do.
	//
	// What the count adds is scale: one image out of thirty is a different report from thirty out
	// of thirty, and that is the part the rows cannot say. Which ones, for a run with no findings
	// to mark, is in the JSON and in --evidence.
	return fmt.Sprintf("from cache, %s reused on a tag, so it may describe an earlier build. Pin a digest.",
		plural(len(refs), "image"))
}

// historicalNote says that a finding's location is a path in a commit rather than in the tree.
//
// Without it the location column is read as current, and a path that no longer exists reads as
// something already cleaned up. That inference is backwards: a credential reachable from any
// commit is still fetchable by anyone who can clone, so removing it from the tip is not
// remediation and the finding is not stale. One line, because a reader scanning a table of
// findings is counting, not reading.
func historicalNote(historical bool) string {
	if !historical {
		return ""
	}
	return "in git history · path as it was then. Rotate it; deleting it does not unpublish it."
}

// runLine accounts for the run: what it cost, and the numbers that decide whether anything can be
// done about it.
//
// A reader looking at this is asking one question, why did that take so long, and the answer is
// either "it was waiting" or "one control is slow". So it reports how many ran at once and which
// control took longest: the first says whether more parallelism is available, the second says
// whether it would help.
//
// What it no longer reports is how many jobs were answered by an identical one. That is the
// scheduler's own bookkeeping, true and unactionable, and a number nobody can act on teaches a
// reader to skip the line it is on.
//
// Wall-clock rather than the sum of the jobs, because jobs run concurrently and their sum is a
// number that matches nothing the reader experienced.
func runLine(st engine.Stats) string {
	if st.Jobs == 0 || st.Duration <= 0 {
		return ""
	}
	line := fmt.Sprintf("Ran %s in %s", plural(st.Jobs, "job"), st.Duration.Round(time.Millisecond))
	// Only where it bound the run. Concurrency is a ceiling, and a run with fewer jobs than the
	// ceiling never reached it: "30 jobs, 32 at a time" is arithmetic that does not add up, and a
	// reader who tries to make it add up is reading a number that was never going to help them.
	if st.Concurrency > 0 && st.Jobs > st.Concurrency {
		line += fmt.Sprintf(", %d at a time", st.Concurrency)
	}
	if name, took := slowestControl(st.ByControl); name != "" {
		// "scanner time" because it is summed across that control's jobs, which ran concurrently:
		// a control can hold more of it than the run took in wall clock, and a number larger than
		// the duration beside it reads as the report contradicting itself.
		line += fmt.Sprintf(" · %s took the most scanner time, %s", name, took.Round(time.Millisecond))
	}
	if st.CacheHits > 0 {
		line += fmt.Sprintf(" · %d from cache", st.CacheHits)
	}
	if w := waitSummary(st.ToolWaits); w != "" {
		line += " · " + w
	}
	return line + "."
}

// slowestControl names the control that took longest, summed across its jobs.
//
// The one worth attention, rather than the one with the most jobs: with concurrency the parts do
// not add up to the whole, and somebody deciding whether to raise --jobs needs to know whether one
// control would still be there afterwards.
func slowestControl(byControl map[string]time.Duration) (string, time.Duration) {
	var name string
	var took time.Duration
	for control, d := range byControl {
		// Ties broken by name, so a report built twice reads the same.
		if d > took || (d == took && name != "" && control < name) {
			name, took = control, d
		}
	}
	return name, took
}

// waitSummary says how much of the run was spent queueing for a tool's cache rather than scanning.
//
// The total, once, rather than a line per wait: the waits happen inside concurrent jobs and
// overlap, so a reader adding up individual messages would overstate the cost. Reported next to
// the duration because that is where somebody asking "why did this take so long" is looking, and
// it is the one figure that answers them.
//
// Sub-second totals are not reported. A wait too short to perceive does not explain a slow scan,
// and printing it competes with the findings for the same line.
func waitSummary(waits map[string]time.Duration) string {
	const worthSaying = time.Second
	tools := make([]string, 0, len(waits))
	for tool, d := range waits {
		if d >= worthSaying {
			tools = append(tools, tool)
		}
	}
	if len(tools) == 0 {
		return ""
	}
	sort.Strings(tools)
	parts := make([]string, 0, len(tools))
	for _, tool := range tools {
		parts = append(parts, fmt.Sprintf("%s waiting for the %s cache",
			waits[tool].Round(time.Second), tool))
	}
	return strings.Join(parts, ", ")
}

// toolBuildLines reports which build of each external scanner ran, and flags the ones Draugr
// cannot vouch for.
//
// One line for everything Draugr fetched and checked, because that is a single fact and does not
// need a row each. Anything weaker gets its own line carrying the reason, because those are the
// ones a reader has to decide about.
func toolBuildLines(tools []ToolBuild) []string {
	if len(tools) == 0 {
		return nil
	}
	var verified, other []string
	for _, t := range tools {
		label := t.Name
		if t.Version != "" {
			label += " " + t.Version
		}
		if t.Level == "pinned" || t.Level == "signed" {
			verified = append(verified, label)
			continue
		}
		other = append(other, label+" · "+t.Reason)
	}
	sort.Strings(verified)
	sort.Strings(other)

	var out []string
	if len(verified) > 0 {
		out = append(out, "Scanners: "+strings.Join(verified, ", "))
	}
	for _, o := range other {
		out = append(out, "Scanner (unverified): "+o)
	}
	return out
}

// repositoryRows is what was read and at which commit, one row per repository.
//
// A table rather than a sentence each. A component may hold several repositories and a descriptor
// may hold many components, so this is the block that grows without bound, and fifty sentences
// each naming a URL in the middle of them cannot be compared. The host is dropped with it: every
// row would carry the same one, and what tells them apart is the path.
func repositoryRows(repos []RepositoryProvenance) [][2]string {
	out := make([][2]string, 0, len(repos))
	for _, r := range repos {
		where := r.URL
		if short := strings.TrimPrefix(strings.TrimPrefix(where, "https://"), "http://"); short != where {
			if _, path, ok := strings.Cut(short, "/"); ok && path != "" {
				where = path
			}
		}
		said := r.Short()
		if r.WorkingTree {
			said = strings.TrimSpace("working tree " + said)
		}
		switch {
		case r.WorkingTree && r.Uncommitted > 0:
			// The uncommitted work is the reason this scan was asked for, so it is included rather
			// than missing, and the result cannot be reproduced from the revision.
			said += fmt.Sprintf(" · %s, not reproducible", plural(r.Uncommitted, "uncommitted file"))
		case r.Uncommitted > 0:
			// A clause, not an alarm. Uncommitted work is the normal state of a checkout somebody
			// is editing; what matters is knowing it is not in what you are reading.
			said += fmt.Sprintf(" · %s not included", plural(r.Uncommitted, "uncommitted file"))
		}
		out = append(out, [2]string{where, strings.TrimSpace(said)})
	}
	return out
}

// sbomLine reports what inventory the run produced.
//
// An assembled project document is called out rather than counted in with the rest: it is the one
// that answers "what does this release contain", and "3 documents" would hide it among the parts
// it was built from.
func sbomLine(docs []sbom.Document) string {
	if len(docs) == 0 {
		return ""
	}
	parts := 0
	project := false
	for _, d := range docs {
		if d.Project {
			project = true
			continue
		}
		parts++
	}
	switch {
	case project && parts > 0:
		return fmt.Sprintf("SBOM: 1 project document + %s (%s)", plural(parts, "component document"), docs[0].Format)
	case project:
		return fmt.Sprintf("SBOM: 1 project document (%s)", docs[0].Format)
	default:
		return fmt.Sprintf("SBOM: %s (%s)", plural(parts, "document"), docs[0].Format)
	}
}

// scopeNote describes what a scoped run covered, for the line beside the verdict.
//
// Says the ratio for components, because "2 of 12" is the fact that changes what the verdict
// means, and names the controls, because there are few of them and the names are the answer.
// Empty for an unscoped run, which is nearly all of them.
func scopeNote(d Data) string {
	if d.Scope == nil {
		return ""
	}
	var parts []string
	if n := len(d.Scope.SkippedComponents); n > 0 {
		parts = append(parts, fmt.Sprintf("%d of %d components", len(d.Components), len(d.Components)+n))
	}
	if len(d.Scope.Controls) > 0 {
		parts = append(parts, strings.Join(d.Scope.Controls, ", "))
	}
	if len(parts) == 0 {
		return ""
	}
	return "(scope: " + strings.Join(parts, "; ") + ")"
}

// writeActions renders the fix list as things to do rather than things that are wrong.
//
// One row per action, each saying how many findings it clears and where. A reader deciding what to
// spend an afternoon on is choosing between actions, and a list of findings makes them do the
// grouping in their head, which for a library carrying a dozen CVEs is a dozen rows describing one
// upgrade.
func writeActions(w io.Writer, col tui.Painter, s summary, d Data, limit int) (truncated bool) {
	actions, external := groupActions(s.findings, d.Run.Stats.UnpinnedCacheHits)

	if len(actions) == 0 {
		// Everything found belongs to somebody else. Saying "no findings" would be false and
		// saying nothing would be worse, so say exactly that.
		_, _ = fmt.Fprintf(w, "%s\n\n", col.Paint(cDim, externalLine(external)))
		return false
	}

	shown := actions
	if limit >= 0 && len(shown) > limit {
		shown = shown[:limit]
	}
	_, _ = fmt.Fprintf(w, "%s  %s\n", heading(col, "What to do"), col.Paint(cDim, fmt.Sprintf(
		"%s %s %s", plural(len(shown), "action"), clears(shown), plural(cleared(shown), "finding"))))
	renderActions(w, col, shown, d.View == ViewCompact)

	if len(shown) < len(actions) {
		_, _ = fmt.Fprintf(w, "\n… and %s not listed.\n",
			plural(len(actions)-len(shown), "action"))
		truncated = true
	}
	if len(external) > 0 {
		_, _ = fmt.Fprintln(w, col.Paint(cDim, externalLine(external)))
	}
	_, _ = fmt.Fprintln(w)
	return truncated
}

// writeTail ends a report with what the run produced and what else it can be asked.
//
// Shared by both listings. A receipt that appears only in the view somebody is not using is one
// nobody sees, which is what a duplicated tail drifts into.
func writeTail(w io.Writer, col tui.Painter, s summary, d Data, truncated bool) {
	writeEffects(w, col, s, d)
	writeUncovered(w, col, d)
	// What stands behind the verdict, under the findings rather than over them.
	//
	// It answers "can I trust this run" where the findings answer "what did it find", and the
	// second question is the one a reader came with. Six paragraphs of provenance between the
	// verdict and the list pushed the list off the screen for a reader who asked for both.
	if d.Evidence {
		_, _ = fmt.Fprintf(w, "%s\n", heading(col, "Evidence"))
		writeEvidence(w, col, d, "  ")
	}
	if len(s.findings) == 0 && len(d.Suggestions) == 0 || dense(d) {
		return
	}
	// "Try", because none of it is required and a heading that reads as instructions puts a reader
	// who has already got their answer through a list of things they are apparently expected to do.
	//
	// A row each, rather than a sentence naming two flags with a comma between them. A reader
	// scanning for something to type finds it in a column; the same two flags inside a sentence
	// have to be read whole to find out neither of them applies.
	t := tui.NewTable(col).Indent("  ")
	row := func(what, does string) { t.Row(tui.Styled(cDim, what), tui.Styled(cDim, does)) }
	if truncated {
		// Only where something was left out. Offering to show everything below a list that is
		// already everything is advice that reads as the product not knowing what it printed.
		row("--top 0", "every one of them, not the first ten")
	}
	if d.View != ViewCompact {
		row("--view compact", "one line each, to see how much there is")
	}
	if d.View == ViewActions {
		row("--view findings", "the findings themselves, one row each")
	} else {
		row("--view actions", "the same findings as a list of things to do")
	}
	if len(s.findings) > 0 {
		row("draugr explain <rule>", "what a rule means and how to fix it")
	}
	// Whatever this particular run makes worth trying, after the ones that are always true.
	for _, sug := range d.Suggestions {
		row(sug.What, sug.Why)
	}
	_, _ = fmt.Fprintln(w, heading(col, "Try"))
	t.Render(w)
}

// writeSignals names everything that argued with a band, and what each one did.
//
// One section rather than three, because they answer one question: what moved this ranking away
// from what severity alone would have given.
//
// Counted over every finding rather than the listed ones. `--top` and `--min-priority` narrow what
// is shown, and this answers what the signals did, not what fitted on the page.
func writeSignals(w io.Writer, col tui.Painter, d Data, s summary) {
	type signal struct{ name, did string }
	var signals []signal

	// In the order the engine applies them, which is the order the concept introduces them.
	//
	// Every row reads the same, because every row is the same kind of thing: something that argued
	// with a band, and how much it moved. The colors belong on the marks in the listing below,
	// where a reader is looking for the argued-with rows among hundreds; here there are four rows
	// and a label on each, and a hue would be decoration on a thing that is already found.
	for _, name := range []string{"kev", "epss"} {
		n := s.bySignal[name]
		if n == 0 && !consulted(d, name) {
			continue
		}
		// "nothing raised" is a result rather than an absence. Without it the only way to learn a
		// feed changed nothing is to read every finding looking for a mark that is not there.
		did := "nothing raised"
		if n > 0 {
			did = fmt.Sprintf("%s raised", plural(n, "finding"))
		}
		signals = append(signals, signal{name: strings.ToUpper(name), did: did})
	}
	if n := s.floored; n > 0 {
		signals = append(signals, signal{
			name: "floor",
			did:  fmt.Sprintf("%s raised by a control's own rule", plural(n, "finding")),
		})
	}
	// Named for what it is rather than for the tool that did it. "govulncheck" in the left column
	// tells a reader which binary ran and not what it decided, and this is the one signal whose
	// name they have no reason to know.
	rows, notes := reachabilityBlock(d)
	for _, row := range rows {
		analyzer, did, _ := strings.Cut(row, "  ")
		signals = append(signals, signal{
			name: "reachability",
			did:  strings.TrimSpace(analyzer) + " · " + strings.TrimSpace(did),
		})
	}
	if len(signals) == 0 {
		return
	}

	t := tui.NewTable(col).Indent("  ")
	for _, sig := range signals {
		t.Row(tui.Styled(tui.StyleStrong, sig.name), tui.Styled(cDim, sig.did))
	}
	_, _ = fmt.Fprintln(w, heading(col, "Signals"))
	t.Render(w)
	for _, note := range notes {
		_, _ = fmt.Fprintf(w, "  %s\n", col.Paint(cDim, note))
	}
	_, _ = fmt.Fprintln(w)
}

// consulted reports whether a feed was read at all, so a signal that changed nothing can say so
// rather than being indistinguishable from one nobody loaded.
func consulted(d Data, name string) bool {
	for _, f := range d.Exploitability {
		if f.Name == name {
			return true
		}
	}
	return false
}

// writeAccepted names everything that was set aside, and what went wrong with the setting aside.
//
// One block rather than up to five paragraphs. Each of these was a line of its own separated by a
// blank one, so a run with a couple of exclusions and a supplier document spent a third of the
// screen on statements that share a shape: a place a decision lives, and what it did to this run.
//
// Not dimmed. This is where the report says part of itself was set aside, and greying it out puts
// it below the reading threshold of the thing it qualifies; a reader skimming a clean-looking
// report was the failure mode.
//
// A row per place a decision lives, because that is what a reader would go and edit. A supplier's
// document and a rule in the descriptor are answerable to different people, and a comment in the
// code is answerable to nobody, which is why the three never share a count.
func writeAccepted(w io.Writer, col tui.Painter, d Data, full bool) {
	type row struct {
		where string
		said  []string
		notes []string
	}
	var rows []row

	if line := suppressionLine(d, full); line != "" {
		r := row{where: "config.exclude", said: []string{strings.TrimPrefix(line, "config.exclude: ")}}
		// An exclusion past its date stops suppressing. A finding that used to be accepted
		// reappearing with no explanation is the confusing half of expiry; this is the other half.
		if lapsed := d.Run.LapsedExclusions; len(lapsed) > 0 {
			r.said = append(r.said, fmt.Sprintf("%d expired and no longer suppressing", len(lapsed)))
			for _, e := range lapsed {
				who := e.AcceptedBy
				if who == "" {
					who = "unattributed"
				}
				r.notes = append(r.notes, fmt.Sprintf("expired %s, accepted by %s · %s",
					e.Expires, who, findingSummary(e.Reason)))
			}
		}
		// An exclusion that matched nothing is doing nothing, and reads exactly like one that is
		// working. Usually a typo, a rule id that moved, or a finding somebody fixed and forgot to
		// stop excusing, and in every case the descriptor claims a decision it is not making.
		if unmatched := d.Run.UnmatchedExclusions; len(unmatched) > 0 {
			r.said = append(r.said, fmt.Sprintf("%d matched nothing", len(unmatched)))
			for _, e := range unmatched {
				r.notes = append(r.notes, excludeSummary(e))
			}
		}
		rows = append(rows, r)
	}

	// A supplier's own analysis, named separately and just as loudly. A suppression the reader
	// cannot see is the failure this block exists to prevent, and one made by somebody outside the
	// project is the case where seeing it matters most.
	if line := importedLine(d, full); line != "" {
		r := row{where: "VEX", said: []string{strings.TrimPrefix(line, "VEX: ")}}
		// A statement that matched nothing is doing nothing and looks exactly like one that
		// worked. Usually the supplier and the scanner name a package differently, which is a real
		// finding about the document rather than a quiet no-op.
		if n := len(d.Run.UnmatchedClaims); n > 0 {
			r.said = append(r.said, fmt.Sprintf("%s matched nothing", plural(n, "statement")))
		}
		rows = append(rows, r)
	}

	// A comment in the code. Without this a `nosem` is the one form of acceptance that leaves no
	// trace anywhere, the weakest of the three, added by whoever was editing the file, and the
	// easiest to add without anybody noticing.
	if line := silencedLine(d); line != "" {
		rows = append(rows, row{
			where: "source directives",
			said:  []string{strings.TrimPrefix(line, "source directives: ")},
		})
	}

	if len(rows) == 0 {
		return
	}
	t := tui.NewTable(col).Indent("  ")
	for _, r := range rows {
		t.RowWithNotes(r.notes,
			tui.Styled(tui.StyleStrong, r.where),
			tui.Styled(cAccent, strings.Join(r.said, " · ")))
	}
	_, _ = fmt.Fprintln(w, heading(col, "Accepted"))
	t.Render(w)
	_, _ = fmt.Fprintln(w)
}

// writeUncovered names what the descriptor declares and no enabled control looks at.
//
// A table rather than a sentence each, because every line answers the same two questions and a
// reader comparing them should not have to find the answer in a different place on every row.
func writeUncovered(w io.Writer, col tui.Painter, d Data) {
	if len(d.Uncovered) == 0 {
		return
	}
	t := tui.NewTable(col).Indent("  ")
	for _, g := range d.Uncovered {
		t.Row(
			tui.Styled(tui.StyleStrong, g.Component+" "+g.Surface),
			tui.Styled(cDim, plural(len(g.Controls), "control")+" off: "+strings.Join(g.Controls, ", ")),
		)
	}
	_, _ = fmt.Fprintln(w, heading(col, "Not checked"))
	t.Render(w)
	_, _ = fmt.Fprintln(w)
}

// clears reads as a verb agreeing with the count before it.
func clears(actions []action) string {
	if len(actions) == 1 {
		return "clears"
	}
	return "clear"
}

// cleared totals the findings a set of actions resolves.
func cleared(actions []action) int {
	n := 0
	for _, a := range actions {
		n += a.count()
	}
	return n
}

// externalLine reports what was found on a surface somebody else operates.
//
// One line however many there are, and it says why rather than only how many: "106 findings" with
// no explanation reads as something withheld, and the reason is the useful half.
func externalLine(external []finding) string {
	if len(external) == 0 {
		return ""
	}
	controls := map[string]bool{}
	for _, f := range external {
		controls[f.control] = true
	}
	names := make([]string, 0, len(controls))
	for c := range controls {
		names = append(names, c)
	}
	sort.Strings(names)
	return fmt.Sprintf("%s on infrastructure operated by your provider (%s), reported, "+
		"and not yours to fix.", plural(len(external), "finding"), strings.Join(names, ", "))
}

// renderActions draws the action rows.
func renderActions(w io.Writer, col tui.Painter, actions []action, compact bool) {
	const namedLocations = 2
	for _, a := range actions {
		band := a.priority
		if band == "" {
			band = "-"
		}
		title := a.title
		// The version to move to, when every advisory agrees on one. In the title because it is
		// the action, not a footnote to it.
		if v := a.target(); v != "" {
			title += " → " + v
		}
		meta := fmt.Sprintf("%s · %s", a.control, plural(a.count(), "finding"))
		if a.upstream {
			meta += " · upstream"
		}
		if a.cached {
			meta += " · from cache"
		}
		_, _ = fmt.Fprintf(w, "  %s  %s  %s\n",
			col.Paint(priorityColor(a.priority), fmt.Sprintf("%-2s", band)),
			title,
			col.Paint(cDim, meta))
		if detail := actionDetail(col, a, namedLocations); detail != "" && !compact {
			_, _ = fmt.Fprintf(w, "      %s\n", col.Paint(cDim, detail))
		}
	}
}

// actionDetail is the line under an action: where it applies, and a way into the findings.
//
// Grouping answers "what do I do" and takes away "what exactly is wrong", which is the question a
// reader has next and the one a rule identifier answers. One is named, linked to whatever the
// scanner published about it, and the rest are counted, a reader following a link is going to read
// one of them, and listing fifty-four identifiers to offer that choice fills the screen.
func actionDetail(col tui.Painter, a action, locations int) string {
	var parts []string
	// Not for an image action: the image is the title, and repeating it underneath says nothing.
	if !a.upstream {
		parts = a.where(locations)
	}
	if f, ok := a.exemplar(); ok && f.ruleID != "" {
		ref := col.Link(f.helpURI, shortRuleID(f.ruleID))
		if more := a.count() - 1; more > 0 {
			ref += fmt.Sprintf(" +%d", more)
		}
		parts = append(parts, ref)
	}
	return strings.Join(parts, " · ")
}

// noun agrees a bare noun with a count, for sentences that put the number elsewhere.
//
// Handles the one irregularity the vocabulary here actually contains: a word ending in a
// consonant and "y" takes "ies". "repositorys" is the sort of thing a reader notices and a tool
// does not, and it makes everything around it look less carefully made than it is.
func noun(n int, word string) string {
	if n == 1 {
		return word
	}
	if len(word) > 1 && word[len(word)-1] == 'y' && !isVowel(word[len(word)-2]) {
		return word[:len(word)-1] + "ies"
	}
	return word + "s"
}

func isVowel(b byte) bool { return strings.IndexByte("aeiou", b) >= 0 }

// elide shortens the last line of a wrapped message, at a word boundary where there is one.
//
// Cutting mid-word leaves a fragment that reads as a different word, a truncated identifier or
// version looks like a real one, and a reader cannot tell which they are looking at. Where the line
// is a single long token there is no boundary to find, and cutting it is the only option.
func elide(msg string, width int) string {
	if width <= 1 {
		return "…"
	}
	// Nothing to elide. Callers that wrap already know the line is too long; a caller fitting a
	// value into a column does not, and every short one would otherwise be cut at the width.
	if len(msg) <= width {
		return msg
	}
	cut := strings.LastIndex(msg[:width-1], " ")
	if cut <= 0 {
		cut = width - 1
	}
	return strings.TrimSpace(msg[:cut]) + "…"
}

// writeEvidence prints what makes a run defensible: which tools ran, what they measured against,
// what the scan did to its targets, which revision it read, and what it cost.
//
// Not in the default view. Each of these is justified on its own and together they are most of what
// precedes the findings, a developer opening a terminal is asking what to fix, and answers to a
// question they have not asked push the answer to the one they have off the screen.
//
// Three things deliberately stay in the default view instead of moving here, because they are not
// evidence but warnings, and removing them would change what the report means: a control that did
// not run, a finding suppressed with nobody accepting it, and a cache hit on a mutable reference.
func writeEvidence(w io.Writer, col tui.Painter, d Data, indent string) {
	if lines := toolBuildLines(d.Tools); len(lines) > 0 {
		for _, l := range lines {
			_, _ = fmt.Fprintf(w, "%s%s\n", indent, col.Paint(cDim, l))
		}
		_, _ = fmt.Fprintln(w)
	}

	if l := runLine(d.Run.Stats); l != "" {
		_, _ = fmt.Fprintf(w, "%s%s\n\n", indent, col.Paint(cDim, l))
	}

	if rows := repositoryRows(d.Repositories); len(rows) > 0 {
		_, _ = fmt.Fprintf(w, "%s%s\n", indent, col.Paint(cDim, "Scanned"))
		t := tui.NewTable(col).Indent(indent + "  ")
		for _, r := range rows {
			t.Row(tui.Styled(cDim, r[0]), tui.Styled(cDim, r[1]))
		}
		t.Render(w)
		_, _ = fmt.Fprintln(w)
	}

	// What the run wrote, where the rest of what it did is. Not beside the findings: Draugr writes
	// a report, a SARIF file and whatever else the descriptor asked for without announcing any of
	// them, and one artifact naming itself there reads as the important one rather than as the
	// one that happened to have a line.
	if line := sbomLine(d.Run.SBOMs); line != "" {
		_, _ = fmt.Fprintf(w, "%s%s\n\n", indent, col.Paint(cDim, line))
	}

	if line := exploitabilityLine(d.Exploitability); line != "" {
		_, _ = fmt.Fprintf(w, "%s%s\n\n", indent, col.Paint(cDim, line))
	}

	var provenance []string
	if line := descriptorLine(d.Descriptor); line != "" {
		provenance = append(provenance, line)
	}
	if line := ciLine(d.CI); line != "" {
		provenance = append(provenance, line)
	}
	for _, l := range provenance {
		_, _ = fmt.Fprintf(w, "%s%s\n", indent, col.Paint(cDim, l))
	}
	if len(provenance) > 0 {
		_, _ = fmt.Fprintln(w)
	}

	// Last, because a verdict is the thing everything above stands behind, and the gate is what
	// turned findings into that verdict.
	writeGate(w, col, d, true, indent)
}

// unscannedDetail says what a component has that nothing managed to examine.
//
// Counted by kind and against what the component declared, because three lines naming each registry
// path is not what a reader needs here, the control's error above already carries why, and this row
// answers what, and how much of it.
func unscannedDetail(us []engine.Unscanned, declared map[string]int) string {
	byKind := map[string]int{}
	for _, u := range us {
		kind := u.Kind
		if kind == "" {
			kind = "target"
		}
		byKind[kind]++
	}
	kinds := make([]string, 0, len(byKind))
	for kind := range byKind {
		kinds = append(kinds, kind)
	}
	sort.Strings(kinds)
	parts := make([]string, 0, len(kinds))
	for _, kind := range kinds {
		// "3 of 3" and "3 of 30" are different situations. One is a component nothing looked at, the
		// other a gap in one that was mostly covered. And the bare count reads as the first either way.
		if total := declared[kind]; total > 0 {
			parts = append(parts, fmt.Sprintf("%d/%d %s", byKind[kind], total, noun(total, kind)))
			continue
		}
		parts = append(parts, plural(byKind[kind], kind))
	}
	return strings.Join(parts, ", ") + " not scanned"
}

// writeGate says what policy the verdict was produced under.
//
// In the default view only when the gate lets through something a default gate would have caught,
// because that is the case a reader cannot see any other way: a pass under a narrowed gate looks
// exactly like a pass under a full one, and --no-gate exits 0 on a verdict of FAIL. A stricter gate
// needs no announcement. It can only fail more, and the failure says so itself.
//
// Under --evidence the gate is stated whatever it is, including when it is the default. An
// auditor's question about a verdict is what it was measured against, and "the default" is an
// answer only if the report says so rather than leaving it to be assumed.
func writeGate(w io.Writer, col tui.Painter, d Data, full bool, indent string) {
	g := d.Gate
	// Printed unasked when it is not the default, and always under --evidence. A rule nobody chose
	// is not news; a rule somebody chose qualifies every pass above it.
	if !full && !g.chosen() {
		return
	}

	if g.Disabled {
		// The strongest case in the file: the command exits 0 on a verdict of FAIL, so anything
		// reading the exit code is told the opposite of what this report says.
		_, _ = fmt.Fprintf(w, "%s%s\n\n", indent, col.Paint(tui.StyleAccent,
			"Gate off (--no-gate) · this verdict does not decide the exit code."))
		return
	}

	// One question, so one clause. The gate asks either what a scanner called the flaw or what
	// band it lands in here, and a line that could say both left a reader with two candidates for
	// why their build was red.
	var line string
	if g.Threshold == "" && len(g.PerControl) == 0 {
		band := g.FailOnPriority
		if band == "" {
			band = norn.DefaultPriority
		}
		line = fmt.Sprintf("Gate: fails on %s", band)
		if overrides := renderOverrides(g.PerControlBand, ""); overrides != "" {
			line += " · " + overrides
		}
	} else {
		line = fmt.Sprintf("Gate: fails on %s severity", g.Threshold)
		if overrides := gateOverrides(g); overrides != "" {
			line += " · " + overrides
		}
	}

	// Dimmed when it is only a record, lit when it is a caveat. A narrowed gate qualifies every
	// pass in the report above it, and dimming it puts it below the reading threshold of the
	// thing it qualifies.
	style := cDim
	if g.weakened() {
		style = tui.StyleAccent
	}
	_, _ = fmt.Fprintf(w, "%s%s\n\n", indent, col.Paint(style, line+"."))
}

// gateOverrides renders the per-control thresholds in a stable order.
//
// Named rather than counted: which control was exempted is the whole content of the exemption,
// and "2 controls" answers nothing a reader wanted to know.
func gateOverrides(g GateSettings) string {
	as := make(map[string]string, len(g.PerControl))
	for name, sev := range g.PerControl {
		as[name] = string(sev)
	}
	return renderOverrides(as, " severity")
}

// renderOverrides is the same in either vocabulary: the per-control thresholds, named, in a stable
// order.
func renderOverrides(overrides map[string]string, unit string) string {
	if len(overrides) == 0 {
		return ""
	}
	controls := make([]string, 0, len(overrides))
	for name := range overrides {
		controls = append(controls, name)
	}
	sort.Strings(controls)

	parts := make([]string, 0, len(controls))
	for _, name := range controls {
		// A statement rather than an exception to the sentence before it. "fails on P1, except
		// licenses on P2" asks a reader to hold the first clause and subtract from it; the control
		// says what it fails on, in the same words the gate above it used.
		parts = append(parts, fmt.Sprintf("%s fails on %s%s", name, overrides[name], unit))
	}
	return strings.Join(parts, " · ")
}

// descriptorLine says which descriptor drove the run and whether it was one file.
//
// The digest first, because it is the part that answers a question: two runs carrying the same one
// were asked the same thing. Fragments are counted rather than listed. The full list is in
// report.json, and an auditor comparing files is reading that, not a terminal.
func descriptorLine(d *skald.DescriptorRef) string {
	if d == nil || len(d.Sources) == 0 {
		return ""
	}
	root := d.Sources[0].Path
	for _, s := range d.Sources {
		if s.Root {
			root = s.Path
			break
		}
	}
	line := "Descriptor: " + root
	if n := len(d.Sources) - 1; n > 0 {
		line += fmt.Sprintf(" + %s", plural(n, "fragment"))
	}
	if d.Digest != "" {
		// Named, because eight characters of hex is not self-evidently anything. It is the digest
		// of the merged document, fragments folded in, which is what makes two runs comparable when
		// the descriptor is assembled from several files.
		line += " · merged digest " + shortDigest(d.Digest)
	}
	return line
}

// shortDigest keeps a digest recognizable without spending a line on it. Twelve hex characters is
// what git settled on for the same job.
func shortDigest(d string) string {
	hex := strings.TrimPrefix(d, "sha256:")
	if len(hex) > 12 {
		hex = hex[:12]
	}
	return hex
}

// ciLine names the job, so a report read later can be traced back to the pipeline that produced it.
func ciLine(c *ci.Context) string {
	if c == nil || !c.Detected() {
		return ""
	}
	line := "CI: " + c.System
	for _, part := range []string{c.Repository, jobPath(c), c.JobID()} {
		if part != "" {
			line += " · " + part
		}
	}
	return line
}

// jobPath is "workflow/job", or whichever of the two the platform names.
func jobPath(c *ci.Context) string {
	switch {
	case c.Workflow != "" && c.Job != "":
		return c.Workflow + "/" + c.Job
	case c.Workflow != "":
		return c.Workflow
	default:
		return c.Job
	}
}
