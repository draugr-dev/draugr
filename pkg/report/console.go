package report

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/sbom"
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
)

func (consoleReporter) Render(w io.Writer, d Data) error {
	s := summarize(d)
	col := tui.For(w)

	verdict, vcol := "PASS", cPass
	if s.verdict == norn.Fail {
		verdict, vcol = "FAIL", cFail
	}
	_, _ = fmt.Fprintf(w, "Draugr — %s", col.Paint(vcol, verdict))
	if d.Release.Name != "" {
		rel := d.Release.Name
		if d.Release.Version != "" {
			rel += " " + d.Release.Version
		}
		_, _ = fmt.Fprintf(w, "   %s", col.Paint(cDim, "("+rel+")"))
	}
	// Beside the verdict rather than below it. A reader who takes one line from this report takes
	// this one, and a PASS covering a fifth of the release must not be readable on its own.
	if note := scopeNote(d); note != "" {
		_, _ = fmt.Fprintf(w, "   %s", col.Paint(cAccent, note))
	}
	_, _ = fmt.Fprint(w, "\n\n")

	if s.prioritized {
		_, _ = fmt.Fprintf(w, "Priorities:  %s   %s   %s   %s\n\n",
			col.Paint(priorityColor("P1"), fmt.Sprintf("P1 %d", s.p1)),
			col.Paint(priorityColor("P2"), fmt.Sprintf("P2 %d", s.p2)),
			fmt.Sprintf("P3 %d", s.p3),
			col.Paint(cDim, fmt.Sprintf("P4 %d", s.p4)))
	}

	// Controls that errored are listed alongside the ones that ran. A control that produced no
	// report has no verdict entry to hang a row on, so listing only the ones that succeeded
	// makes the output shorter exactly when something has gone wrong — which reads as a clean
	// run to anyone who does not already know how many controls to expect.
	errored := d.Run.ScanErrors
	if len(d.Verdict.Controls) > 0 || len(errored) > 0 {
		_, _ = fmt.Fprintln(w, "Controls:")
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
				// Wrapped rather than clamped to one line. A clamp suits a tool's own stderr,
				// which can be a whole usage screen — but these are Draugr's sentences too, and
				// the half a reader acts on is the end of them.
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
			v, vc := "pass", cDim
			if c.Verdict == norn.Fail {
				v, vc = "FAIL", cFail
			}
			if _, bad := errored[c.Control]; bad {
				// It produced findings *and* something failed: what it did report is partial.
				v, vc = "ERROR", cFail
			}
			_, _ = fmt.Fprintf(w, "  %s  %s  %s\n",
				fmt.Sprintf("%-*s", width, c.Control),
				col.Paint(vc, fmt.Sprintf("%-5s", v)),
				bandsText(col, s.bands[c.Control]))
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
		// Both stay in the default view. They are coverage rather than provenance: what a control
		// was measured against carries what it did *not* cover — a spec-driven scan that skipped
		// the methods it was not allowed to send, a benchmark that could decide 20 of 34 checks —
		// and a partial scan reading as a complete one is the failure this whole block exists to
		// prevent. The tool builds, job counts and scanned revision are the provenance, and those
		// travel with the evidence.
		writeMeasuredAgainst(w, col, d, width)
		writeNotMeasured(w, col, d, width)
		_, _ = fmt.Fprintln(w)
	}

	writeComponents(w, col, d)

	// Evidence, not a control — so a line rather than a row in the table above, where every
	// entry means "checked, and here is the verdict". Printed before the early returns below,
	// because a clean scan still produced the inventory and should say so.
	// Silent suppression is the thing to avoid: an excluded finding that leaves no trace reads
	// exactly like one that was never found. The count says otherwise, and each reason travels
	// in the SARIF next to the result it justifies.
	if line := suppressionLine(d); line != "" {
		// Not dimmed. This is the one line saying part of the report was set aside, and greying
		// it out put it below the reading threshold of the thing it qualifies — a reader
		// skimming a clean-looking report was the failure mode.
		_, _ = fmt.Fprintf(w, "%s\n\n", col.Paint(tui.StyleAccent, line))
	}

	// Findings a supplier's own analysis set aside, named separately and just as loudly. A
	// suppression the reader cannot see is the failure this whole section exists to prevent, and
	// one made by somebody outside the project is the case where seeing it matters most.
	if line := importedLine(d); line != "" {
		_, _ = fmt.Fprintf(w, "%s\n\n", col.Paint(tui.StyleAccent, line))
	}

	// A supplier statement that matched nothing is doing nothing and looks exactly like one that
	// worked — usually the supplier and the scanner name a package differently, which is a real
	// finding about the document rather than a quiet no-op.
	if n := len(d.Run.UnmatchedClaims); n > 0 {
		_, _ = fmt.Fprintf(w, "%s\n\n", col.Paint(tui.StyleMuted, fmt.Sprintf(
			"%s in a supplier's VEX matched nothing in this scan", plural(n, "statement"))))
	}

	// An exclusion past its date stops suppressing, and says so. A finding that used to be
	// accepted reappearing with no explanation is the confusing half of expiry; this is the
	// other half.
	if lapsed := d.Run.LapsedExclusions; len(lapsed) > 0 {
		_, _ = fmt.Fprintf(w, "%s\n", col.Paint(cFail,
			fmt.Sprintf("%s expired and no longer suppressing:", plural(len(lapsed), "exclusion"))))
		for _, e := range lapsed {
			who := e.AcceptedBy
			if who == "" {
				who = "unattributed"
			}
			_, _ = fmt.Fprintf(w, "  %s\n", col.Paint(cDim,
				fmt.Sprintf("expired %s, accepted by %s — %s", e.Expires, who, findingSummary(e.Reason))))
		}
		_, _ = fmt.Fprintln(w)
	}

	// An exclusion that matched nothing is doing nothing, and reads exactly like one that is
	// working. Usually a typo, a rule id that moved, or a finding someone fixed and forgot to
	// stop excusing — and in every case the descriptor claims a decision it is not making.
	if unmatched := d.Run.UnmatchedExclusions; len(unmatched) > 0 {
		_, _ = fmt.Fprintf(w, "%s\n", col.Paint(tui.StyleAccent,
			fmt.Sprintf("%s matched nothing in this run:", plural(len(unmatched), "exclusion"))))
		for _, e := range unmatched {
			_, _ = fmt.Fprintf(w, "  %s\n", col.Paint(cDim, excludeSummary(e)))
		}
		_, _ = fmt.Fprintln(w)
	}

	if !d.Evidence {
		writeGate(w, col, d, false)
	}

	// Everything from here to the findings answers "can I trust this run" rather than "what did
	// it find", and the second question is the one a reader came with. Behind --evidence so the
	// default view is the findings, and an auditor asks for the rest — see writeEvidence.
	if d.Evidence {
		writeEvidence(w, col, d, s)
	}

	if len(s.findings) == 0 {
		// A clean run still did whatever it did and still produced whatever it produced, and
		// both are worth saying: an SBOM nobody is told about is one nobody uses, and a scan
		// that created something in a cluster owes a record of it whatever the verdict.
		writeEffects(w, col, s, d)
		// "No findings ✓" after a control that didn't run would be the same false reassurance
		// the ERROR row exists to prevent.
		if len(errored) > 0 {
			_, _ = fmt.Fprintln(w, col.Paint(cDim,
				"No findings from the controls that ran — see the errors above."))
			return nil
		}
		_, _ = fmt.Fprintln(w, col.Paint(cPass, "No findings. ✓"))
		return nil
	}

	limit := consoleFixFirstLimit(d.TopN)

	if d.GroupActions {
		return writeActions(w, col, s, d, limit)
	}

	shown := s.findings
	if limit >= 0 && len(shown) > limit {
		shown = shown[:limit]
	}
	_, _ = fmt.Fprintln(w, fixFirstHeading(s, len(shown), len(s.findings)))
	renderFixFirst(w, col, shown)

	// Two different readers, two different answers. Somebody looking at a truncated list wants
	// the rest of *this* list, and answering that with a machine format sends them to a document
	// they did not ask for — human-readable is the default here, so the follow-up should be too.
	if len(shown) < len(s.findings) {
		_, _ = fmt.Fprintf(w, "\n… and %d more finding(s).\n", len(s.findings)-len(shown))
		_, _ = fmt.Fprintln(w, col.Paint(cDim,
			"Use --top 0 to list them all, or --group action to see them as things to do."))
	} else {
		_, _ = fmt.Fprint(w, "\n")
	}
	writeEffects(w, col, s, d)
	_, _ = fmt.Fprintln(w, col.Paint(cDim,
		"Machine-readable: --format json|sarif, or -o <dir> for report.json + results.sarif."))
	// The rule id in a row is enough to rank a finding and not enough to decide anything. What
	// the check means and what to change is in the report already; without this the reader is
	// sent to whatever a search engine offers for the identifier.
	_, _ = fmt.Fprintln(w, col.Paint(cDim,
		"`draugr explain <rule>` says what a finding means and how to fix it."))
	return nil
}

// writeEffects records what the run did to its targets beyond reading them.
//
// Not evidence and not hidden: this is what Draugr did to somebody's systems, and a scan that
// created a Job in a cluster or sent traffic to a live endpoint should say so where the verdict
// is read. Near the end because it is a receipt rather than an instruction — the reader acts on
// the findings above and wants this on the way past.
func writeEffects(w io.Writer, col tui.Painter, s summary, d Data) {
	wrote := false
	for _, e := range s.effects {
		_, _ = fmt.Fprintf(w, "%s\n", col.Paint(cDim, fmt.Sprintf("%s: %s", e.Kind, e.Detail)))
		wrote = true
	}
	// What the descriptor asked for and this run could not deliver. With the receipts because it
	// is one: a record of what did not happen, where somebody would otherwise assume it did.
	if line := undeliveredLine(d.UndeliveredReports); line != "" {
		_, _ = fmt.Fprintf(w, "%s\n", col.Paint(cMedium, line))
		wrote = true
	}
	// Below the findings, not above them. It qualifies what was just read rather than introducing
	// it, and a caveat placed before the fix list competes with the thing it is a caveat about.
	// Not dim, unlike its neighbors here: a reader deciding whether to trust these findings
	// should not have to notice it.
	if line := unpinnedCacheLine(d.Run.Stats.UnpinnedCacheHits); line != "" {
		_, _ = fmt.Fprintf(w, "%s\n", col.Paint(cMedium, line))
		wrote = true
	}
	// The inventory is a receipt of the same kind: somebody who asked for an SBOM wants to know
	// it was written, and a clean scan still produced one.
	if line := sbomLine(d.Run.SBOMs); line != "" {
		_, _ = fmt.Fprintf(w, "%s\n", col.Paint(cDim, line))
		wrote = true
	}
	if wrote {
		_, _ = fmt.Fprintln(w)
	}
}

// fixFirstHeading names what the table below it actually contains.
//
// "Fix first" describes a shortlist, and the default is one — ten of however many, worst first.
// With --top 0 the same words sit above every finding in the run, where they stop being a
// recommendation and become a label, and the reader loses the thing the default was telling
// them: that these few are where to start.
//
// Both headings say the order is meaningful, because that is true either way and is not obvious
// from a table that otherwise looks like any other scanner's dump.
func fixFirstHeading(s summary, shown, total int) string {
	filter := ""
	if s.minPriority != "" {
		// Say what was filtered, or a short list reads as a contradiction of the counts above.
		filter = fmt.Sprintf(", %s and above", strings.ToUpper(s.minPriority))
		if s.hidden > 0 {
			filter += fmt.Sprintf("; %d lower-priority finding(s) hidden", s.hidden)
		}
	}
	if shown < total {
		return fmt.Sprintf("Fix first (top %d of %d, by priority%s):", shown, total, filter)
	}
	if total == 1 {
		return fmt.Sprintf("The finding (by priority%s):", filter)
	}
	return fmt.Sprintf("All %d findings, by priority%s:", total, filter)
}

// fixFirstHeader labels the ranked-findings columns. It's included in the width
// calculation and printed dimmed so the table is self-explanatory — newcomers can see at a
// glance which control and scanner flagged each finding.
// Component sits before Location because a path answers "where inside" and, once a descriptor
// has more than one component, the reader needs "which one" first — two components can carry the
// same path. Omitted entirely when nothing has one, so a single-component project keeps the
// narrower frame it had.
var fixFirstHeader = []string{"Priority", "Severity", "Score", "Rule", "Control", "Scanner", "Component", "Location"}

// fixFirstHeaderNoComponent is the frame for a run where no finding has a component: a
// project-scoped control, or a zero-config scan. An always-present column of dashes costs width
// and tells the reader nothing.
var fixFirstHeaderNoComponent = []string{"Priority", "Severity", "Score", "Rule", "Control", "Scanner", "Location"}

// manyComponents reports whether the findings span more than one component.
//
// One component repeats the same value on every row and answers a question nobody has — the
// release header already says what was scanned. The column earns its width only when it
// distinguishes findings from each other, which is the case that prompted it: several components
// with paths that look alike.
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

// insertBefore puts a column immediately before the named one, appending if it is absent.
func insertBefore(header []string, before, col string) []string {
	out := make([]string, 0, len(header)+1)
	for _, h := range header {
		if h == before {
			out = append(out, col)
		}
		out = append(out, h)
	}
	if len(out) == len(header) {
		out = append(out, col)
	}
	return out
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
func renderFixFirst(w io.Writer, col tui.Painter, fs []finding) {
	withComponent := manyComponents(fs)
	// A component may hold several repositories, and paths are repository-relative — so the same
	// file in two of them produces rows identical in every column. The reader sees a duplicate
	// and has no way to learn otherwise.
	withRepository := manyRepositories(fs)
	header := fixFirstHeaderNoComponent
	if withComponent {
		header = fixFirstHeader
	}
	if withRepository {
		// Before Location for the same reason Component is: a path answers "where inside", and
		// "which project" comes first.
		header = insertBefore(header, "Location", "Repository")
	}
	t := tui.NewTable(col, header...).Indent("  ")
	for _, f := range fs {
		cells := []tui.Cell{
			tui.Styled(priorityColor(f.priority), dash(f.priority)),
			tui.Styled(severityColor(f.severity), string(f.severity)),
			tui.PlainCell(scoreStr(f)),
			// A rule id names a finding; it doesn't explain it. The link is where a reader
			// finds out what it means, and it costs no width.
			{Text: shortRuleID(f.ruleID), URL: f.helpURI},
			tui.PlainCell(f.control),
			tui.PlainCell(dash(f.tool)),
		}
		if withComponent {
			cells = append(cells, tui.PlainCell(dash(f.component)))
		}
		if withRepository {
			cells = append(cells, tui.PlainCell(dash(shortRepository(f.repository))))
		}
		cells = append(cells, tui.PlainCell(dash(f.location)))
		t.RowWithNotes([]string{
			findingSummary(f.message),
			escalationNote(f.escalation),
			priorityFloorNote(f.priorityFloor),
			historicalNote(f.historical),
		}, cells...)
	}
	t.Render(w)
}

// ruleIDWidth caps the Rule column. Some scanners use long namespaced ids — Semgrep's run past
// a hundred characters — and one of those pushes every column after it off the screen, which
// costs the reader the location and the scanner to show a namespace they didn't need.
const ruleIDWidth = 44

// shortRuleID fits a rule id into the column by dropping the front. Namespaced ids put the
// general part first and the specific part last ("yaml.github-actions.security.<name>"), so the
// tail is the half worth keeping. The full id stays in the JSON and SARIF reports, and the
// hyperlink on it still resolves.
//
// It cuts on a dot where one fits. Cutting purely by width lands mid-word and the result reads
// as corruption rather than truncation — "…ction-tag.github-actions-mutable-action-tag" invites
// the reader to wonder what went wrong, where "…github-actions-mutable-action-tag" plainly says
// there is more in front.
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
			// One unbroken token longer than the line — a URL, or a path with no spaces in it.
			// Emitted whole and overflowing rather than split at the margin: the reason a URL is
			// in a failure message is so somebody can paste it somewhere, and one broken across
			// two lines cannot be pasted. A long line is untidy; a severed URL is unusable.
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
// the unit exposure and criticality are declared on, so it is the unit someone is deciding
// about — and with several of them, "sca FAIL" says the project has a problem and stops.
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

	_, _ = fmt.Fprintln(w, "Components:")
	for _, c := range d.Components {
		verdict, style := "pass", cPass
		if c.Verdict == norn.Fail {
			verdict, style = "FAIL", cFail
		}
		// A component nothing was able to look at has not passed. Its scans failed, so "no
		// findings" is true only in the sense that none were possible — which is the reading
		// this row must not invite, and the same reason a component the scope excluded is
		// listed apart rather than among the passes.
		if len(c.Unscanned) > 0 && c.Findings == 0 {
			verdict, style = "ERROR", cFail
		}
		detail := col.Paint(cDim, "no findings")
		if c.Findings > 0 {
			detail = componentBands(col, c.Priorities)
			if len(c.Controls) > 0 {
				detail += "  " + col.Paint(cDim, strings.Join(c.Controls, ", "))
			}
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
				col.Paint(cDim, "not scanned  (--components)"))
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
	styles := [4]tui.Style{cFail, tui.StyleAccent, tui.StyleNone, cDim}
	var parts []string
	for i, n := range p {
		if n == 0 {
			continue
		}
		parts = append(parts, col.Paint(styles[i], fmt.Sprintf("%s %d", labels[i], n)))
	}
	if len(parts) == 0 {
		return col.Paint(cDim, "no priorities set")
	}
	return strings.Join(parts, "  ")
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
	return strings.Join(parts, "; ") + " — " + findingSummary(e.Reason)
}

// bandsText renders per-control severity counts, omitting empty bands, each colorized.
func bandsText(col tui.Painter, b sevCounts) string {
	var parts []string
	if b.critical > 0 {
		parts = append(parts, col.Paint(cCritical, fmt.Sprintf("%d critical", b.critical)))
	}
	if b.high > 0 {
		parts = append(parts, col.Paint(cHigh, fmt.Sprintf("%d high", b.high)))
	}
	if b.medium > 0 {
		parts = append(parts, col.Paint(cMedium, fmt.Sprintf("%d medium", b.medium)))
	}
	if b.low > 0 {
		parts = append(parts, col.Paint(cLow, fmt.Sprintf("%d low", b.low)))
	}
	if len(parts) == 0 {
		return col.Paint(cDim, "no findings")
	}
	return strings.Join(parts, "  ")
}

func priorityColor(p string) tui.Style {
	switch strings.ToUpper(p) {
	case "P1":
		return cFail
	case "P2":
		return cMedium
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
	_, _ = fmt.Fprintln(w, "Measured against:")
	for _, l := range lines {
		text := l.Label()
		if l.Detail != "" {
			text += " — " + l.Detail
		}
		_, _ = fmt.Fprintf(w, "  %s  %s\n", fmt.Sprintf("%-*s", width, l.Control), col.Paint(cDim, text))
	}
}

// writeNotMeasured names a scanner that was planned for a component and then not run.
//
// Beside "Measured against" because it is the same question answered the other way, and a reader
// deciding what a PASS is worth needs both halves. Without it a scanner that could not answer the
// question a component asked looks exactly like one that answered it and found nothing — which is
// the difference this report exists to make visible.
func writeNotMeasured(w io.Writer, col tui.Painter, d Data, width int) {
	if len(d.Run.Skipped) == 0 {
		return
	}
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, "Not measured:")
	for _, sk := range d.Run.Skipped {
		text := sk.Scanner
		if sk.Component != "" {
			text += " on " + sk.Component
		}
		if sk.Reason != "" {
			text += " — " + sk.Reason
		}
		_, _ = fmt.Fprintf(w, "  %s  %s\n", fmt.Sprintf("%-*s", width, sk.Control), col.Paint(cDim, text))
	}
}

// exploitabilityLine summarizes the feeds a run's severities were enriched from, or "" when
// there were none.
//
// Beside the SBOM line rather than in the findings table: it describes the run, and a reader
// asking "is this data current" is asking about the whole scan rather than any one result.
// exploitabilityLine names the feeds, their dates, and — the part a reader actually wants — what
// they did to this run.
//
// Dates alone say enrichment ran, not whether it changed anything, so the only way to find out
// was to read every finding looking for an escalation note and then wonder whether one had been
// missed. "nothing raised" is a real answer and it takes one word to give.
func exploitabilityLine(feeds []FeedProvenance, escalated int) string {
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
	effect := "nothing raised"
	if escalated > 0 {
		effect = fmt.Sprintf("%s raised", plural(escalated, "finding"))
	}
	return "Exploitability: " + strings.Join(parts, " · ") + " — " + effect
}

// unpinnedCacheLine names the images whose findings came from a cache entry that could not be
// content-addressed, or "" when none did.
//
// The cache is content-addressed, and a report that does not say where that held is a report
// claiming more than it knows. An image named by a tag alone has a stable key and unstable bytes:
// the tag may have been rebuilt since the entry was written, and the findings then describe an
// image that is no longer there — a pass over code nobody is running.
//
// It says what to do rather than only what happened, because both answers are one step away: pin
// the digest in the descriptor and the entry becomes content-addressed, or refuse the entry with
// --cache-require-digest and take the re-scan.
func unpinnedCacheLine(refs []string) string {
	if len(refs) == 0 {
		return ""
	}
	// A count, never a list. The rows carry the mark and say which findings this applies to, so
	// naming the references again here answers a question already answered — and on a descriptor
	// with dozens of images it is a list nobody reads at the foot of the one they do.
	//
	// What the count adds is scale: one image out of thirty is a different report from thirty out
	// of thirty, and that is the part the rows cannot say. Which ones, for a run with no findings
	// to mark, is in the JSON and in --evidence.
	return fmt.Sprintf("from cache: %s reused on a tag — may describe an earlier build. Pin a digest.",
		plural(len(refs), "image"))
}

// escalationNote is the line under a finding saying why it outranks its severity, or "" when
// nothing moved it.
//
// Says what the finding was *ranked* as rather than "raised from x": the Severity column keeps
// showing what the scanner reported, because that is what the scanner reported. A note reading
// "raised from high" beside a row reading "high" describes nothing. What the reader needs is why
// a P1 is sitting on a high row, and the answer is that it was ranked as critical.
//
// Under the finding rather than in a column because it is the answer to a question only some
// rows provoke, and a column of mostly-dashes costs every row width to serve a few.
func escalationNote(e *sarif.Escalation) string {
	if e == nil {
		return ""
	}
	out := "↑ ranked as " + string(e.To) + " — " + e.Detail
	if e.AsOf != "" {
		out += " (" + e.AsOf + ")"
	}
	return out
}

// priorityFloorNote is the line under a finding saying why it outranks its component's
// classification, or "" when the classification accounts for the band.
//
// Without it the band is unaccountable: a reader who knows this component is internal and
// supporting, and reads P2 beside it, has no way to reconstruct the answer and has to take the
// ranking on trust. The ranking is the thing they are being asked to act on.
func priorityFloorNote(reason string) string {
	if reason == "" {
		return ""
	}
	return "↑ " + reason
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
	return "↩ in git history — path as it was then. Rotate it; deleting it does not unpublish it."
}

// runLine accounts for the run: how long it took, and how much of it was avoided.
//
// The engine has recorded all of this since caching was added and nothing showed it to the person
// who ran the scan. That makes `--cache-dir` unverifiable by the only means available at a
// terminal — the run is faster, and whether the cache did it or the registry was warm is a
// question the output does not answer. A count of hits is the answer, and it costs one line.
//
// Wall-clock rather than the sum of the jobs, because jobs run concurrently and their sum is a
// number that matches nothing the reader experienced.
func runLine(st engine.Stats) string {
	if st.Jobs == 0 || st.Duration <= 0 {
		return ""
	}
	line := fmt.Sprintf("Ran %s in %s", plural(st.Jobs, "job"), st.Duration.Round(time.Millisecond))
	var savings []string
	if st.CacheHits > 0 {
		savings = append(savings, fmt.Sprintf("%d from cache", st.CacheHits))
	}
	// Deduped is a different saving and worth its own word: two components sharing a repository
	// plan two jobs, and one scan answers both. A reader counting jobs against scans otherwise
	// finds a discrepancy with no name.
	if st.Deduped > 0 {
		savings = append(savings, fmt.Sprintf("%d shared with an identical job", st.Deduped))
	}
	if len(savings) > 0 {
		line += " — " + strings.Join(savings, ", ")
	}
	if w := waitSummary(st.ToolWaits); w != "" {
		line += ", " + w
		if len(savings) == 0 {
			line = strings.Replace(line, ", "+w, " — "+w, 1)
		}
	}
	return line + "."
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
		other = append(other, label+" — "+t.Reason)
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

// repositoryLines say which repository was read, and at which commit.
//
// The reason a scan reads a committed revision rather than your working tree is so the report can
// name something reproducible. This is that name — without it the justification was asserted in
// the docs and never delivered in the output, and the only thing said out loud was a warning about
// which revision was *not* scanned.
func repositoryLines(repos []RepositoryProvenance) []string {
	if len(repos) == 0 {
		return nil
	}
	out := make([]string, 0, len(repos))
	for _, r := range repos {
		line := "Scanned: " + r.URL
		if r.WorkingTree {
			line += " working tree"
		}
		if rev := r.Short(); rev != "" {
			line += " at " + rev
		}
		switch {
		case r.WorkingTree && r.Uncommitted > 0:
			// The uncommitted work is the reason this scan was asked for, so it is included
			// rather than missing — and the result cannot be reproduced from the revision.
			line += fmt.Sprintf(" (%s, not reproducible)", plural(r.Uncommitted, "uncommitted file"))
		case r.Uncommitted > 0:
			// A clause, not an alarm. Uncommitted work is the normal state of a checkout somebody
			// is editing; what matters is knowing it is not in what you are reading.
			line += fmt.Sprintf(" (%s not included)", plural(r.Uncommitted, "uncommitted file"))
		}
		out = append(out, line)
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
// One row per action, each saying how many findings it clears and where. A reader deciding what
// to spend an afternoon on is choosing between actions, and a list of findings makes them do the
// grouping in their head — which for a library carrying a dozen CVEs is a dozen rows describing
// one upgrade.
func writeActions(w io.Writer, col tui.Painter, s summary, d Data, limit int) error {
	actions, external := groupActions(s.findings, d.Run.Stats.UnpinnedCacheHits)

	if len(actions) == 0 {
		// Everything found belongs to somebody else. Saying "no findings" would be false and
		// saying nothing would be worse, so say exactly that.
		_, _ = fmt.Fprintln(w, col.Paint(cDim, externalLine(external)))
		return nil
	}

	shown := actions
	if limit >= 0 && len(shown) > limit {
		shown = shown[:limit]
	}
	_, _ = fmt.Fprintf(w, "Fix first — %s %s %s:\n",
		plural(len(shown), "action"), clears(shown), plural(cleared(shown), "finding"))
	renderActions(w, col, shown)

	if len(shown) < len(actions) {
		_, _ = fmt.Fprintf(w, "\n… and %d more %s.\n", len(actions)-len(shown),
			noun(len(actions)-len(shown), "action"))
		_, _ = fmt.Fprintln(w, col.Paint(cDim,
			"Use --top 0 to list them all, or --group none to list every finding separately."))
	} else {
		_, _ = fmt.Fprint(w, "\n")
	}
	if len(external) > 0 {
		_, _ = fmt.Fprintln(w, col.Paint(cDim, externalLine(external)))
	}
	// The same tail as the ungrouped listing. Both paths end a report, so both owe the record of
	// what the run did and produced — a receipt that appears only in the view somebody is not
	// using is one nobody sees.
	writeEffects(w, col, s, d)
	_, _ = fmt.Fprintln(w, col.Paint(cDim,
		"Machine-readable: --format json|sarif, or -o <dir> for report.json + results.sarif."))
	// The rule id in a row is enough to rank a finding and not enough to decide anything. What
	// the check means and what to change is in the report already; without this the reader is
	// sent to whatever a search engine offers for the identifier.
	_, _ = fmt.Fprintln(w, col.Paint(cDim,
		"`draugr explain <rule>` says what a finding means and how to fix it."))
	return nil
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
	return fmt.Sprintf("%s on infrastructure operated by your provider (%s) — reported, "+
		"and not yours to fix.", plural(len(external), "finding"), strings.Join(names, ", "))
}

// renderActions draws the action rows.
func renderActions(w io.Writer, col tui.Painter, actions []action) {
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
		if detail := actionDetail(col, a, namedLocations); detail != "" {
			_, _ = fmt.Fprintf(w, "      %s\n", col.Paint(cDim, detail))
		}
	}
}

// actionDetail is the line under an action: where it applies, and a way into the findings.
//
// Grouping answers "what do I do" and takes away "what exactly is wrong", which is the question
// a reader has next and the one a rule identifier answers. One is named, linked to whatever the
// scanner published about it, and the rest are counted — a reader following a link is going to
// read one of them, and listing fifty-four identifiers to offer that choice fills the screen.
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
// Cutting mid-word leaves a fragment that reads as a different word — a truncated identifier or
// version looks like a real one, and a reader cannot tell which they are looking at. Where the
// line is a single long token there is no boundary to find, and cutting it is the only option.
func elide(msg string, width int) string {
	if width <= 1 {
		return "…"
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
// Not in the default view. Each of these is justified on its own and together they are most of
// what precedes the findings — a developer opening a terminal is asking what to fix, and answers
// to a question they have not asked push the answer to the one they have off the screen.
//
// Three things deliberately stay in the default view instead of moving here, because they are not
// evidence but warnings, and removing them would change what the report means: a control that did
// not run, a finding suppressed with nobody accepting it, and a cache hit on a mutable reference.
func writeEvidence(w io.Writer, col tui.Painter, d Data, s summary) {
	if lines := toolBuildLines(d.Tools); len(lines) > 0 {
		for _, l := range lines {
			_, _ = fmt.Fprintf(w, "%s\n", col.Paint(cDim, l))
		}
		_, _ = fmt.Fprintln(w)
	}

	if l := runLine(d.Run.Stats); l != "" {
		_, _ = fmt.Fprintf(w, "%s\n\n", col.Paint(cDim, l))
	}

	for _, l := range repositoryLines(d.Repositories) {
		_, _ = fmt.Fprintf(w, "%s\n", col.Paint(cDim, l))
	}
	if len(d.Repositories) > 0 {
		_, _ = fmt.Fprintln(w)
	}

	if line := exploitabilityLine(d.Exploitability, s.escalated); line != "" {
		_, _ = fmt.Fprintf(w, "%s\n\n", col.Paint(cDim, line))
	}

	// Last, because a verdict is the thing everything above stands behind, and the gate is what
	// turned findings into that verdict.
	writeGate(w, col, d, true)
}

// unscannedDetail says what a component has that nothing managed to examine.
//
// Counted by kind and against what the component declared, because three lines naming each
// registry path is not what a reader needs here — the control's error above already carries why,
// and this row answers what, and how much of it.
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
		// "3 of 3" and "3 of 30" are different situations — one is a component nothing looked
		// at, the other a gap in one that was mostly covered — and the bare count reads as the
		// first either way.
		if total := declared[kind]; total > 0 {
			parts = append(parts, fmt.Sprintf("%d/%d %s", byKind[kind], total, noun(total, kind)))
			continue
		}
		parts = append(parts, plural(byKind[kind], kind))
	}
	return strings.Join(parts, ", ") + " not scanned"
}

// undeliveredLine says which declared reports had nowhere to go.
//
// Named rather than counted, because the reader's next move is to decide whether they wanted that
// one — and there are rarely more than a handful in a descriptor.
func undeliveredLine(formats []string) string {
	if len(formats) == 0 {
		return ""
	}
	return fmt.Sprintf("config.reports declares %s and this run had nowhere to write %s — "+
		"pass -o <dir>, or add a publisher.",
		strings.Join(formats, ", "), them(len(formats)))
}

// them agrees the pronoun with the count.
func them(n int) string {
	if n == 1 {
		return "it"
	}
	return "them"
}

// writeGate says what policy the verdict was produced under.
//
// In the default view only when the gate lets through something a default gate would have caught,
// because that is the case a reader cannot see any other way: a pass under a narrowed gate looks
// exactly like a pass under a full one, and --no-gate exits 0 on a verdict of FAIL. A stricter
// gate needs no announcement — it can only fail more, and the failure says so itself.
//
// Under --evidence the gate is stated whatever it is, including when it is the default. An
// auditor's question about a verdict is what it was measured against, and "the default" is an
// answer only if the report says so rather than leaving it to be assumed.
func writeGate(w io.Writer, col tui.Painter, d Data, full bool) {
	g := d.Gate
	if !full && !g.weakened() {
		return
	}

	if g.Disabled {
		// The strongest case in the file: the command exits 0 on a verdict of FAIL, so anything
		// reading the exit code is told the opposite of what this report says.
		_, _ = fmt.Fprintf(w, "%s\n\n", col.Paint(tui.StyleAccent,
			"Gate off (--no-gate) — this verdict does not decide the exit code."))
		return
	}

	threshold := g.Threshold
	if threshold == "" {
		threshold = sarif.SeverityHigh
	}
	line := fmt.Sprintf("Gate: fails on %s", threshold)
	if g.FailOnPriority != "" {
		line += fmt.Sprintf(" or %s", g.FailOnPriority)
	}
	if overrides := gateOverrides(g); overrides != "" {
		line += ", except " + overrides
	}

	// Dimmed when it is only a record, lit when it is a caveat. A narrowed gate qualifies every
	// pass in the report above it, and dimming it puts it below the reading threshold of the
	// thing it qualifies.
	style := cDim
	if g.weakened() {
		style = tui.StyleAccent
	}
	_, _ = fmt.Fprintf(w, "%s\n\n", col.Paint(style, line+"."))
}

// gateOverrides renders the per-control thresholds in a stable order.
//
// Named rather than counted: which control was exempted is the whole content of the exemption,
// and "2 controls" answers nothing a reader wanted to know.
func gateOverrides(g GateSettings) string {
	if len(g.PerControl) == 0 {
		return ""
	}
	controls := make([]string, 0, len(g.PerControl))
	for name := range g.PerControl {
		controls = append(controls, name)
	}
	sort.Strings(controls)

	parts := make([]string, 0, len(controls))
	for _, name := range controls {
		parts = append(parts, fmt.Sprintf("%s on %s", name, g.PerControl[name]))
	}
	return strings.Join(parts, ", ")
}
