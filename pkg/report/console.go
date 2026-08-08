package report

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

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

	// Controls that errored are listed alongside the ones that ran. Previously a control whose
	// scanner was missing simply wasn't in Verdict.Controls, so it vanished from the report —
	// the output got shorter precisely when something had gone wrong.
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
		}
		// Controls that produced nothing at all have no verdict entry, so they're listed here.
		for _, name := range s.errored {
			_, _ = fmt.Fprintf(w, "  %s  %s  %s\n",
				fmt.Sprintf("%-*s", width, name),
				col.Paint(cFail, fmt.Sprintf("%-5s", "ERROR")),
				col.Paint(cDim, "did not run"))
		}
		for _, name := range sortedKeys(errored) {
			for _, msg := range dedupeMessages(errored[name]) {
				// Wrapped rather than clamped. The one-line clamp is right for a tool's own
				// stderr, which can be a usage screen — but these are also Draugr's own
				// sentences, and the clamp cut them at the clause that said what to do.
				for i, line := range wrapMessage(msg, messageWidth) {
					prefix := strings.Repeat(" ", width+2)
					if i > 0 {
						prefix += "  "
					}
					_, _ = fmt.Fprintf(w, "  %s%s\n", prefix, col.Paint(cDim, line))
				}
			}
		}
		writeMeasuredAgainst(w, col, d, width)
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

	// What the run did, not just what it found. A scan that probed a live endpoint should say so
	// where the verdict is read, rather than only in the docs that describe the control.
	for _, e := range s.effects {
		_, _ = fmt.Fprintf(w, "%s\n", col.Paint(cDim, fmt.Sprintf("%s: %s", e.Kind, e.Detail)))
	}
	if len(s.effects) > 0 {
		_, _ = fmt.Fprintln(w)
	}

	if lines := toolBuildLines(d.Tools); len(lines) > 0 {
		for _, l := range lines {
			_, _ = fmt.Fprintf(w, "%s\n", col.Paint(cDim, l))
		}
		_, _ = fmt.Fprintln(w)
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

	if line := sbomLine(d.Run.SBOMs); line != "" {
		_, _ = fmt.Fprintf(w, "%s\n\n", col.Paint(cDim, line))
	}

	if len(s.findings) == 0 {
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
	shown := s.findings
	if limit >= 0 && len(shown) > limit {
		shown = shown[:limit]
	}
	_, _ = fmt.Fprintln(w, fixFirstHeading(s, len(shown), len(s.findings)))
	renderFixFirst(w, col, shown)

	if len(shown) < len(s.findings) {
		_, _ = fmt.Fprintf(w, "\n… and %d more finding(s). ", len(s.findings)-len(shown))
	} else {
		_, _ = fmt.Fprint(w, "\n")
	}
	_, _ = fmt.Fprintln(w, col.Paint(cDim,
		"Use --format json for the full report, or -o <dir> for report.json + results.sarif."))
	return nil
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

// renderFixFirst prints the ranked findings as an aligned table with a header row, each
// finding's own message on a dimmed line beneath it.
func renderFixFirst(w io.Writer, col tui.Painter, fs []finding) {
	withComponent := manyComponents(fs)
	header := fixFirstHeaderNoComponent
	if withComponent {
		header = fixFirstHeader
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
			cut = width // one unbroken token, e.g. a path: split it rather than overflow
		}
		lines = append(lines, strings.TrimSpace(msg[:cut]))
		msg = strings.TrimSpace(msg[cut:])
		if len(lines) == maxMessageLines-1 {
			break
		}
	}
	if len(msg) > width {
		msg = strings.TrimSpace(msg[:width-1]) + "…"
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
		detail := col.Paint(cDim, "no findings")
		if c.Findings > 0 {
			detail = componentBands(col, c.Priorities)
			if len(c.Controls) > 0 {
				detail += "  " + col.Paint(cDim, strings.Join(c.Controls, ", "))
			}
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
func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
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

// exploitabilityLine summarises the feeds a run's severities were enriched from, or "" when
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
	return "↑ not damped by exposure — " + reason
}

// historicalNote says that a finding's location is a path in a commit rather than in the tree.
//
// Without it the location column is read as current, and a path that no longer exists reads as
// something already cleaned up. That inference is backwards: a credential reachable from any
// commit is still fetchable by anyone who can clone, so removing it from the tip is not
// remediation and the finding is not stale.
func historicalNote(historical bool) string {
	if !historical {
		return ""
	}
	return "↩ found in commit history — this path is as it was then, and may have moved or gone " +
		"since. Still needs rotating: removing it from the tip does not unpublish it."
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
