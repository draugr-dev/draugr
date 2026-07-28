package report

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/sarif"
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
		for _, name := range erroredOnly(d) {
			_, _ = fmt.Fprintf(w, "  %s  %s  %s\n",
				fmt.Sprintf("%-*s", width, name),
				col.Paint(cFail, fmt.Sprintf("%-5s", "ERROR")),
				col.Paint(cDim, "did not run"))
		}
		for _, name := range sortedKeys(errored) {
			for _, msg := range errored[name] {
				_, _ = fmt.Fprintf(w, "  %s%s\n", strings.Repeat(" ", width+2),
					col.Paint(cDim, findingSummary(msg)))
			}
		}
		_, _ = fmt.Fprintln(w)
	}

	// Evidence, not a control — so a line rather than a row in the table above, where every
	// entry means "checked, and here is the verdict". Printed before the early returns below,
	// because a clean scan still produced the inventory and should say so.
	if n := len(d.Run.SBOMs); n > 0 {
		_, _ = fmt.Fprintf(w, "%s\n\n", col.Paint(cDim,
			fmt.Sprintf("SBOM: %s (%s)", plural(n, "document"), d.Run.SBOMs[0].Format)))
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
	heading := "Fix first:"
	if s.minPriority != "" {
		// Say what was filtered, or the short list reads as a contradiction of the counts above.
		heading = fmt.Sprintf("Fix first (%s and above", strings.ToUpper(s.minPriority))
		if s.hidden > 0 {
			heading += fmt.Sprintf("; %d lower-priority finding(s) hidden", s.hidden)
		}
		heading += "):"
	}
	_, _ = fmt.Fprintln(w, heading)
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

// fixFirstHeader labels the ranked-findings columns. It's included in the width
// calculation and printed dimmed so the table is self-explanatory — newcomers can see at a
// glance which control and scanner flagged each finding.
var fixFirstHeader = []string{"Priority", "Severity", "Score", "Rule", "Control", "Scanner", "Location"}

// renderFixFirst prints the ranked findings as an aligned table with a header row, each
// finding's own message on a dimmed line beneath it.
func renderFixFirst(w io.Writer, col tui.Painter, fs []finding) {
	t := tui.NewTable(col, fixFirstHeader...).Indent("  ")
	for _, f := range fs {
		t.RowWithNote(findingSummary(f.message),
			tui.Styled(priorityColor(f.priority), dash(f.priority)),
			tui.Styled(severityColor(f.severity), string(f.severity)),
			tui.PlainCell(scoreStr(f)),
			// A rule id names a finding; it doesn't explain it. The link is where a reader
			// finds out what it means, and it costs no width.
			tui.Cell{Text: shortRuleID(f.ruleID), URL: f.helpURI},
			tui.PlainCell(f.control),
			tui.PlainCell(dash(f.tool)),
			tui.PlainCell(dash(f.location)),
		)
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

// erroredOnly names controls that failed without producing any report at all, so they have no
// entry in the verdict to hang an ERROR on.
func erroredOnly(d Data) []string {
	seen := make(map[string]bool, len(d.Verdict.Controls))
	for _, c := range d.Verdict.Controls {
		seen[c.Control] = true
	}
	var out []string
	for name := range d.Run.ScanErrors {
		if !seen[name] {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
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
