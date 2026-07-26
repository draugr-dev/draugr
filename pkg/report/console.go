package report

import (
	"fmt"
	"io"
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

	if len(d.Verdict.Controls) > 0 {
		_, _ = fmt.Fprintln(w, "Controls:")
		width := 0
		for _, c := range d.Verdict.Controls {
			if len(c.Control) > width {
				width = len(c.Control)
			}
		}
		for _, c := range d.Verdict.Controls {
			v, vc := "pass", cDim
			if c.Verdict == norn.Fail {
				v, vc = "FAIL", cFail
			}
			_, _ = fmt.Fprintf(w, "  %s  %s  %s\n",
				fmt.Sprintf("%-*s", width, c.Control),
				col.Paint(vc, fmt.Sprintf("%-4s", v)),
				bandsText(col, s.bands[c.Control]))
		}
		_, _ = fmt.Fprintln(w)
	}

	if len(s.findings) == 0 {
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
func shortRuleID(id string) string {
	r := []rune(id)
	if len(r) <= ruleIDWidth {
		return id
	}
	return "…" + string(r[len(r)-(ruleIDWidth-1):])
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
