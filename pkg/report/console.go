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

// renderFixFirst prints the ranked findings as an aligned, colorized table with a header row.
// Columns are padded from the plain text so ANSI color codes don't skew the alignment.
func renderFixFirst(w io.Writer, col tui.Painter, fs []finding) {
	// rows[0] is the header; the rest are findings, each
	// [priority, severity, score, rule, control, scanner, location].
	rows := make([][]string, 0, len(fs)+1)
	rows = append(rows, fixFirstHeader)
	for _, f := range fs {
		rows = append(rows, []string{
			dash(f.priority), string(f.severity), scoreStr(f), f.ruleID,
			f.control, dash(f.tool), dash(f.location),
		})
	}
	widths := make([]int, len(fixFirstHeader))
	for _, r := range rows {
		for i, cell := range r {
			if len(cell) > widths[i] {
				widths[i] = len(cell)
			}
		}
	}
	// The last column is never padded — nothing follows it.
	pad := func(r []string, n int) string {
		if n == len(widths)-1 {
			return r[n]
		}
		return fmt.Sprintf("%-*s", widths[n], r[n])
	}

	h := rows[0]
	_, _ = fmt.Fprintf(w, "  %s  %s  %s  %s  %s  %s  %s\n",
		col.Paint(cDim, pad(h, 0)), col.Paint(cDim, pad(h, 1)), col.Paint(cDim, pad(h, 2)),
		col.Paint(cDim, pad(h, 3)), col.Paint(cDim, pad(h, 4)), col.Paint(cDim, pad(h, 5)),
		col.Paint(cDim, pad(h, 6)))

	for i, f := range fs {
		r := rows[i+1]
		_, _ = fmt.Fprintf(w, "  %s  %s  %s  %s  %s  %s  %s\n",
			col.Paint(priorityColor(f.priority), pad(r, 0)),
			col.Paint(severityColor(f.severity), pad(r, 1)),
			pad(r, 2), col.Link(ruleURL(f.ruleID), pad(r, 3)), pad(r, 4), pad(r, 5), pad(r, 6))
		// A rule id names a finding; it doesn't explain it. "DS-0002" is meaningless to anyone
		// who doesn't already know the scanner, which is exactly the reader we care about — so
		// the finding's own message goes underneath, dimmed so it reads as support, not noise.
		if msg := findingSummary(f.message); msg != "" {
			_, _ = fmt.Fprintf(w, "  %s%s\n", strings.Repeat(" ", widths[0]+2), col.Paint(cDim, msg))
		}
	}
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

// ruleURL returns where a reader can look a rule up, or "" when we can't say. Only identifiers
// with a stable, publicly resolvable home qualify — a wrong link is worse than none, and the
// message below the row already carries the explanation.
func ruleURL(ruleID string) string {
	switch {
	case strings.HasPrefix(ruleID, "CVE-"):
		return "https://nvd.nist.gov/vuln/detail/" + ruleID
	case strings.HasPrefix(ruleID, "GHSA-"):
		return "https://github.com/advisories/" + ruleID
	default:
		return ""
	}
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
