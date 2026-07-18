package report

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// consoleReporter renders a human-readable terminal summary: verdict, priority counts,
// per-control severity, and a ranked "fix first" list. It colorizes when writing to a TTY
// (unless NO_COLOR is set). The gate and machine formats (json/sarif) still speak SARIF levels;
// this human view speaks severity bands and priority.
type consoleReporter struct{}

func (consoleReporter) Format() string { return "console" }

const consoleTopN = 10

// ANSI SGR codes for the report's vocabulary.
const (
	cFail     = "1;31" // bold red
	cPass     = "32"   // green
	cCritical = "1;31"
	cHigh     = "31"
	cMedium   = "33"
	cLow      = "2" // dim
	cDim      = "2"
)

func (consoleReporter) Render(w io.Writer, d Data) error {
	s := summarize(d)
	col := newColorizer(w)

	verdict, vcol := "PASS", cPass
	if s.verdict == norn.Fail {
		verdict, vcol = "FAIL", cFail
	}
	_, _ = fmt.Fprintf(w, "Draugr — %s", col.paint(vcol, verdict))
	if d.Release.Name != "" {
		rel := d.Release.Name
		if d.Release.Version != "" {
			rel += " " + d.Release.Version
		}
		_, _ = fmt.Fprintf(w, "   %s", col.paint(cDim, "("+rel+")"))
	}
	_, _ = fmt.Fprint(w, "\n\n")

	if s.prioritized {
		_, _ = fmt.Fprintf(w, "Priorities:  %s   %s   %s   %s\n\n",
			col.paint(priorityColor("P1"), fmt.Sprintf("P1 %d", s.p1)),
			col.paint(priorityColor("P2"), fmt.Sprintf("P2 %d", s.p2)),
			fmt.Sprintf("P3 %d", s.p3),
			col.paint(cDim, fmt.Sprintf("P4 %d", s.p4)))
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
				col.paint(vc, fmt.Sprintf("%-4s", v)),
				bandsText(col, s.bands[c.Control]))
		}
		_, _ = fmt.Fprintln(w)
	}

	if len(s.findings) == 0 {
		_, _ = fmt.Fprintln(w, col.paint(cPass, "No findings. ✓"))
		return nil
	}

	shown := s.findings
	if len(shown) > consoleTopN {
		shown = shown[:consoleTopN]
	}
	_, _ = fmt.Fprintln(w, "Fix first:")
	renderFixFirst(w, col, shown)

	if len(s.findings) > consoleTopN {
		_, _ = fmt.Fprintf(w, "\n… and %d more finding(s). ", len(s.findings)-consoleTopN)
	} else {
		_, _ = fmt.Fprint(w, "\n")
	}
	_, _ = fmt.Fprintln(w, col.paint(cDim,
		"Use --format json for the full report, or -o <dir> for report.json + results.sarif."))
	return nil
}

// renderFixFirst prints the ranked findings as an aligned, colorized table. Columns are padded
// from the plain text so ANSI color codes don't skew the alignment.
func renderFixFirst(w io.Writer, col colorizer, fs []finding) {
	cols := make([][]string, len(fs)) // rows of [priority, severity, score, rule, control, location]
	for i, f := range fs {
		cols[i] = []string{
			dash(f.priority), string(f.severity), scoreStr(f), f.ruleID, f.control, dash(f.location),
		}
	}
	widths := make([]int, 6)
	for _, r := range cols {
		for i, cell := range r {
			if len(cell) > widths[i] {
				widths[i] = len(cell)
			}
		}
	}
	for i, f := range fs {
		r := cols[i]
		pad := func(n int) string { return fmt.Sprintf("%-*s", widths[n], r[n]) }
		_, _ = fmt.Fprintf(w, "  %s  %s  %s  %s  %s  %s\n",
			col.paint(priorityColor(f.priority), pad(0)),
			col.paint(severityColor(f.severity), pad(1)),
			pad(2), pad(3), pad(4), r[5])
	}
}

// bandsText renders per-control severity counts, omitting empty bands, each colorized.
func bandsText(col colorizer, b sevCounts) string {
	var parts []string
	if b.critical > 0 {
		parts = append(parts, col.paint(cCritical, fmt.Sprintf("%d critical", b.critical)))
	}
	if b.high > 0 {
		parts = append(parts, col.paint(cHigh, fmt.Sprintf("%d high", b.high)))
	}
	if b.medium > 0 {
		parts = append(parts, col.paint(cMedium, fmt.Sprintf("%d medium", b.medium)))
	}
	if b.low > 0 {
		parts = append(parts, col.paint(cLow, fmt.Sprintf("%d low", b.low)))
	}
	if len(parts) == 0 {
		return col.paint(cDim, "no findings")
	}
	return strings.Join(parts, "  ")
}

func priorityColor(p string) string {
	switch strings.ToUpper(p) {
	case "P1":
		return cFail
	case "P2":
		return cMedium
	case "P4":
		return cDim
	default:
		return ""
	}
}

func severityColor(s sarif.Severity) string {
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

// colorizer applies ANSI SGR codes when enabled.
type colorizer struct{ on bool }

// newColorizer enables color only when w is a terminal and NO_COLOR is unset.
func newColorizer(w io.Writer) colorizer {
	if os.Getenv("NO_COLOR") != "" {
		return colorizer{}
	}
	f, ok := w.(*os.File)
	if !ok {
		return colorizer{}
	}
	fi, err := f.Stat()
	return colorizer{on: err == nil && fi.Mode()&os.ModeCharDevice != 0}
}

func (c colorizer) paint(code, s string) string {
	if !c.on || code == "" {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
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
