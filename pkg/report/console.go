package report

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/draugr-dev/draugr/pkg/norn"
)

// consoleReporter renders a human-readable terminal summary: verdict, priority/severity
// counts, per-control outcomes, and a ranked "fix first" list.
type consoleReporter struct{}

func (consoleReporter) Format() string { return "console" }

const consoleTopN = 10

func (consoleReporter) Render(w io.Writer, d Data) error {
	s := summarize(d)

	verdict := "PASS"
	if s.verdict == norn.Fail {
		verdict = "FAIL"
	}
	_, _ = fmt.Fprintf(w, "Draugr — %s", verdict)
	if d.Release.Name != "" {
		rel := d.Release.Name
		if d.Release.Version != "" {
			rel += " " + d.Release.Version
		}
		_, _ = fmt.Fprintf(w, "   (%s)", rel)
	}
	_, _ = fmt.Fprint(w, "\n\n")

	if s.prioritized {
		_, _ = fmt.Fprintf(w, "Priorities:  P1 %d   P2 %d   P3 %d   P4 %d\n\n", s.p1, s.p2, s.p3, s.p4)
	}

	if len(d.Verdict.Controls) > 0 {
		_, _ = fmt.Fprintln(w, "Controls:")
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		for _, c := range d.Verdict.Controls {
			v := "pass"
			if c.Verdict == norn.Fail {
				v = "FAIL"
			}
			_, _ = fmt.Fprintf(tw, "  %s\t%s\t%d error  %d warning  %d note\n",
				c.Control, v, c.Counts.Error, c.Counts.Warning, c.Counts.Note)
		}
		_ = tw.Flush()
		_, _ = fmt.Fprintln(w)
	}

	if len(s.findings) == 0 {
		_, _ = fmt.Fprintln(w, "No findings. ✓")
		return nil
	}

	shown := s.findings
	if len(shown) > consoleTopN {
		shown = shown[:consoleTopN]
	}
	_, _ = fmt.Fprintln(w, "Fix first:")
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, f := range shown {
		_, _ = fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\t%s\n",
			dash(f.priority), f.level, scoreStr(f), f.ruleID, where(f), f.tool)
	}
	_ = tw.Flush()

	if len(s.findings) > consoleTopN {
		_, _ = fmt.Fprintf(w, "\n… and %d more finding(s). ", len(s.findings)-consoleTopN)
	} else {
		_, _ = fmt.Fprint(w, "\n")
	}
	_, _ = fmt.Fprintln(w, "Use --format json for the full report, or -o <dir> for report.json + results.sarif.")
	return nil
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

func where(f finding) string {
	if f.location != "" {
		return f.control + " " + f.location
	}
	return f.control
}
