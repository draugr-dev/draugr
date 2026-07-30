package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/draugr-dev/draugr/pkg/norn"
)

// markdownReporter renders a portable Markdown report — for MR comments (GitLab/Bitbucket),
// wikis, Slack, or email — leading with the verdict and "fix first".
type markdownReporter struct{}

func (markdownReporter) Format() string { return "markdown" }

const markdownTopN = 25

func (markdownReporter) Render(w io.Writer, d Data) error {
	s := summarize(d)

	verdict := "✅ PASS"
	if s.verdict == norn.Fail {
		verdict = "❌ FAIL"
	}
	_, _ = fmt.Fprintf(w, "## Draugr — %s\n\n", verdict)
	if d.Release.Name != "" {
		_, _ = fmt.Fprintf(w, "**Release:** %s %s\n\n", d.Release.Name, d.Release.Version)
	}

	if s.prioritized {
		_, _ = fmt.Fprintln(w, "| Priority | P1 | P2 | P3 | P4 |")
		_, _ = fmt.Fprintln(w, "|---|---|---|---|---|")
		_, _ = fmt.Fprintf(w, "| Findings | %d | %d | %d | %d |\n\n", s.p1, s.p2, s.p3, s.p4)
	}

	if len(d.Verdict.Controls) > 0 || len(s.errored) > 0 {
		_, _ = fmt.Fprintf(w, "### Controls\n\n")
		_, _ = fmt.Fprintln(w, "| Control | Verdict | Critical | High | Medium | Low |")
		_, _ = fmt.Fprintln(w, "|---|---|---:|---:|---:|---:|")
		for _, c := range d.Verdict.Controls {
			v := "pass"
			if c.Verdict == norn.Fail {
				v = "**FAIL**"
			}
			// It reported findings *and* something failed, so what it did report is partial.
			if _, bad := s.scanErrors[c.Control]; bad {
				v = "**ERROR**"
			}
			b := s.bands[c.Control]
			_, _ = fmt.Fprintf(w, "| %s | %s | %d | %d | %d | %d |\n",
				c.Control, v, b.critical, b.high, b.medium, b.low)
		}
		// A control that produced nothing at all has no verdict row, and leaving it out
		// entirely is how a broken run reads as a clean one.
		for _, name := range s.errored {
			_, _ = fmt.Fprintf(w, "| %s | **ERROR** | — | — | — | — |\n", name)
		}
		_, _ = fmt.Fprintln(w)
		writeScanErrors(w, s)
	}

	writeEvidenceNotes(w, s)

	if len(s.findings) == 0 {
		if len(s.scanErrors) > 0 {
			_, _ = fmt.Fprintln(w, "No findings from the controls that ran — see the errors above.")
			return nil
		}
		_, _ = fmt.Fprintln(w, "No findings. ✓")
		return nil
	}

	if s.minPriority != "" {
		heading := fmt.Sprintf("### Fix first (%s and above", strings.ToUpper(s.minPriority))
		if s.hidden > 0 {
			heading += fmt.Sprintf("; %d lower-priority finding(s) hidden", s.hidden)
		}
		_, _ = fmt.Fprintf(w, "%s)\n\n", heading)
	} else {
		_, _ = fmt.Fprintf(w, "### Fix first\n\n")
	}
	_, _ = fmt.Fprintln(w, "| Priority | Severity | Score | Rule | Control | Scanner | Location |")
	_, _ = fmt.Fprintln(w, "|---|---|---|---|---|---|---|")
	shown := s.findings
	if len(shown) > markdownTopN {
		shown = shown[:markdownTopN]
	}
	for _, f := range shown {
		_, _ = fmt.Fprintf(w, "| %s | %s | %s | `%s` | %s | %s | %s |\n",
			dash(f.priority), f.severity, scoreStr(f), f.ruleID, f.control, f.tool, dash(f.location))
	}
	if len(s.findings) > markdownTopN {
		_, _ = fmt.Fprintf(w, "\n_…and %d more finding(s)._\n", len(s.findings)-markdownTopN)
	}
	return nil
}

// writeScanErrors lists what stopped each control, under the Controls table.
func writeScanErrors(w io.Writer, s summary) {
	if len(s.scanErrors) == 0 {
		return
	}
	_, _ = fmt.Fprintln(w, "**Errors**")
	_, _ = fmt.Fprintln(w)
	for _, name := range sortedKeys(s.scanErrors) {
		for _, msg := range s.scanErrors[name] {
			_, _ = fmt.Fprintf(w, "- `%s` — %s\n", name, findingSummary(msg))
		}
	}
	_, _ = fmt.Fprintln(w)
}

// writeEvidenceNotes records what the run set aside and what it produced alongside the findings.
// A suppression that leaves no trace reads exactly like a finding that was never made.
func writeEvidenceNotes(w io.Writer, s summary) {
	if s.suppressed > 0 {
		_, _ = fmt.Fprintf(w, "_%s suppressed by `config.exclude`._\n\n", plural(s.suppressed, "finding"))
	}
	if s.sboms > 0 {
		_, _ = fmt.Fprintf(w, "_SBOM: %s (%s)._\n\n", plural(s.sboms, "document"), s.sbomFormat)
	}
}
