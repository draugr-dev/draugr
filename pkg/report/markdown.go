package report

import (
	"fmt"
	"io"

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

	if len(d.Verdict.Controls) > 0 {
		_, _ = fmt.Fprintf(w, "### Controls\n\n")
		_, _ = fmt.Fprintln(w, "| Control | Verdict | Critical | High | Medium | Low |")
		_, _ = fmt.Fprintln(w, "|---|---|---:|---:|---:|---:|")
		for _, c := range d.Verdict.Controls {
			v := "pass"
			if c.Verdict == norn.Fail {
				v = "**FAIL**"
			}
			b := s.bands[c.Control]
			_, _ = fmt.Fprintf(w, "| %s | %s | %d | %d | %d | %d |\n",
				c.Control, v, b.critical, b.high, b.medium, b.low)
		}
		_, _ = fmt.Fprintln(w)
	}

	if len(s.findings) == 0 {
		_, _ = fmt.Fprintln(w, "No findings. ✓")
		return nil
	}

	_, _ = fmt.Fprintf(w, "### Fix first\n\n")
	_, _ = fmt.Fprintln(w, "| Priority | Severity | Score | Rule | Control | Tool | Location |")
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
