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
		writeProvenance(w, d)
	}

	writeComponentTable(w, d)
	writeEvidenceNotes(w, d, s)

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
	// Component before Location: a path answers "where inside", and with more than one component
	// the reader needs "which one" first — two components can carry the same path.
	_, _ = fmt.Fprintln(w, "| Priority | Severity | Score | Rule | Control | Scanner | Component | Location |")
	_, _ = fmt.Fprintln(w, "|---|---|---|---|---|---|---|---|")
	shown := s.findings
	if len(shown) > markdownTopN {
		shown = shown[:markdownTopN]
	}
	for _, f := range shown {
		_, _ = fmt.Fprintf(w, "| %s | %s | %s | `%s` | %s | %s | %s | %s |\n",
			dash(f.priority), f.severity, scoreStr(f), f.ruleID, f.control, f.tool,
			dash(f.component), dash(f.location))
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
		for _, msg := range dedupeMessages(s.scanErrors[name]) {
			_, _ = fmt.Fprintf(w, "- `%s` — %s\n", name, findingSummary(msg))
		}
	}
	_, _ = fmt.Fprintln(w)
}

// writeEvidenceNotes records what the run set aside and what it produced alongside the findings.
// A suppression that leaves no trace reads exactly like a finding that was never made.
func writeEvidenceNotes(w io.Writer, d Data, s summary) {
	if line := suppressionLine(d); line != "" {
		_, _ = fmt.Fprintf(w, "**%s**\n\n", line)
	}
	if s.sboms > 0 {
		_, _ = fmt.Fprintf(w, "_SBOM: %s (%s)._\n\n", plural(s.sboms, "document"), s.sbomFormat)
	}
}

// writeProvenance records what each scanner measured, and against what.
//
// Under the controls table rather than beside a finding: it describes the run, not any one
// result, and a reader checking "is this the right standard" is asking about the whole control.
func writeProvenance(w io.Writer, d Data) {
	lines := provenanceLines(d)
	if len(lines) == 0 {
		return
	}
	_, _ = fmt.Fprintln(w, "**Measured against**")
	_, _ = fmt.Fprintln(w)
	for _, l := range lines {
		if l.Detail == "" {
			_, _ = fmt.Fprintf(w, "- `%s` — %s\n", l.Control, l.Label())
			continue
		}
		_, _ = fmt.Fprintf(w, "- `%s` — %s: %s\n", l.Control, l.Label(), l.Detail)
	}
	_, _ = fmt.Fprintln(w)
}

// writeComponentTable breaks the verdict down by component, when there is more than one.
//
// The controls table says whether the project is shippable. A reviewer reading this in a merge
// request owns one part of it, and that is the question they are actually asking.
func writeComponentTable(w io.Writer, d Data) {
	if len(d.Components) == 0 {
		return
	}
	_, _ = fmt.Fprintln(w, "### Components")
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, "| Component | Verdict | P1 | P2 | P3 | P4 | Failing controls |")
	_, _ = fmt.Fprintln(w, "|---|---|---:|---:|---:|---:|---|")
	for _, c := range d.Components {
		v := "pass"
		if c.Verdict == norn.Fail {
			v = "**FAIL**"
		}
		_, _ = fmt.Fprintf(w, "| %s | %s | %d | %d | %d | %d | %s |\n",
			c.Name, v, c.Priorities[0], c.Priorities[1], c.Priorities[2], c.Priorities[3],
			dash(strings.Join(c.Controls, ", ")))
	}
	_, _ = fmt.Fprintln(w)
	if d.UnattributedFindings > 0 {
		_, _ = fmt.Fprintf(w, "_%s not tied to a component (project-wide controls)._\n\n",
			plural(d.UnattributedFindings, "finding"))
	}
}
