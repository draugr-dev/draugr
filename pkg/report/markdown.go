package report

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/draugr-dev/draugr/pkg/norn"
)

// markdownReporter renders a portable Markdown report, for MR comments (GitLab/Bitbucket), wikis,
// Slack, or email, leading with the verdict and "fix first".
type markdownReporter struct{}

func (markdownReporter) Format() string { return "markdown" }

const markdownTopN = 25

func (markdownReporter) Render(w io.Writer, d Data) error {
	s := summarize(d)

	verdict := "✅ PASS"
	if s.verdict == norn.Fail {
		verdict = "❌ FAIL"
	}
	_, _ = fmt.Fprintf(w, "## Draugr · %s\n\n", verdict)
	if name := d.ProjectName(); name != "" {
		_, _ = fmt.Fprintf(w, "**Release:** %s %s\n\n", name, d.Release.Version)
	}

	if s.prioritized {
		_, _ = fmt.Fprintln(w, "| Priority | P1 | P2 | P3 | P4 |")
		_, _ = fmt.Fprintln(w, "|---|---|---|---|---|")
		_, _ = fmt.Fprintf(w, "| Findings | %d | %d | %d | %d |\n\n", s.p1, s.p2, s.p3, s.p4)
	}

	if len(d.Verdict.Controls) > 0 || len(s.errored) > 0 {
		_, _ = fmt.Fprintf(w, "### Controls\n\n")
		// Bands, because the verdict, the components and the gate all talk about priority, and a
		// table counting severities beside them asks a reader to hold two vocabularies and map
		// between them. A run that ranked nothing falls back to what it has.
		head, cells := "| Control | Verdict | P1 | P2 | P3 | P4 |", func(name string) string {
			b := s.controlBands[name]
			return fmt.Sprintf("%d | %d | %d | %d", b[0], b[1], b[2], b[3])
		}
		if !s.prioritized {
			head = "| Control | Verdict | Critical | High | Medium | Low |"
			cells = func(name string) string {
				b := s.bands[name]
				return fmt.Sprintf("%d | %d | %d | %d", b.critical, b.high, b.medium, b.low)
			}
		}
		_, _ = fmt.Fprintln(w, head)
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
			_, _ = fmt.Fprintf(w, "| %s | %s | %s |\n", c.Control, v, cells(c.Control))
		}
		// A control that produced nothing at all has no verdict row, and leaving it out
		// entirely is how a broken run reads as a clean one.
		for _, name := range s.errored {
			_, _ = fmt.Fprintf(w, "| %s | **ERROR** | | | | |\n", name)
		}
		_, _ = fmt.Fprintln(w)
		writeScanErrors(w, s)
		writeNotMeasuredRows(w, d)
		writeRepositories(w, d)
		writeProvenance(w, d)
		writeExploitability(w, d)
	}

	writeComponentTable(w, d)
	writeSignalRows(w, d, s)
	writeEvidenceNotes(w, d, s)

	if len(s.findings) == 0 {
		if len(s.scanErrors) > 0 {
			_, _ = fmt.Fprintln(w, "No findings from the controls that ran. See the errors reported above.")
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
	shown := s.findings
	if len(shown) > markdownTopN {
		shown = shown[:markdownTopN]
	}
	// Component before Location: a path answers "where inside", and with more than one component the
	// reader needs "which one" first. Two components can carry the same path. Dropped entirely when
	// every row carries the same one, which is a column repeating itself.
	withComponent := varies(shown, func(f finding) string { return f.component })
	head := "| Priority | Severity | Rule | Scanner | Location | Upgrade | Finding |"
	rule := "|---|---|---|---|---|---|---|"
	if withComponent {
		head = "| Priority | Severity | Rule | Scanner | Component | Location | Upgrade | Finding |"
		rule = "|---|---|---|---|---|---|---|---|"
	}
	_, _ = fmt.Fprintln(w, head)
	_, _ = fmt.Fprintln(w, rule)
	for _, f := range shown {
		component := ""
		if withComponent {
			component = " " + dash(f.component) + " |"
		}
		// The rating the band was computed from, so the row does not contradict the band beside it,
		// and the mark that moved it, in the words the console uses.
		sev := string(rankedSeverity(f))
		if m := movedBy(f); m != nil {
			sev += " " + m.glyph + " " + m.label
		}
		_, _ = fmt.Fprintf(w, "| %s | %s | %s | %s |%s %s | %s | %s |\n",
			dash(f.priority), sev, ruleLink(f), f.tool, component, dash(f.location),
			dash(upgradeLabel(f)), findingTitle(f))
	}
	if len(s.findings) > markdownTopN {
		_, _ = fmt.Fprintf(w, "\n_…and %d more finding(s)._\n", len(s.findings)-markdownTopN)
	}
	return nil
}

// writeNotMeasuredRows names any scanner that was planned and then not run.
//
// Carried into markdown as well as the console because this is the format that gets pasted into a
// pull request, where a reader is deciding whether the check passing means anything. A scanner
// that quietly did not run is indistinguishable there from one that ran and found nothing.
func writeNotMeasuredRows(w io.Writer, d Data) {
	if len(d.Run.Skipped) == 0 {
		return
	}
	_, _ = fmt.Fprintln(w, "**Not measured**")
	_, _ = fmt.Fprintln(w)
	for _, sk := range d.Run.Skipped {
		where := sk.Scanner
		if sk.Component != "" {
			where += " on `" + sk.Component + "`"
		}
		_, _ = fmt.Fprintf(w, "- %s (%s) · %s\n", where, sk.Control, sk.Reason)
	}
	_, _ = fmt.Fprintln(w)
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
			_, _ = fmt.Fprintf(w, "- `%s` · %s\n", name, findingSummary(msg))
		}
	}
	_, _ = fmt.Fprintln(w)
}

// writeEvidenceNotes records what the run set aside and what it produced alongside the findings.
// A suppression that leaves no trace reads exactly like a finding that was never made.
func writeEvidenceNotes(w io.Writer, d Data, s summary) {
	// A table rather than three bold sentences with blank lines between them. Each of these is a
	// decision with somebody at the end of it, and a sentence cannot be read down a column or
	// counted. Named in full here: a rendered report is read once and kept, often by somebody
	// asking who decided, where the console is read while somebody is deciding what to fix.
	type row struct{ where, what string }
	var accepted []row
	if line := suppressionLine(d, true); line != "" {
		accepted = append(accepted, row{"`config.exclude`", strings.TrimPrefix(line, "config.exclude: ")})
	}
	if line := importedLine(d, true); line != "" {
		accepted = append(accepted, row{"VEX", strings.TrimPrefix(line, "VEX: ")})
	}
	if line := silencedLine(d); line != "" {
		accepted = append(accepted, row{"source directives", strings.TrimPrefix(line, "source directives: ")})
	}
	if len(accepted) > 0 {
		_, _ = fmt.Fprintln(w, "### Accepted")
		_, _ = fmt.Fprintln(w)
		_, _ = fmt.Fprintln(w, "| Source | What was set aside |")
		_, _ = fmt.Fprintln(w, "|---|---|")
		for _, r := range accepted {
			_, _ = fmt.Fprintf(w, "| %s | %s |\n", r.where, r.what)
		}
		_, _ = fmt.Fprintln(w)
	}

	// One row per decision, always, because this is the copy somebody keeps. The count above says
	// how much was set aside and cannot say what was acceptable about any of it, though every
	// suppressed finding carries the reason somebody gave.
	if decs := decisions(d); len(decs) > 0 {
		_, _ = fmt.Fprintln(w, "### Decisions")
		_, _ = fmt.Fprintln(w)
		_, _ = fmt.Fprintln(w, "| Findings | Accepted by | Expires | Reason |")
		_, _ = fmt.Fprintln(w, "|---:|---|---|---|")
		for _, dec := range decs {
			who := dec.by
			if who == "unattributed" {
				// The one an auditor cannot follow up, so it is marked rather than left to be
				// noticed among names.
				who = "**unattributed**"
			}
			expires := dec.expires
			if expires == "" {
				// "never" rather than a dash: an acceptance with no end date is a decision somebody
				// made, and a blank reads as a value the report failed to record.
				expires = "never"
			}
			_, _ = fmt.Fprintf(w, "| %d | %s | %s | %s |\n", dec.n, who, expires, dec.reason)
		}
		_, _ = fmt.Fprintln(w)
	}

	// A rule that matched nothing claims a decision it is not making, and in the copy somebody
	// keeps that is worth more than in the terminal: the descriptor and the report are read apart,
	// so nothing else here would say the line was dead.
	var unmatched []row
	for _, e := range d.Run.UnmatchedExclusions {
		// The field and the pattern set apart, the way the page does it. A pattern in code is
		// something a reader compares against their tree; the field name beside it is ours.
		var parts []string
		for _, m := range excludeMatchers(e) {
			parts = append(parts, m.Key+" `"+m.Value+"`")
		}
		unmatched = append(unmatched, row{"`config.exclude`",
			strings.Join(parts, "; ") + " · " + findingSummary(e.Reason)})
	}
	for _, c := range d.Run.UnmatchedClaims {
		unmatched = append(unmatched, row{"VEX", claimSummary(c)})
	}
	if len(unmatched) > 0 {
		_, _ = fmt.Fprintln(w, "### Unmatched")
		_, _ = fmt.Fprintln(w)
		_, _ = fmt.Fprintln(w, "| Source | Rule |")
		_, _ = fmt.Fprintln(w, "|---|---|")
		for _, r := range unmatched {
			_, _ = fmt.Fprintf(w, "| %s | %s |\n", r.where, r.what)
		}
		_, _ = fmt.Fprintln(w)
	}

	if s.sboms > 0 {
		_, _ = fmt.Fprintf(w, "_SBOM: %s (%s)._\n\n", plural(s.sboms, "document"), s.sbomFormat)
	}
	// What the verdict was measured against. A report that does not say what stopped the build
	// cannot be checked by anybody who was not there when it ran.
	if line := gateSentence(d); line != "" {
		_, _ = fmt.Fprintf(w, "_%s_\n\n", line)
	}
}

// writeProvenance records what each scanner measured, and against what.
//
// Under the controls table rather than beside a finding: it describes the run, not any one
// result, and a reader checking "is this the right standard" is asking about the whole control.
func writeRepositories(w io.Writer, d Data) {
	if len(d.Repositories) == 0 {
		return
	}
	_, _ = fmt.Fprintln(w, "**Scanned**")
	_, _ = fmt.Fprintln(w)
	for _, r := range d.Repositories {
		line := "- `" + r.URL + "`"
		if rev := r.Short(); rev != "" {
			line += " at `" + rev + "`"
		}
		if r.Uncommitted > 0 {
			line += fmt.Sprintf(" · %s not included", plural(r.Uncommitted, "uncommitted file"))
		}
		_, _ = fmt.Fprintln(w, line)
	}
	_, _ = fmt.Fprintln(w)
}

func writeProvenance(w io.Writer, d Data) {
	lines := provenanceLines(d)
	if len(lines) == 0 {
		return
	}
	_, _ = fmt.Fprintln(w, "**Measured against**")
	_, _ = fmt.Fprintln(w)
	for _, l := range lines {
		if l.Detail == "" {
			_, _ = fmt.Fprintf(w, "- `%s` · %s\n", l.Control, l.Label())
			continue
		}
		_, _ = fmt.Fprintf(w, "- `%s` · %s: %s\n", l.Control, l.Label(), l.Detail)
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

// writeExploitability records the datasets that raised severities in this run.
//
// Alongside the scanners' own provenance, and for the same reason: a reader asking whether the
// right standard was applied is asking about the run. A stale copy is marked here rather than
// only warned about while the scan was running.
func writeExploitability(w io.Writer, d Data) {
	if len(d.Exploitability) == 0 {
		return
	}
	_, _ = fmt.Fprintln(w, "**Exploitability data**")
	_, _ = fmt.Fprintln(w)
	for _, f := range d.Exploitability {
		when := "supplied as a file"
		if !f.FetchedAt.IsZero() {
			when = "fetched " + f.FetchedAt.UTC().Format(time.DateOnly)
		}
		if f.Stale {
			when += " · **stale**"
		}
		_, _ = fmt.Fprintf(w, "- `%s` · %s\n", f.Name, when)
	}
	_, _ = fmt.Fprintln(w)
}

// ruleLink renders a rule id, linked to whatever the scanner published about it.
//
// The same thing the console does with the same fact: a reader deciding whether a finding matters
// is one click from the advisory rather than one search, and in a pull-request comment the link is
// the only way there.
func ruleLink(f finding) string {
	id := "`" + f.ruleID + "`"
	if f.helpURI == "" {
		return id
	}
	return "[" + id + "](" + f.helpURI + ")"
}

// varies reports whether a column would say something different on any two rows.
//
// A column repeating one value answers nothing and costs the width the rows it sits beside need.
// The console drops one for the same reason, and this is the table that gets pasted into a pull
// request where width is scarcest.
func varies(fs []finding, of func(finding) string) bool {
	var first string
	for i, f := range fs {
		v := of(f)
		if i == 0 {
			first = v
			continue
		}
		if v != first {
			return true
		}
	}
	return false
}

// writeSignalRows records what argued with this run's ranking.
//
// Absent from the file reports entirely, which made them the one place a reader could not find out
// that a finding was raised because CISA lists it as exploited. The console names each signal and
// how many findings it moved; so does this, in the same words.
func writeSignalRows(w io.Writer, d Data, s summary) {
	type sig struct{ name, did string }
	var sigs []sig
	for _, name := range []string{"kev", "epss"} {
		n := s.bySignal[name]
		if n == 0 && !consulted(d, name) {
			continue
		}
		did := "nothing raised"
		if n > 0 {
			did = fmt.Sprintf("%s raised", plural(n, "finding"))
		}
		sigs = append(sigs, sig{strings.ToUpper(name), did})
	}
	if n := s.floored; n > 0 {
		sigs = append(sigs, sig{"floor", fmt.Sprintf("%s raised by a control's own rule", plural(n, "finding"))})
	}
	rows, notes := reachabilityBlock(d)
	for _, row := range rows {
		analyzer, did, _ := strings.Cut(row, "  ")
		sigs = append(sigs, sig{"reachability", strings.TrimSpace(analyzer) + " · " + strings.TrimSpace(did)})
	}
	if len(sigs) == 0 {
		return
	}
	_, _ = fmt.Fprintln(w, "### Signals")
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, "| Signal | Effect |")
	_, _ = fmt.Fprintln(w, "|---|---|")
	for _, x := range sigs {
		_, _ = fmt.Fprintf(w, "| %s | %s |\n", x.name, x.did)
	}
	_, _ = fmt.Fprintln(w)
	for _, note := range notes {
		_, _ = fmt.Fprintf(w, "_%s_\n\n", note)
	}
}
