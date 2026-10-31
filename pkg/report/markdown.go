package report

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/draugr-dev/draugr/internal/english"
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
	if d.ProjectName() != "" {
		_, _ = fmt.Fprintf(w, "**Release:** %s\n\n", releaseLabel(d))
	}

	if s.prioritized {
		_, _ = fmt.Fprintln(w, "| Priority | P1 | P2 | P3 | P4 |")
		_, _ = fmt.Fprintln(w, "|---|---|---|---|---|")
		_, _ = fmt.Fprintf(w, "| Findings | %d | %d | %d | %d |\n\n", s.p1, s.p2, s.p3, s.p4)
	}

	// Beside the bands it qualifies, which is where the console and the page put it.
	writeSignalRows(w, d, s)

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
	}

	writeComponentTable(w, d)
	writeCaveatRows(w, d)
	writeEvidenceNotes(w, d)

	if len(s.findings) == 0 {
		if len(s.scanErrors) > 0 {
			_, _ = fmt.Fprintln(w, "No findings from the controls that ran. A control marked ERROR did not report.")
		} else {
			_, _ = fmt.Fprintln(w, "No findings. ✓")
		}
		_, _ = fmt.Fprintln(w)
		writeRunEvidence(w, d, s)
		return nil
	}

	if s.minPriority != "" {
		heading := fmt.Sprintf("### Fix first (%s and above", strings.ToUpper(s.minPriority))
		if s.hidden > 0 {
			heading += "; " + english.Count(s.hidden, "lower-priority finding") + " hidden"
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
		_, _ = fmt.Fprintf(w, "\n_…and %s more._\n", english.Count(len(s.findings)-markdownTopN, "finding"))
	}
	_, _ = fmt.Fprintln(w)
	writeRunEvidence(w, d, s)
	return nil
}

// writeCaveatRows lists the run's caveats under each component, from the list the console's
// CAVEATS block prints, so the two cannot disagree.
//
// Carried into markdown because this is the format pasted into a pull request, where a reader is
// deciding whether the check passing means anything. A surface nothing looked at, a scanner that
// did not run and a file nothing read are each indistinguishable there from one that was checked
// and found clean. Every row, uncapped: the console caps its block for a terminal, and this is the
// copy that is kept.
func writeCaveatRows(w io.Writer, d Data) {
	groups := caveatsByComponent(caveats(d))
	if len(groups) == 0 {
		return
	}
	failing, _ := splitCaveats(d)
	_, _ = fmt.Fprintln(w, "### Caveats")
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, "Shortfalls in what the run covered, by component.")
	_, _ = fmt.Fprintln(w)
	// The console heading's note, in its words.
	switch {
	case len(failing) > 0 && d.AcceptedErrors:
		_, _ = fmt.Fprintf(w, "%d accepted by `--allow-scan-errors` · `%s`\n\n", len(failing), caveatSetting(d))
	case len(failing) > 0:
		verb := "fail"
		if len(failing) == 1 {
			verb = "fails"
		}
		_, _ = fmt.Fprintf(w, "%d %s the run · `%s`\n\n", len(failing), verb, caveatSetting(d))
	default:
		_, _ = fmt.Fprintln(w, "do not fail the run · `config.gate.failOnCaveats` lists the kinds that do")
		_, _ = fmt.Fprintln(w)
	}
	verdicts := map[string]ComponentVerdict{}
	for _, c := range d.Components {
		verdicts[c.Name] = c
	}
	for _, g := range groups {
		head := "_no component_"
		if g.component != "" {
			head = "**" + g.component + "**"
		}
		// The component's row from the Components table, so its verdict and what the run did not
		// cover are read together, with the classification the ranking used as the table writes it.
		if c, ok := verdicts[g.component]; ok {
			exposure, criticality := rankedClass(c)
			head += " · " + exposure.markdown() + " · " + criticality.markdown() + " · " + componentVerdictWord(c)
		}
		_, _ = fmt.Fprintln(w, head)
		_, _ = fmt.Fprintln(w)
		for _, c := range g.caveats {
			kind := "`" + string(c.key) + "`"
			if c.fails(d) {
				kind = "✗ " + kind
			}
			_, _ = fmt.Fprintf(w, "- %s · `%s` · %s\n", kind, c.what, c.detail)
		}
		_, _ = fmt.Fprintln(w)
	}
}

// componentVerdictWord is a component's verdict as the markdown Components table prints it. A
// component with a target no scanner read, or a caveat the gate fails on, has not passed, whatever
// it found in the rest, which is the console's rule.
func componentVerdictWord(c ComponentVerdict) string {
	switch {
	case len(c.Unscanned) > 0 || len(c.FailedCaveats) > 0:
		return "**ERROR**"
	case c.Verdict == norn.Fail:
		return "**FAIL**"
	}
	return "pass"
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
func writeEvidenceNotes(w io.Writer, d Data) {
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
		accepted = append(accepted, row{"scanner exclusions", strings.TrimPrefix(line, "scanner exclusions: ")})
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
		_, _ = fmt.Fprintln(w, "| Findings | Exclusion | Git history | Expires | Reason |")
		_, _ = fmt.Fprintln(w, "|---:|---|---|---|---|")
		for _, dec := range decs {
			where := "not recorded"
			if dec.where != "" {
				where = "`" + dec.where + "`"
			}
			history := "not recorded"
			if h := dec.history; h != nil {
				// The column names the source, so the cell carries the facts alone.
				history = h.Summary()
			}
			expires := dec.expires
			if expires == "" {
				// "never" rather than a dash: an acceptance with no end date is a decision somebody
				// made, and a blank reads as a value the report failed to record.
				expires = "never"
			}
			_, _ = fmt.Fprintf(w, "| %d | %s | %s | %s | %s |\n", dec.n, where, history, expires, dec.reason)
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

}

// writeRunEvidence is what stands behind the verdict rather than what it found.
//
// One section at the end. These were four bold paragraphs and two italic lines scattered between
// the tables, and a line with a blank one either side belongs to whichever section the reader
// happens to attach it to.
func writeRunEvidence(w io.Writer, d Data, s summary) {
	var body strings.Builder
	if line := gateSentence(d); line != "" {
		_, _ = fmt.Fprintf(&body, "- **Gate:** %s\n", strings.TrimPrefix(line, "Gate: "))
	}
	if s.sboms > 0 {
		_, _ = fmt.Fprintf(&body, "- **SBOM:** %s (%s)\n", english.Count(s.sboms, "document"), s.sbomFormat)
	}
	writeRepositories(&body, d)
	writeProvenance(&body, d)
	writeExploitability(&body, d)
	if body.Len() == 0 {
		return
	}
	_, _ = fmt.Fprintln(w, "### Evidence")
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprint(w, body.String())
	if !strings.HasSuffix(body.String(), "\n\n") {
		_, _ = fmt.Fprintln(w)
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
	_, _ = fmt.Fprintf(w, "- **Scanned**\n")
	for _, r := range d.Repositories {
		line := "  - `" + r.URL + "`"
		if rev := r.Short(); rev != "" {
			line += " at `" + rev + "`"
		}
		if r.Uncommitted > 0 {
			line += fmt.Sprintf(" · %s not included", english.Count(r.Uncommitted, "uncommitted file"))
		}
		_, _ = fmt.Fprintln(w, line)
	}
}

func writeProvenance(w io.Writer, d Data) {
	lines := provenanceLines(d)
	if len(lines) == 0 {
		return
	}
	_, _ = fmt.Fprintf(w, "- **Measured against**\n")
	for _, l := range lines {
		if l.Detail == "" {
			_, _ = fmt.Fprintf(w, "  - `%s` · %s\n", l.Control, l.Label())
			continue
		}
		_, _ = fmt.Fprintf(w, "  - `%s` · %s: %s\n", l.Control, l.Label(), l.Detail)
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
	_, _ = fmt.Fprintln(w, "| Component | Exposure | Criticality | Verdict | P1 | P2 | P3 | P4 | Failing controls |")
	_, _ = fmt.Fprintln(w, "|---|---|---|---|---:|---:|---:|---:|---|")
	for _, c := range d.Components {
		// A row of counts beside the word "pass" for a component with a target no scanner read
		// asserts something no scanner established, and a table is where that reads most like a
		// result. So it reads ERROR, and says what was missed.
		v := componentVerdictWord(c)
		var notes []string
		if len(c.Controls) > 0 {
			notes = append(notes, strings.Join(c.Controls, ", "))
		}
		if len(c.Unscanned) > 0 {
			notes = append(notes, unscannedDetail(c.Unscanned, c.Declared))
		}
		if len(c.FailedCaveats) > 0 {
			notes = append(notes, failedCaveatNote(c.FailedCaveats))
		}
		exposure, criticality := rankedClass(c)
		_, _ = fmt.Fprintf(w, "| %s | %s | %s | %s | %d | %d | %d | %d | %s |\n",
			c.Name, exposure.markdown(), criticality.markdown(), v,
			c.Priorities[0], c.Priorities[1], c.Priorities[2], c.Priorities[3],
			dash(strings.Join(notes, "; ")))
	}
	_, _ = fmt.Fprintln(w)
	if d.UnattributedFindings > 0 {
		_, _ = fmt.Fprintf(w, "_%s not tied to a component (project-wide controls)._\n\n",
			english.Count(d.UnattributedFindings, "finding"))
	}
}

// markdown writes a half of the classification as a cell. Plain text carries no dimming, so a half
// the ranking assumed says so in words.
func (h classHalf) markdown() string {
	if h.Assumed {
		return h.Value + " (assumed)"
	}
	return h.Value
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
	_, _ = fmt.Fprintf(w, "- **Exploitability data**\n")
	for _, f := range d.Exploitability {
		when := "supplied as a file"
		if !f.FetchedAt.IsZero() {
			when = "fetched " + f.FetchedAt.UTC().Format(time.DateOnly)
		}
		if f.Stale {
			when += " · **stale**"
		}
		_, _ = fmt.Fprintf(w, "  - `%s` · %s\n", f.Name, when)
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

// writeSignalRows records what argued with this run's ranking, how each signal moves a finding,
// and what it did.
//
// Absent from the file reports entirely, which made them the one place a reader could not find out
// that a finding was raised because CISA lists it as exploited. The rows are the console's and the
// HTML report's, from the same table, so the three cannot disagree about what moved a run.
//
// The movement in bold, where the HTML report draws the mark a finding row wears: a pull-request
// comment has no outline to draw, and bold is what keeps the change apart from its condition.
func writeSignalRows(w io.Writer, d Data, s summary) {
	rows, notes := signals(d, s)
	if len(rows) == 0 {
		return
	}
	_, _ = fmt.Fprintln(w, "### Signals")
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, "| Signal | How it moves a finding | This run |")
	_, _ = fmt.Fprintln(w, "|---|---|---|")
	for _, x := range rows {
		m := x.Moves
		how := fmt.Sprintf("**%s %s** %s", m.Glyph(), m.Change, m.Condition)
		if m.Value != "" {
			how += " `" + m.Value + "`"
		}
		how += m.Rest
		_, _ = fmt.Fprintf(w, "| %s | %s | %s |\n", x.Name, how, x.Did)
	}
	_, _ = fmt.Fprintln(w)
	for _, note := range notes {
		_, _ = fmt.Fprintf(w, "_%s_\n\n", note)
	}
}
