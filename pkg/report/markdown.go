package report

import (
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/draugr-dev/draugr/internal/english"
	"github.com/draugr-dev/draugr/pkg/norn"
)

// markdownReporter renders a portable Markdown report, for MR comments (GitLab/Bitbucket), wikis,
// Slack, or email, leading with the verdict and "fix first".
type markdownReporter struct{}

func (markdownReporter) Format() string { return "markdown" }

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

	change := changeViewFor(d, s.prioritized)
	if change != nil {
		change.capActions(changeActions(d, s))
	}
	writeChangeSection(w, change)
	if s.prioritized {
		_, _ = fmt.Fprintln(w, "| Priority | P1 | P2 | P3 | P4 |")
		_, _ = fmt.Fprintln(w, "|---|---|---|---|---|")
		_, _ = fmt.Fprintf(w, "| Findings | %d | %d | %d | %d |\n\n", s.p1, s.p2, s.p3, s.p4)
		// A caveat on every count above it, as the console has it.
		if d.Unclassified {
			_, _ = fmt.Fprintf(w, "**%s** %s\n\n", unclassifiedRead, unclassifiedBands)
		}
		// Beside the counts they are part of, as the console has it.
		if note := nonShippingNote(s.nonShipping, s.nonShippingTests); note != "" {
			_, _ = fmt.Fprintf(w, "%s, counted above.\n\n", note)
		}
	}

	// Under the counts it acts on, ahead of the tables that describe the whole run: a reader of a
	// pull-request comment decides what to do from the top of it.
	if len(s.findings) > 0 {
		writeFixFirstActions(w, d, s)
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
			// A caveat that fails the run fails the control it names, as a finding past the gate does.
			if c.Verdict == norn.Fail || caveatControls(d)[c.Control] {
				v = "**FAIL**"
			}
			// It reported findings *and* something failed, so what it did report is partial.
			if _, bad := s.scanErrors[c.Control]; bad {
				v = "**ERROR**"
			}
			if note := unreadNote(d.Run.Inputs, c.Control); note != "" {
				v += " · " + note
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

	writeFoundRows(w, d)
	writeComponentTable(w, d)
	writeCaveatRows(w, d)
	writeEvidenceNotes(w, d)

	if len(s.findings) == 0 {
		if len(s.scanErrors) > 0 {
			_, _ = fmt.Fprintln(w, noFindingsWithErrors)
		} else {
			line, _ := cleanRunLine(d)
			_, _ = fmt.Fprintln(w, line)
		}
		_, _ = fmt.Fprintln(w)
	}
	writeRunEvidence(w, d, s)
	return nil
}

// markdownActionsN is how many actions Fix first lists before pointing at the HTML report.
const markdownActionsN = 10

// placesCut matches the end of a place list cut short, as action.where and foldedPlaces write it.
var placesCut = regexp.MustCompile(`and (\d+) more$`)

// markdownFixFirstHeading is the Fix first heading, naming the filter where the run has one.
func markdownFixFirstHeading(s summary) string {
	if s.minPriority == "" {
		return "### Fix first\n\n"
	}
	heading := fmt.Sprintf("### Fix first (%s and above", strings.ToUpper(s.minPriority))
	if s.hidden > 0 {
		heading += "; " + english.Count(s.hidden, "lower-priority finding") + " hidden"
	}
	return heading + ")\n\n"
}

// writeFixFirstActions lists what to do, one bullet per action, built as the HTML report's What to
// do is, so the two agree row for row.
//
// Actions rather than findings: a pull-request comment is narrow, a table with a row per finding
// scrolls sideways there, and one package's advisories take a row each where one upgrade clears
// them all.
func writeFixFirstActions(w io.Writer, d Data, s summary) {
	grouped, external := groupActions(s.findings, d.Run.Stats.UnpinnedCacheHits, s.copies...)
	nameComponents := actionsNameComponents(grouped)
	_, _ = fmt.Fprint(w, markdownFixFirstHeading(s))
	folded := foldLines(grouped)
	for i, a := range folded {
		if i == markdownActionsN {
			_, _ = fmt.Fprintf(w, "\n_…and %s, in the HTML report's What to do._\n",
				english.Count(len(folded)-markdownActionsN, "more action"))
			break
		}
		_, _ = fmt.Fprintln(w, markdownActionLine(a, nameComponents))
	}
	if len(external) > 0 {
		if len(folded) > 0 {
			_, _ = fmt.Fprintln(w)
		}
		_, _ = fmt.Fprintf(w, "_%s_\n", externalLine(external))
	}
	_, _ = fmt.Fprintln(w)
}

// markdownActionLine is one action as a bullet: its band, what to do, how many findings it clears,
// and where.
func markdownActionLine(a action, nameComponents bool) string {
	ha := toHTMLAction(a)
	// The band is the worst of the action's findings, and a total beside it reads as that many at
	// that band, so a row whose findings sit in more than one band says how many are at its own.
	clears := english.Count(ha.Clears, "finding")
	if a.priority != "" {
		atBand := 0
		for _, f := range a.findings {
			if f.priority == a.priority {
				atBand++
			}
		}
		if atBand < ha.Clears {
			clears += fmt.Sprintf(", %d at %s", atBand, a.priority)
		}
	}
	head := fmt.Sprintf("- **%s** %s", ha.Priority, ha.Title)
	// A step past the component's fixes.upgrade says so after the instruction, as the console's row
	// does, with the setting as code so it reads as the key to copy.
	if s := a.step; s.past() {
		head += fmt.Sprintf(" · %s, past `%s`", s.beyond, s.setting())
	}
	// Evidence that a flaw this clears is exploited, KEV above all, ranks the action inside its band,
	// so the row carries the mark that ranked it, as the finding's own row does in the console.
	if f := a.rank.exploited; f != nil {
		if m := movedBy(*f); m != nil {
			head += " · " + m.text()
		}
	}
	line := head + " · " + clears
	if nameComponents && ha.Component != "" {
		line += " · " + ha.Component
	}
	// A place list cut short says where the rest are, which the HTML report lists in full.
	if ha.Where != "" {
		line += " · " + placesCut.ReplaceAllStringFunc(ha.Where, func(m string) string {
			n, _ := strconv.Atoi(placesCut.FindStringSubmatch(m)[1])
			return "and " + english.Count(n, "more place") + ", in the HTML report"
		})
	}
	return line
}

// writeFoundRows lists what a run with no descriptor read from the tree, as the console's FOUND
// section does. The pull request this is pasted into is often the first place somebody meets the
// run, and without it a scanner the tree turned on is one nobody can account for.
func writeFoundRows(w io.Writer, d Data) {
	if len(d.Found) == 0 {
		return
	}
	_, _ = fmt.Fprintln(w, "### Found")
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, "What the run read from the tree, which `draugr init` writes to `draugr.saga.yaml`.")
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, "| Kind | Files | This run |")
	_, _ = fmt.Fprintln(w, "|---|---|---|")
	for _, f := range d.Found {
		_, _ = fmt.Fprintf(w, "| %s | %s | %s |\n", f.Kind, f.Files, f.Did)
	}
	_, _ = fmt.Fprintln(w)
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
			head += " · " + exposure.markdown() + " · " + criticality.markdown() + " · " + componentVerdictWord(d, c)
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

// componentVerdictWord is a component's verdict as the markdown Components table prints it, by the
// console's rule: ERROR for a target no scanner read, FAIL for a finding past the gate or a caveat
// that fails the run.
func componentVerdictWord(d Data, c ComponentVerdict) string {
	switch {
	case c.Errored():
		return "**ERROR**"
	case componentFails(d, c):
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
	for _, r := range settingRows(d) {
		accepted = append(accepted, row{"`" + r.where() + "`", r.said()})
	}
	asides := toolAsides(d)
	for _, t := range asides {
		accepted = append(accepted, row{t.reporter, t.said()})
	}
	if line := silencedLine(d); line != "" {
		accepted = append(accepted, row{"scanner exclusions", strings.TrimPrefix(line, "scanner exclusions: ")})
	}
	for _, u := range unlistedRows(d) {
		accepted = append(accepted, row{"`" + u.where + "`", u.said})
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

	// Where and why each imported file's tool suppressed the findings Draugr set aside. Its own
	// table, because these are no decision of this project's: the tool recorded them, in its own
	// place, with a reason SARIF leaves optional and no field for who; an alert dismissed in GitHub
	// names who dismissed it. The reason is the file's text,
	// so it is kept to one line and its pipes cannot end the cell.
	if len(asides) > 0 {
		_, _ = fmt.Fprintln(w, "### Set aside by imported tools")
		_, _ = fmt.Fprintln(w)
		_, _ = fmt.Fprintln(w, "| Findings | Tool | Suppressed | Reason | Who |")
		_, _ = fmt.Fprintln(w, "|---:|---|---|---|---|")
		for _, t := range asides {
			for _, r := range t.reasons {
				_, _ = fmt.Fprintf(w, "| %d | %s | %s | %s | %s |\n", r.n, t.reporter, r.in,
					strings.ReplaceAll(r.reason(), "|", `\|`), r.whoOf())
			}
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
		// Uncommitted files a scan left out are a caveat, said under Caveats. Read from the working
		// tree, they are in the result and it cannot be reproduced from the revision.
		if r.WorkingTree && r.Uncommitted > 0 {
			line += fmt.Sprintf(" · working tree · %s, not reproducible", english.Count(r.Uncommitted, "uncommitted file"))
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
		v := componentVerdictWord(d, c)
		var notes []string
		if len(c.Controls) > 0 {
			notes = append(notes, strings.Join(c.Controls, ", "))
		}
		if len(c.Unscanned) > 0 {
			notes = append(notes, unscannedDetail(c.Unscanned, c.Declared))
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
