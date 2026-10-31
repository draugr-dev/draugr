package report

import (
	"cmp"
	"fmt"
	"io"
	"regexp"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/draugr-dev/draugr/internal/english"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/skald"
	"github.com/draugr-dev/draugr/pkg/tui"
)

// The run's shortfalls, in two blocks, because they mean different things to the verdict.
//
// A target no scanner could read is an error: it is what makes a run incomplete, and the run fails
// unless --allow-scan-errors accepted it. It is said once, by target, with the components it leaves
// unscanned, rather than once per control that tried, which at scale is the same missing repository
// repeated under every control that reads repositories.
//
// A caveat does not fail the run: a declared surface no enabled control looks at, a scanner that
// cannot honor a component's scope, a dependency file inside a repository that was read. Each makes
// the run cover less than it appears to, so each is shown, in every view, apart from the errors.

// errorRowsShown caps both blocks, as the findings are capped: --top 0 shows every row.
const errorRowsShown = 10

// whyWidth keeps a row's reason to one line beside its other columns. The whole of it is in
// --format json.
const whyWidth = 80

// notReached is the run's targets every scanner tried and failed to read, by kind in the order a
// descriptor declares them and then by address, so twenty images from one registry that is down
// sit together. A target no scanner was run for is a caveat, under `not-measured`, because nothing
// failed.
func notReached(d Data) []engine.TargetOutcome {
	var out []engine.TargetOutcome
	for _, t := range d.Run.Targets {
		if t.Status == engine.TargetFailed {
			out = append(out, t)
		}
	}
	rank := func(kind string) int {
		if i := slices.Index(kindOrder, kind); i >= 0 {
			return i
		}
		return len(kindOrder)
	}
	slices.SortStableFunc(out, func(a, b engine.TargetOutcome) int {
		if c := cmp.Compare(rank(a.Kind), rank(b.Kind)); c != 0 {
			return c
		}
		return cmp.Compare(a.Target, b.Target)
	})
	return out
}

// kindOrder is the order a component declares its targets in.
var kindOrder = []string{"repository", "image", "host", "cluster", "account", "file"}

// bareFailure matches a clause that says something failed and not what.
var bareFailure = regexp.MustCompile(`^(?i:fatal|error|exit status \d+)$`)

// identifierOnly matches a clause that is only an identifier: a UUID, a request id, a digest.
var identifierOnly = regexp.MustCompile(`^(?:sha256:)?[0-9a-fA-F]{8,}(?:-[0-9a-fA-F]{4,})*$`)

// quotedSpan matches a single-quoted address or path inside a clause.
var quotedSpan = regexp.MustCompile(`'[^']*'`)

// shortReason is the part of a failure that says what went wrong, in the scanner's words: its last
// clause, or the one before when the last only repeats the address. "git clone: exit status 128:
// remote: Repository not found. fatal: repository 'https://…' not found" says "Repository not
// found". The whole message is in --format json.
func shortReason(detail string, width int) string {
	line := strings.Join(strings.Fields(detail), " ")
	parts := strings.Split(line, ": ")
	reason := strings.TrimSpace(parts[len(parts)-1])
	// A registry closes its refusal with a reference for its own logs, "CorrelationId: 5bf38f62-…",
	// which identifies the request and says nothing about it. The clause before says what went
	// wrong, less the label of the reference.
	if identifierOnly.MatchString(reason) && len(parts) > 1 {
		prev := strings.TrimSpace(parts[len(parts)-2])
		if k := strings.LastIndex(prev, ". "); k > 0 && !strings.Contains(prev[k+2:], " ") {
			prev = prev[:k]
		}
		// "…, visit https://… for more information" points somewhere else for the reason.
		var kept []string
		for _, c := range strings.Split(prev, ", ") {
			if strings.Contains(c, "://") {
				break
			}
			kept = append(kept, c)
		}
		if len(kept) > 0 {
			prev = strings.Join(kept, ", ")
		}
		return truncate(strings.TrimSuffix(prev, "."), width)
	}
	if (strings.Contains(reason, "://") || strings.Contains(reason, "'")) && len(parts) > 1 {
		prev := strings.TrimSpace(parts[len(parts)-2])
		if k := strings.Index(prev, ". "); k > 0 {
			prev = prev[:k]
		}
		// The clause before can be git's `fatal` or an exit status, which say only that it failed.
		// The last clause then carries the meaning, with the address taken out.
		if bareFailure.MatchString(prev) {
			reason = strings.Join(strings.Fields(quotedSpan.ReplaceAllString(reason, "")), " ")
		} else {
			reason = prev
		}
	}
	return truncate(strings.TrimSuffix(reason, "."), width)
}

// targetError reports whether a control's error is a failure to reach a target, which the errors
// block says once, by target, instead of under every control that tried.
func targetError(d Data, control, msg string) bool {
	for _, f := range d.Run.Stats.Failures {
		if f.Control == control && strings.TrimSpace(msg) == f.Detail {
			return true
		}
	}
	return false
}

// caveat is one shortfall in what the run covered. It fails the run only when the gate lists its
// key in failOnCaveats.
type caveat struct {
	component, what, detail string
	// key is the kind as gate.failOnCaveats names it, and the word the Caveat column prints, so a
	// reader who wants a kind to fail the run copies it from the row into the setting.
	key saga.CaveatKind
}

// caveats gathers what was declared and not checked, what could not be measured, and the files and
// checks that were not read, by component.
func caveats(d Data) []caveat {
	var out []caveat
	for _, g := range d.Uncovered {
		out = append(out, caveat{g.Component, g.Surface, strings.Join(g.Controls, ", ") + " off",
			saga.CaveatNotChecked})
	}
	for _, sk := range d.Run.Skipped {
		out = append(out, caveat{sk.Component, sk.Scanner, sk.Reason, saga.CaveatNotMeasured})
	}
	// A service's checks the scan could not evaluate, one row per service, because one granted
	// permission clears all of them. The control is not named: the service says which one it is.
	for _, g := range d.Run.UnreadChecks {
		out = append(out, caveat{g.Component, g.Group,
			english.Count(len(g.Checks), "check") + " · " + g.Reason, saga.CaveatUnreadChecks})
	}
	// An imported file that names no revision: read, but nothing shows it describes the code this
	// run scanned.
	for _, u := range unboundImports(d) {
		out = append(out, caveat{u.component, u.file, "names no commit, so nothing ties its findings to this code",
			saga.CaveatUnboundImports})
	}
	for _, g := range unreadByComponent(d.Run.Inputs, d.Run.Targets) {
		for _, f := range g.files {
			out = append(out, caveat{g.component, f.label,
				fmt.Sprintf("%s (%s)", f.reason, strings.Join(f.controls, ", ")), saga.CaveatUnreadFiles})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].component < out[j].component })
	return out
}

// fails reports whether the gate lists this caveat's kind in failOnCaveats.
func (c caveat) fails(d Data) bool { return slices.Contains(d.FailOnCaveats, c.key) }

// caveatGroup is one component's caveats, in the order caveats lists them.
type caveatGroup struct {
	component string
	caveats   []caveat
}

// caveatsByComponent folds the run's caveats under their components, which is how the HTML and
// markdown reports list them. caveats sorts by component, so each group is a run of rows.
func caveatsByComponent(cs []caveat) []caveatGroup {
	var out []caveatGroup
	for _, c := range cs {
		if n := len(out); n > 0 && out[n-1].component == c.component {
			out[n-1].caveats = append(out[n-1].caveats, c)
			continue
		}
		out = append(out, caveatGroup{component: c.component, caveats: []caveat{c}})
	}
	return out
}

// caveatSetting names the setting that makes a caveat fail the run and the kinds it lists, in the
// words every format prints: `config.gate.failOnCaveats: unread-files`.
func caveatSetting(d Data) string {
	return fmt.Sprintf("%s: %s", cmp.Or(d.FailOnCaveatsFrom, "config.gate.failOnCaveats"),
		strings.Join(namesOfKinds(d.FailOnCaveats), ", "))
}

// splitCaveats divides the run's caveats into the ones the gate fails on and the rest.
func splitCaveats(d Data) (failing, rest []caveat) {
	for _, c := range caveats(d) {
		if c.fails(d) {
			failing = append(failing, c)
		} else {
			rest = append(rest, c)
		}
	}
	return failing, rest
}

// FailedCaveat is a caveat whose kind the gate lists in failOnCaveats. Declared in skald, which
// writes it into report.json.
type FailedCaveat = skald.FailedCaveat

// FailedCaveats returns the run's caveats of the kinds d.FailOnCaveats lists, by component.
func FailedCaveats(d Data) []FailedCaveat {
	failing, _ := splitCaveats(d)
	out := make([]FailedCaveat, 0, len(failing))
	for _, c := range failing {
		out = append(out, FailedCaveat{Component: c.component, What: c.what, Kind: c.key, Detail: c.detail})
	}
	return out
}

// shownRows is how many of n rows a block draws, and whether some were left out.
func shownRows(d Data, n int) (int, bool) {
	if consoleFixFirstLimit(d.TopN) < 0 || n <= errorRowsShown {
		return n, false
	}
	return errorRowsShown, true
}

// writeErrors draws the targets no scanner could read. Images a registry refused are grouped under
// that registry, with its answer and the command that changes it said once; every other target is
// a row of its own, with its reason.
func writeErrors(w io.Writer, col tui.Painter, d Data) {
	missed := notReached(d)
	if len(missed) == 0 {
		return
	}
	_, _ = fmt.Fprintf(w, "%s  %s\n", heading(col, "Errors"), col.Paint(cFail,
		fmt.Sprintf("%d of %s not reached", len(missed), english.Count(len(d.Run.Targets), "target"))))
	n, capped := shownRows(d, len(missed))
	cols := tui.Columns(w)
	groups, rest := byRegistry(missed[:n])

	for _, g := range groups {
		_, _ = fmt.Fprintf(w, "  %s  %s\n", col.Paint(tui.StyleStrong, g.host), col.Paint(cDim, g.said))
		rows := make([]unreachedRow, len(g.images))
		for i, m := range g.images {
			rows[i] = unreachedRow{name: inRegistry(m.Target, g.host), components: m.Components}
		}
		writeUnreached(w, col, cols, "    ", "Image", rows)
		if g.login {
			_, _ = fmt.Fprintf(w, "  %s  %s\n", col.Paint(cAccent, loginCommand(g.host)), col.Paint(cDim, "then scan again"))
		}
	}
	if len(rest) > 0 {
		rows := make([]unreachedRow, len(rest))
		for i, m := range rest {
			rows[i] = unreachedRow{name: m.Kind + " " + shownTarget(m.Kind, m.Target), components: m.Components,
				why: shortReason(m.Detail, whyWidth)}
		}
		writeUnreached(w, col, cols, "  ", "Target", rows)
	}
	if capped {
		_, _ = fmt.Fprintf(w, "  %s\n", col.Paint(cDim,
			fmt.Sprintf("… and %d more · --top 0 lists every one", len(missed)-n)))
	}
	_, _ = fmt.Fprintln(w)
}

// unreachedRow is one target the errors block names: what it is, the components it leaves
// unscanned, and why it was not read where its group does not already say.
type unreachedRow struct {
	name       string
	components []string
	why        string
}

// writeUnreached draws rows as a table when the table fits a terminal cols wide, and otherwise each
// target on a line of its own with its components and reason on the line under it. A table cut to
// fit would cut the reason, which is the one column a reader needs whole, and the target's name is
// an address, useless shortened. A cols of zero is a file or a pipe, with no width to respect.
func writeUnreached(w io.Writer, col tui.Painter, cols int, indent, first string, rows []unreachedRow) {
	headers := []string{first, "Components"}
	withWhy := slices.ContainsFunc(rows, func(r unreachedRow) bool { return r.why != "" })
	if withWhy {
		headers = append(headers, "Why")
	}
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = utf8.RuneCountInString(h)
	}
	for _, r := range rows {
		widths[0] = max(widths[0], utf8.RuneCountInString(r.name))
		widths[1] = max(widths[1], utf8.RuneCountInString(strings.Join(r.components, ", ")))
		if withWhy {
			widths[2] = max(widths[2], utf8.RuneCountInString(r.why))
		}
	}
	natural := len(indent) + 2*(len(widths)-1)
	for _, n := range widths {
		natural += n
	}

	if cols > 0 && natural > cols {
		for _, r := range rows {
			below := componentsLabel(r.components)
			if r.why != "" {
				below += " · " + r.why
			}
			_, _ = fmt.Fprintf(w, "%s%s\n", indent, col.Paint(tui.StyleStrong, r.name))
			_, _ = fmt.Fprintf(w, "%s  %s\n", indent, col.Paint(cDim, truncate(below, max(cols-len(indent)-2, minBelow))))
		}
		return
	}
	t := tui.NewTable(col, headers...).Indent(indent)
	for _, r := range rows {
		cells := []tui.Cell{tui.Styled(tui.StyleStrong, r.name), tui.Styled(cDim, strings.Join(r.components, ", "))}
		if withWhy {
			cells = append(cells, tui.Styled(cDim, r.why))
		}
		t.Row(cells...)
	}
	t.Render(w)
}

// minBelow is the narrowest the line under a target is cut to, on a terminal too narrow for its
// indent: below that, a cut says less than a wrap does.
const minBelow = 40

// componentsLabel names a target's components with the word for them, for a line that has no
// column heading to say what they are.
func componentsLabel(cs []string) string {
	return english.Choose(len(cs), "component", "components") + " " + strings.Join(cs, ", ")
}

// writeCaveats draws a row per shortfall in what the run covered.
//
// One block for every caveat, the ones the gate fails on among them, each marked where it sits.
// Moving those into the errors would put two kinds of row under one heading, a target no scanner
// read beside a file no scanner read, and split a component's caveats across two blocks. The
// heading says how many fail the run and which setting made them, so a reader can find the line to
// change.
func writeCaveats(w io.Writer, col tui.Painter, d Data) {
	cs := caveats(d)
	if len(cs) == 0 {
		return
	}
	failing, _ := splitCaveats(d)
	note := col.Paint(cDim, "do not fail the run · config.gate.failOnCaveats lists the kinds that do")
	if len(failing) > 0 {
		setting := caveatSetting(d)
		verb := "fail"
		if len(failing) == 1 {
			verb = "fails"
		}
		note = col.Paint(cFail, fmt.Sprintf("%d %s the run · %s", len(failing), verb, setting))
		// Accepted, they are reported as an error accepted, which is what the verdict's own note
		// says beside PASS.
		if d.AcceptedErrors {
			note = col.Paint(cAccent, fmt.Sprintf("%d accepted by --allow-scan-errors · %s", len(failing), setting))
		}
	}
	_, _ = fmt.Fprintf(w, "%s  %s\n", heading(col, "Caveats"), note)
	t := tui.NewTable(col, "Component", "What", "Caveat", "Why").Indent("  ")
	n, capped := shownRows(d, len(cs))
	for _, c := range cs[:n] {
		kind := tui.Styled(cAccent, string(c.key))
		// The mark only where something is marked, so a run with nothing failing reads as it always
		// did, and the kinds stay aligned under one another when something is.
		if len(failing) > 0 {
			kind = tui.Styled(cAccent, "  "+string(c.key))
			if c.fails(d) {
				kind = tui.Styled(cFail, "✗ "+string(c.key))
			}
		}
		t.Row(tui.Styled(tui.StyleStrong, c.component), tui.Styled(tui.StyleStrong, c.what),
			kind, tui.Styled(cDim, truncate(c.detail, whyWidth)))
	}
	t.Render(w)
	if capped {
		_, _ = fmt.Fprintf(w, "  %s\n", col.Paint(cDim,
			fmt.Sprintf("… and %d more · --top 0 lists every one", len(cs)-n)))
	}
	_, _ = fmt.Fprintln(w)
}

// failedCaveatNote is what a component's row says about its caveats the gate fails on: each one's
// kind and what it names, the words a reader would search the caveats for.
func failedCaveatNote(cs []FailedCaveat) string {
	parts := make([]string, 0, len(cs))
	for _, c := range cs {
		parts = append(parts, string(c.Kind)+" "+c.What)
	}
	return strings.Join(parts, ", ")
}

// joinNotes puts two notes on one row, either of which may be empty.
func joinNotes(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	}
	return a + " · " + b
}

// namesOfKinds spells kinds of caveat as the setting writes them.
func namesOfKinds(kinds []saga.CaveatKind) []string {
	out := make([]string, len(kinds))
	for i, k := range kinds {
		out[i] = string(k)
	}
	return out
}

// unboundImport is an imported SARIF file that stated no commit.
type unboundImport struct{ component, file string }

// unboundImports reads them off the import scanner's provenance, which records the commit each
// file was checked against or that it named none.
func unboundImports(d Data) []unboundImport {
	var out []unboundImport
	seen := map[unboundImport]bool{}
	for _, name := range sortedControlNames(d) {
		for _, p := range d.Run.Controls[name].Report.Provenance {
			if p.Tool != plugin.ImportScanner {
				continue
			}
			var u unboundImport
			bound := true
			for _, f := range p.Fields {
				switch f.Key {
				case "component":
					u.component = f.Value
				case "file":
					u.file = f.Value
				case "commit":
					bound = f.Value != "not stated"
				}
			}
			if !bound && !seen[u] {
				seen[u] = true
				out = append(out, u)
			}
		}
	}
	return out
}
