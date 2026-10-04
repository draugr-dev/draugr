package report

import (
	"cmp"
	"fmt"
	"io"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/draugr-dev/draugr/internal/english"
	"github.com/draugr-dev/draugr/pkg/engine"
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
// sit together. A target no scanner was run for is a caveat, under "not measured", because nothing
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
var kindOrder = []string{"repository", "image", "host", "cluster", "account"}

// bareFailure matches a clause that says something failed and not what.
var bareFailure = regexp.MustCompile(`^(?i:fatal|error|exit status \d+)$`)

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

// caveat is one shortfall that does not fail the run.
type caveat struct{ component, what, kind, detail string }

// caveats gathers what was declared and not checked, what could not be measured, and the files and
// checks that were not read, by component.
func caveats(d Data) []caveat {
	var out []caveat
	for _, g := range d.Uncovered {
		out = append(out, caveat{g.Component, g.Surface, "not checked", strings.Join(g.Controls, ", ") + " off"})
	}
	for _, sk := range d.Run.Skipped {
		out = append(out, caveat{sk.Component, sk.Scanner, "not measured", sk.Reason})
	}
	// A service's checks the scan could not evaluate, one row per service, because one granted
	// permission clears all of them. The control is not named: the service says which one it is.
	for _, g := range d.Run.UnreadChecks {
		out = append(out, caveat{g.Component, g.Group, "unread",
			english.Count(len(g.Checks), "check") + " · " + g.Reason})
	}
	for _, g := range unreadByComponent(d.Run.Inputs) {
		for _, f := range g.files {
			out = append(out, caveat{g.component, f.label, "unread",
				fmt.Sprintf("%s (%s)", f.reason, strings.Join(f.controls, ", "))})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].component < out[j].component })
	return out
}

// shownRows is how many of n rows a block draws, and whether some were left out.
func shownRows(d Data, n int) (int, bool) {
	if consoleFixFirstLimit(d.TopN) < 0 || n <= errorRowsShown {
		return n, false
	}
	return errorRowsShown, true
}

// writeErrors draws a row per target no scanner could read.
func writeErrors(w io.Writer, col tui.Painter, d Data) {
	missed := notReached(d)
	if len(missed) == 0 {
		return
	}
	_, _ = fmt.Fprintf(w, "%s  %s\n", heading(col, "Errors"), col.Paint(cFail,
		fmt.Sprintf("%d of %s not reached", len(missed), english.Count(len(d.Run.Targets), "target"))))
	t := tui.NewTable(col, "Target", "Components", "Why").Indent("  ")
	n, capped := shownRows(d, len(missed))
	for _, m := range missed[:n] {
		t.Row(tui.Styled(tui.StyleStrong, m.Kind+" "+m.Target),
			tui.Styled(cDim, strings.Join(m.Components, ", ")),
			tui.Styled(cDim, shortReason(m.Detail, whyWidth)))
	}
	t.Render(w)
	if capped {
		_, _ = fmt.Fprintf(w, "  %s\n", col.Paint(cDim,
			fmt.Sprintf("… and %d more · --top 0 lists every one", len(missed)-n)))
	}
	_, _ = fmt.Fprintln(w)
}

// writeCaveats draws a row per shortfall that does not fail the run.
func writeCaveats(w io.Writer, col tui.Painter, d Data) {
	cs := caveats(d)
	if len(cs) == 0 {
		return
	}
	_, _ = fmt.Fprintf(w, "%s  %s\n", heading(col, "Caveats"), col.Paint(cDim, "do not fail the run"))
	t := tui.NewTable(col, "Component", "What", "Caveat", "Why").Indent("  ")
	n, capped := shownRows(d, len(cs))
	for _, c := range cs[:n] {
		t.Row(tui.Styled(tui.StyleStrong, c.component), tui.Styled(tui.StyleStrong, c.what),
			tui.Styled(cAccent, c.kind), tui.Styled(cDim, truncate(c.detail, whyWidth)))
	}
	t.Render(w)
	if capped {
		_, _ = fmt.Fprintf(w, "  %s\n", col.Paint(cDim,
			fmt.Sprintf("… and %d more · --top 0 lists every one", len(cs)-n)))
	}
	_, _ = fmt.Fprintln(w)
}
