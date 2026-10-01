package diff

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/tui"
)

// nothingChanged is the line a diff with no changed finding prints in place of the table.
//
// A diff whose only news is findings that moved component has still compared something, and the
// moved section follows, so it does not claim every finding was already where it was.
func nothingChanged(r Result) string {
	if len(r.Moved) > 0 {
		return "Nothing is new or fixed."
	}
	return "Nothing changed. Every finding was already there."
}

// movedResults is the head side of each move, for the band strip.
func movedResults(ms []Move) []sarif.Result {
	out := make([]sarif.Result, 0, len(ms))
	for _, m := range ms {
		out = append(out, m.Result)
	}
	return out
}

// movePriority is the band a moved finding has, with the band it had where the two differ.
func movePriority(m Move) string {
	if m.Was.Priority != m.Priority {
		return dash(m.Was.Priority) + " → " + dash(m.Priority)
	}
	return dash(m.Priority)
}

// movePair is the findings that moved from one component to another.
type movePair struct {
	from, to string
	moves    []Move
}

// movePairs groups moves by the two components, in name order.
//
// One line per pair rather than one per finding: splitting a component moves every finding it had,
// and none of them is work, so a row each is a table nobody has to read.
func movePairs(ms []Move) []movePair {
	var out []movePair
	at := map[[2]string]int{}
	for _, m := range ms {
		k := [2]string{m.Was.Component, m.Component}
		i, ok := at[k]
		if !ok {
			i = len(out)
			at[k] = i
			out = append(out, movePair{from: k[0], to: k[1]})
		}
		out[i].moves = append(out[i].moves, m)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].from != out[j].from {
			return out[i].from < out[j].from
		}
		return out[i].to < out[j].to
	})
	return out
}

// shifts names each change of band in a pair, "4 P1 → P2", or says there was none.
func shifts(ms []Move) string {
	n := map[string]int{}
	for _, m := range ms {
		if m.Was.Priority != m.Priority {
			n[movePriority(m)]++
		}
	}
	if len(n) == 0 {
		return "unchanged"
	}
	keys := make([]string, 0, len(n))
	for k := range n {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%d %s", n[k], k))
	}
	return strings.Join(parts, ", ")
}

// reprioritized is the moves whose band changed with the component.
//
// These are the rows a reviewer reads. The finding is the same, and its band changed because the
// component it now belongs to declares a different exposure or criticality, which is a claim in the
// descriptor somebody should check.
func reprioritized(ms []Move) []Move {
	var out []Move
	for _, m := range ms {
		if m.Was.Priority != m.Priority {
			out = append(out, m)
		}
	}
	return out
}

// capMoves applies --top to a list of moves, and says what the heading should read.
func capMoves(ms []Move, top int) (shown []Move, heading string) {
	if top > 0 && len(ms) > top {
		return ms[:top], fmt.Sprintf("top %d of %d, by priority", top, len(ms))
	}
	return ms, fmt.Sprintf("%d, by priority", len(ms))
}

// writeMoved draws the findings that changed component: a line per pair of components, then a row
// for each finding whose band changed with it.
func writeMoved(w io.Writer, col tui.Painter, r Result, opts Options) {
	if len(r.Moved) == 0 {
		return
	}
	_, _ = fmt.Fprintf(w, "\n%s  %s\n", col.Paint(tui.StyleMuted, "MOVED"),
		col.Paint(tui.StyleMuted, fmt.Sprint(len(r.Moved))))
	pairs := tui.NewTable(col, "From", "To", "Findings", "Priority").Indent("  ")
	for _, p := range movePairs(r.Moved) {
		pairs.Row(tui.PlainCell(dash(p.from)), tui.PlainCell(dash(p.to)),
			tui.PlainCell(fmt.Sprint(len(p.moves))), tui.Styled(tui.StyleMuted, shifts(p.moves)))
	}
	pairs.Render(w)

	re := reprioritized(r.Moved)
	if len(re) == 0 {
		return
	}
	shown, heading := capMoves(re, opts.Top)
	_, _ = fmt.Fprintf(w, "\n%s  %s\n", col.Paint(tui.StyleMuted, "PRIORITY CHANGED"), col.Paint(tui.StyleMuted, heading))
	t := tui.NewTable(col, "Priority", "Severity", "Rule", "Scanner", "Component", "Location").Indent("  ").StyledNotes()
	for _, m := range shown {
		cells := []tui.Cell{
			tui.Styled(tui.PriorityStyle(m.Priority), movePriority(m)),
			tui.PlainCell(string(m.Severity(""))),
			{Text: m.RuleID, URL: r.HelpURI(m.RuleID)},
			tui.PlainCell(dash(m.Tool)),
			tui.PlainCell(dash(m.Was.Component) + " → " + dash(m.Component)),
			tui.Styled(tui.StyleMuted, loc(m.Location.URI, m.Location.StartLine)),
		}
		if opts.View == ViewCompact {
			t.Row(cells...)
			continue
		}
		t.RowWithNotes([]string{findingTitle(Entry{Result: m.Result})}, cells...)
	}
	t.Render(w)
	if len(shown) < len(re) {
		_, _ = fmt.Fprintf(w, "\n%s\n", col.Paint(tui.StyleMuted,
			fmt.Sprintf("… and %d not listed.", len(re)-len(shown))))
	}
}

// writeMarkdownMoved is writeMoved for the pull-request comment.
func writeMarkdownMoved(w io.Writer, r Result, opts Options) {
	if len(r.Moved) == 0 {
		return
	}
	_, _ = fmt.Fprintf(w, "\n### Moved · %d\n\n", len(r.Moved))
	_, _ = fmt.Fprintln(w, "| From | To | Findings | Priority |")
	_, _ = fmt.Fprintln(w, "|---|---|---:|---|")
	for _, p := range movePairs(r.Moved) {
		_, _ = fmt.Fprintf(w, "| %s | %s | %d | %s |\n", dash(p.from), dash(p.to), len(p.moves), shifts(p.moves))
	}

	re := reprioritized(r.Moved)
	if len(re) == 0 {
		return
	}
	shown, heading := capMoves(re, opts.Top)
	_, _ = fmt.Fprintf(w, "\n### Priority changed · %s\n\n", heading)
	_, _ = fmt.Fprintln(w, "| Priority | Severity | Rule | Scanner | Component | Location |")
	_, _ = fmt.Fprintln(w, "|---|---|---|---|---|---|")
	for _, m := range shown {
		id := "`" + m.RuleID + "`"
		if u := r.HelpURI(m.RuleID); u != "" {
			id = "[" + id + "](" + u + ")"
		}
		_, _ = fmt.Fprintf(w, "| %s | %s | %s | %s | %s → %s | %s |\n", movePriority(m), m.Severity(""), id,
			dash(m.Tool), dash(m.Was.Component), dash(m.Component), loc(m.Location.URI, m.Location.StartLine))
	}
	if len(shown) < len(re) {
		_, _ = fmt.Fprintf(w, "\n_…and %d not listed._\n", len(re)-len(shown))
	}
}
