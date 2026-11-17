package diff

import (
	"fmt"
	"io"
	"strings"

	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/tui"
)

// rerankedResults is the head side of each reranked finding, for the band strip.
func rerankedResults(rs []Rerank) []sarif.Result {
	out := make([]sarif.Result, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.Result)
	}
	return out
}

// rerankBand is the band a finding had and the band it has, "P1 → P3".
func rerankBand(r Rerank) string { return dash(r.From) + " → " + dash(r.Priority) }

// directions counts the reranked findings by which way they went, naming only a direction that
// happened: "2 raised, 29 lowered", or "29 lowered" where nothing was raised.
func directions(rs []Rerank) string {
	raised := 0
	for _, r := range rs {
		if r.Raised() {
			raised++
		}
	}
	var parts []string
	if raised > 0 {
		parts = append(parts, fmt.Sprintf("%d raised", raised))
	}
	if lowered := len(rs) - raised; lowered > 0 {
		parts = append(parts, fmt.Sprintf("%d lowered", lowered))
	}
	return strings.Join(parts, ", ")
}

// capReranks applies --top to the reranked findings, and says what the heading should read: how
// many there are, or the top of them --top keeps, then which way they went.
func capReranks(rs []Rerank, top int) (shown []Rerank, heading string) {
	shown, heading = rs, fmt.Sprint(len(rs))
	if top > 0 && len(rs) > top {
		shown, heading = rs[:top], fmt.Sprintf("top %d of %d", top, len(rs))
	}
	return shown, heading + " · " + directions(rs)
}

// rerankedComponents reports whether the rows name more than one component, the rule the CHANGED
// table follows for its Component column.
func rerankedComponents(rs []Rerank) bool {
	for _, r := range rs {
		if r.Component != rs[0].Component {
			return true
		}
	}
	return false
}

// writeReranked draws the findings whose band changed and nothing else did, each with the band it
// had and the band it has, raised ones first.
//
// A row each, as the moves whose band changed get one. The band is what a reader triages by, so a
// change to it is a change to their list, and the descriptor edit or signal behind it is the part
// of the change to check.
func writeReranked(w io.Writer, col tui.Painter, r Result, opts Options) {
	if len(r.Reranked) == 0 {
		return
	}
	shown, heading := capReranks(r.Reranked, opts.Top)
	_, _ = fmt.Fprintf(w, "\n%s  %s\n", col.Paint(tui.StyleMuted, "RERANKED"), col.Paint(tui.StyleMuted, heading))
	withComponent := rerankedComponents(shown)
	cols := []string{"Priority", "Severity", "Rule", "Scanner"}
	if withComponent {
		cols = append(cols, "Component")
	}
	t := tui.NewTable(col, append(cols, "Location")...).Indent("  ").StyledNotes()
	for _, rr := range shown {
		cells := []tui.Cell{
			tui.Styled(tui.PriorityStyle(rr.Priority), rerankBand(rr)),
			tui.PlainCell(string(rr.RankedSeverity())),
			{Text: rr.RuleID, URL: r.HelpURI(rr.RuleID)},
			tui.PlainCell(dash(rr.Tool)),
		}
		if withComponent {
			cells = append(cells, tui.PlainCell(dash(rr.Component)))
		}
		cells = append(cells, tui.Styled(tui.StyleMuted, loc(rr.Location.URI, rr.Location.StartLine)))
		if opts.View == ViewCompact {
			t.Row(cells...)
			continue
		}
		t.RowWithNotes([]string{findingTitle(Entry{Result: rr.Result})}, cells...)
	}
	t.Render(w)
	if len(shown) < len(r.Reranked) {
		_, _ = fmt.Fprintf(w, "\n%s\n", col.Paint(tui.StyleMuted,
			fmt.Sprintf("… and %d not listed.", len(r.Reranked)-len(shown))))
	}
}

// writeMarkdownReranked is writeReranked for the pull-request comment.
func writeMarkdownReranked(w io.Writer, r Result, opts Options) {
	if len(r.Reranked) == 0 {
		return
	}
	shown, heading := capReranks(r.Reranked, opts.Top)
	_, _ = fmt.Fprintf(w, "\n### Reranked · %s\n\n", heading)
	withComponent := rerankedComponents(shown)
	if withComponent {
		_, _ = fmt.Fprintln(w, "| Priority | Severity | Rule | Scanner | Component | Location |")
		_, _ = fmt.Fprintln(w, "|---|---|---|---|---|---|")
	} else {
		_, _ = fmt.Fprintln(w, "| Priority | Severity | Rule | Scanner | Location |")
		_, _ = fmt.Fprintln(w, "|---|---|---|---|---|")
	}
	for _, rr := range shown {
		id := "`" + rr.RuleID + "`"
		if u := r.HelpURI(rr.RuleID); u != "" {
			id = "[" + id + "](" + u + ")"
		}
		component := ""
		if withComponent {
			component = " " + dash(rr.Component) + " |"
		}
		_, _ = fmt.Fprintf(w, "| %s | %s | %s | %s |%s %s |\n", rerankBand(rr), rr.RankedSeverity(), id,
			dash(rr.Tool), component, loc(rr.Location.URI, rr.Location.StartLine))
	}
	if len(shown) < len(r.Reranked) {
		_, _ = fmt.Fprintf(w, "\n_…and %d not listed._\n", len(r.Reranked)-len(shown))
	}
}
