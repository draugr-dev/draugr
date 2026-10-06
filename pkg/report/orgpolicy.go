package report

import (
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/draugr-dev/draugr/internal/english"
	"github.com/draugr-dev/draugr/pkg/skald"
	"github.com/draugr-dev/draugr/pkg/tui"
)

// The organization's policy, as doctor and a scan show it.
//
// Every word of a verdict comes from the server: each item is joined as `<field>: <found> ·
// <constraint>: <expected>` and each setting's terms as the server's own phrases. Nothing here knows
// what a rule means, so a rule the organization adds reads the same here as on the server's pages.

// policyHeading is the block's first line: what it was judged against, or why it was not.
func policyHeading(col tui.Painter, p *skald.PolicyCheck, project string) string {
	if !p.Checked {
		return heading(col, "Policy") + "  " + col.Paint(cFail, "not checked") + col.Paint(cDim, " · "+p.Reason)
	}
	var parts []string
	if project != "" {
		parts = append(parts, project)
	}
	parts = append(parts, fmt.Sprintf("version %d", p.Version))
	line := heading(col, "Policy") + "  " + strings.Join(parts, col.Paint(cDim, " · "))
	if p.Server != "" {
		line += col.Paint(cDim, " · "+p.Server)
	}
	return line
}

// termPaint lights a term that acts on this run and leaves one that only observes dim.
func termPaint(col tui.Painter, v skald.PolicyVerdict, text string) string {
	if v.Violates() && v.Acts != "" && v.Acts != skald.PolicyNone {
		return col.Paint(cFail, text)
	}
	return col.Paint(cDim, text)
}

// policyRow is one line a block prints: the rule, once per verdict, and one item.
type policyRow struct {
	rule, item string
	verdict    skald.PolicyVerdict
	first      bool
}

func runeWidth(s string) int { return utf8.RuneCountInString(s) }

func pad(s string, width int) string {
	if n := runeWidth(s); n < width {
		return s + strings.Repeat(" ", width-n)
	}
	return s
}

// writePolicy is a scan's POLICY block: each verdict the run breaks, or a line saying none is
// broken or that the policy could not be checked. Nil where the descriptor publishes to no server
// that judges one.
func writePolicy(w io.Writer, col tui.Painter, p *skald.PolicyCheck) {
	if p == nil {
		return
	}
	_, _ = fmt.Fprintln(w)
	var rows []policyRow
	checked := 0
	for _, v := range p.Verdicts {
		if v.Evaluated() {
			checked++
		}
		if !v.Violates() {
			continue
		}
		for i, item := range v.Breaking() {
			rows = append(rows, policyRow{rule: v.Rule, item: item.String(), verdict: v, first: i == 0})
		}
	}
	head := policyHeading(col, p, "")
	if p.Checked && len(rows) == 0 {
		head += col.Paint(cDim, fmt.Sprintf(" · %s checked, none broken", english.Count(checked, "rule")))
	}
	_, _ = fmt.Fprintln(w, head)
	ruleW, itemW := 0, 0
	for _, r := range rows {
		ruleW = max(ruleW, runeWidth(r.rule))
		itemW = max(itemW, runeWidth(r.item))
	}
	for _, r := range rows {
		rule := ""
		if r.first {
			rule = r.rule
		}
		_, _ = fmt.Fprintf(w, "  %s  %s  %s%s\n", pad(rule, ruleW), pad(r.item, itemW),
			col.Paint(cDim, r.verdict.Profile+" · "), termPaint(col, r.verdict, r.verdict.Term()))
	}
}

// WritePolicyTable is doctor's POLICY section: every rule that reaches the project, passing and
// broken, with what its setting does to a run that breaks it.
func WritePolicyTable(w io.Writer, col tui.Painter, p *skald.PolicyCheck, project string) {
	_, _ = fmt.Fprintln(w, policyHeading(col, p, project))
	if !p.Checked || len(p.Verdicts) == 0 {
		return
	}
	type row struct {
		rule, profile, mark, result, term string
		verdict                           skald.PolicyVerdict
		cont                              bool
	}
	var rows []row
	for _, v := range p.Verdicts {
		switch {
		case v.Evaluated() && len(v.Items) > 0:
			items := v.Items
			if v.Violates() {
				items = v.Breaking()
			}
			mark := "✓"
			if v.Violates() {
				mark = "✗"
			}
			for i, item := range items {
				r := row{mark: mark, result: item.String(), verdict: v, cont: i > 0}
				if i == 0 {
					r.rule, r.profile, r.term = v.Rule, v.Profile, v.Term()
				}
				rows = append(rows, r)
			}
		default:
			// Not judged, or asking nothing of this project. The server says why in its detail.
			why := v.Detail
			if why == "" {
				why = strings.ReplaceAll(v.State, "_", " ")
			}
			rows = append(rows, row{rule: v.Rule, profile: v.Profile, mark: "–", result: why, term: v.Term(), verdict: v})
		}
	}
	ruleW, profW, resW := runeWidth("Rule"), runeWidth("Profile"), runeWidth("Result")
	for _, r := range rows {
		ruleW = max(ruleW, runeWidth(r.rule))
		profW = max(profW, runeWidth(r.profile))
		resW = max(resW, runeWidth(r.mark)+1+runeWidth(r.result))
	}
	_, _ = fmt.Fprintln(w, col.Paint(cDim, pad("Rule", ruleW)+"  "+pad("Profile", profW)+"  "+pad("Result", resW)+"  If broken"))
	for _, r := range rows {
		result := pad(r.mark+" "+r.result, resW)
		switch {
		case r.verdict.Violates():
			result = col.Paint(cFail, result)
		case r.verdict.Evaluated():
			result = col.Paint(tui.StyleFixed, result)
		default:
			result = col.Paint(cDim, result)
		}
		_, _ = fmt.Fprintf(w, "%s  %s  %s  %s\n", pad(r.rule, ruleW), pad(r.profile, profW), result,
			termPaint(col, r.verdict, r.term))
	}
}

// WritePolicyRefused is what a scan prints when the policy refuses it before any scanner starts.
func WritePolicyRefused(w io.Writer, col tui.Painter, project, release string, p *skald.PolicyCheck) {
	title := "DRAUGR   " + col.Paint(cFail, "REFUSED") + "   " + project
	if release != "" {
		title += " " + release
	}
	_, _ = fmt.Fprintln(w, title)
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, policyHeading(col, p, ""))
	var rows []policyRow
	for _, v := range p.Verdicts {
		if v.Acts != skald.PolicyRefuse {
			continue
		}
		for i, item := range v.Breaking() {
			rows = append(rows, policyRow{rule: v.Rule, item: item.String(), verdict: v, first: i == 0})
		}
	}
	ruleW, itemW := 0, 0
	for _, r := range rows {
		ruleW = max(ruleW, runeWidth(r.rule))
		itemW = max(itemW, runeWidth(r.item))
	}
	for _, r := range rows {
		rule := ""
		if r.first {
			rule = r.rule
		}
		_, _ = fmt.Fprintf(w, "  %s  %s  %s%s\n", pad(rule, ruleW), pad(r.item, itemW),
			col.Paint(cDim, r.verdict.Profile+" · "), termPaint(col, r.verdict, r.verdict.Term()))
	}
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, "No scanner ran.")
}
