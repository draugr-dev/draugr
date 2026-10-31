package report

import (
	"regexp"
	"strings"
	"testing"
)

// phoneRules is the stylesheet's phone block, comments removed, as a map from each rule's selector
// to its declarations, whitespace folded so a selector split across lines still matches.
func phoneRules(t *testing.T) map[string]string {
	t.Helper()
	css := regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(htmlDoc, "")
	const open = "@media (max-width: 40rem) {"
	i := strings.Index(css, open)
	if i < 0 {
		t.Fatal("the stylesheet has no phone block")
	}
	body, depth := css[i+len(open):], 0
	for j, c := range body {
		if c == '{' {
			depth++
		} else if c == '}' {
			if depth == 0 {
				body = body[:j]
				break
			}
			depth--
		}
	}
	rules := map[string]string{}
	for _, m := range regexp.MustCompile(`([^{}]+)\{([^{}]*)\}`).FindAllStringSubmatch(body, -1) {
		rules[strings.Join(strings.Fields(m[1]), " ")] = strings.Join(strings.Fields(m[2]), " ")
	}
	return rules
}

// ruleSetting is the selector of the one phone rule that sets decl.
func ruleSetting(t *testing.T, rules map[string]string, decl string) string {
	t.Helper()
	var found []string
	for sel, decls := range rules {
		if strings.Contains(decls, decl) {
			found = append(found, sel)
		}
	}
	if len(found) != 1 {
		t.Fatalf("%d phone rules set %q, want one: %q", len(found), decl, found)
	}
	return found[0]
}

// isList is the classes a selector's :is() names.
func isList(sel string) []string {
	m := regexp.MustCompile(`:is\(([^)]*)\)`).FindStringSubmatch(sel)
	if m == nil {
		return nil
	}
	var out []string
	for _, c := range strings.Split(m[1], ",") {
		out = append(out, strings.TrimPrefix(strings.TrimSpace(c), "."))
	}
	return out
}

// On a phone, every row that wears chips starts its text beside them and continues under them at
// the row's full width. The row types are read from the template, so a row type added with chips
// and left out of the phone rule fails here instead of keeping its desktop gutter on a 390px
// screen. A float inside a grid item does nothing, so the row leaving the grid is held too.
func TestOnAPhoneEveryRowWithChipsGivesItsTextTheFullWidth(t *testing.T) {
	var chipped []string
	for _, m := range regexp.MustCompile(`<div class="([a-z-]+)"[^>]*>\s*<span class="chips">`).FindAllStringSubmatch(htmlDoc, -1) {
		chipped = append(chipped, m[1])
	}
	if len(chipped) == 0 {
		t.Fatal("no row in the template wears chips; the pattern this test reads has moved")
	}
	rules := phoneRules(t)
	float := ruleSetting(t, rules, "float: left")
	if !strings.HasSuffix(float, "> .chips") {
		t.Fatalf("the phone rule that floats something floats %q, not the chips", float)
	}
	flow := ruleSetting(t, rules, "display: flow-root")
	for _, row := range chipped {
		if !strings.Contains(" "+strings.Join(isList(float), " ")+" ", " "+row+" ") {
			t.Errorf("on a phone the chips of a .%s row keep their gutter: %q", row, float)
		}
		if !strings.Contains(" "+strings.Join(isList(flow), " ")+" ", " "+row+" ") {
			t.Errorf("on a phone a .%s row stays a grid, so its chips cannot float: %q", row, flow)
		}
	}
	if !strings.Contains(flow, ":not(.cut)") {
		t.Errorf("the phone rule that lays a row out shows the rows paging and filters cut: %q", flow)
	}
}

// On a phone, the summary of a row that opens wraps like any other title, so a long rule id stays
// inside the row with the mark saying it opens. Held to one line, a long id runs past the panel,
// which cuts off what overflows it. The id breaks inside itself only as an inline box, and an
// inline-block is one unbreakable box.
func TestOnAPhoneARowThatOpensWrapsItsSummary(t *testing.T) {
	rules := phoneRules(t)
	summary, ok := rules[".rows summary.rule"]
	if !ok {
		t.Fatal("the phone block does not lay out the summary of a row that opens")
	}
	if !strings.Contains(summary, "display: block") || !strings.Contains(summary, "white-space: normal") {
		t.Errorf("on a phone the summary is still held to one line: %q", summary)
	}
	for sel, decls := range rules {
		if strings.Contains(sel, ".id") && strings.Contains(decls, "inline-block") {
			t.Errorf("on a phone the rule id is an inline-block, which never breaks: %s { %s }", sel, decls)
		}
	}
	if !strings.Contains(htmlDoc, ".rows .what { min-width: 0; overflow-wrap: anywhere; }") {
		t.Error("nothing lets a rule id with no space in it break inside its row")
	}
}
