package diff

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// split is one component, shop, divided into api and checkout over one repository. Two findings go
// to api at the priority they had; three go to checkout, which declares a lower exposure, and two
// of those drop a band.
func split() Result {
	const repo = "https://github.com/acme/shop.git"
	move := func(rule, uri, to, was, now string) Move {
		f := finding(rule, uri, 3)
		return Move{Result: in(f, to, repo, now), Was: in(f, "shop", repo, was)}
	}
	return Result{
		Gate: Gate{FailOnPriority: "P1"},
		Moved: []Move{
			move("CVE-1", "checkout/go.mod", "checkout", "P1", "P2"),
			move("CVE-2", "checkout/go.mod", "checkout", "P1", "P2"),
			move("CVE-3", "checkout/go.mod", "checkout", "P3", "P3"),
			move("CVE-4", "api/go.mod", "api", "P2", "P2"),
			move("CVE-5", "api/go.mod", "api", "P3", "P3"),
		},
	}
}

// A split lists a line per pair of components rather than a row per finding, and then the findings
// whose priority changed with the component, from both sides.
func TestAMoveListsThePairsAndThePrioritiesThatChanged(t *testing.T) {
	var b bytes.Buffer
	if err := Render(&b, "console", split(), Options{}); err != nil {
		t.Fatal(err)
	}
	got := b.String()
	for _, want := range []string{
		"5 moved", "MOVED  5", "Nothing is new or fixed.",
		"PRIORITY CHANGED  2, by priority", "P1 → P2", "shop → checkout", "checkout/go.mod:3",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q:\n%s", want, got)
		}
	}
	if !lineHas(got, "shop", "api", "2", "unchanged") || !lineHas(got, "shop", "checkout", "3", "2 P1 → P2") {
		t.Errorf("a pair should carry its count and its shifts:\n%s", got)
	}
	// Only the reprioritized moves get a row of their own.
	if strings.Contains(got, "CVE-4") || strings.Contains(got, "CVE-5") || strings.Contains(got, "CVE-3") {
		t.Errorf("a move at the priority it had is listed only in its pair:\n%s", got)
	}
	if !strings.Contains(got, "pass") {
		t.Errorf("a split alone should pass a gate on new findings:\n%s", got)
	}
}

// A split whose findings kept their priorities has no second table to draw.
func TestAMoveThatKeptItsPrioritiesListsOnlyThePairs(t *testing.T) {
	r := split()
	r.Moved = r.Moved[3:]
	for _, format := range []string{"console", "markdown"} {
		var b bytes.Buffer
		if err := Render(&b, format, r, Options{}); err != nil {
			t.Fatal(err)
		}
		if got := strings.ToLower(b.String()); strings.Contains(got, "priority changed") {
			t.Errorf("%s: a priority-changed heading over nothing:\n%s", format, got)
		}
	}
}

// --top caps the reprioritized rows and says how many it held back; the pairs are never capped,
// because they are the summary.
func TestTopCapsTheReprioritizedMoves(t *testing.T) {
	for _, format := range []string{"console", "markdown"} {
		var b bytes.Buffer
		if err := Render(&b, format, split(), Options{Top: 1}); err != nil {
			t.Fatal(err)
		}
		got := b.String()
		if !strings.Contains(got, "top 1 of 2, by priority") || !strings.Contains(got, "and 1 not listed") {
			t.Errorf("%s: a capped listing should say what it held back:\n%s", format, got)
		}
		if !strings.Contains(got, "api") {
			t.Errorf("%s: --top dropped a pair:\n%s", format, got)
		}
	}
}

// The compact view drops the finding's sentence under each row, as it does in the changed table.
func TestCompactDropsTheSentenceUnderAMove(t *testing.T) {
	r := split()
	r.Moved[0].Message = "infinite loop in the decoder"
	var full, compact bytes.Buffer
	if err := Render(&full, "console", r, Options{}); err != nil {
		t.Fatal(err)
	}
	if err := Render(&compact, "console", r, Options{View: ViewCompact}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(full.String(), "infinite loop in the decoder") {
		t.Errorf("the findings view should carry the sentence:\n%s", full.String())
	}
	if strings.Contains(compact.String(), "infinite loop in the decoder") {
		t.Errorf("the compact view should not:\n%s", compact.String())
	}
}

// The comment carries the same two tables, with the rule linked where the report explains it.
func TestTheCommentListsMoves(t *testing.T) {
	r := split()
	r.Rules = map[string]sarif.Rule{"CVE-1": {HelpURI: "https://avd.example/cve-1"}}
	for _, view := range []View{ViewFindings, ViewActions} {
		var b bytes.Buffer
		if err := Render(&b, "markdown", r, Options{View: view}); err != nil {
			t.Fatal(err)
		}
		got := b.String()
		for _, want := range []string{
			"↪️ 5 moved", "_moved_ ·", "Nothing is new or fixed.",
			"### Moved · 5", "| shop | api | 2 | unchanged |", "| shop | checkout | 3 | 2 P1 → P2 |",
			"### Priority changed · 2, by priority",
			"| P1 → P2 | high | [`CVE-1`](https://avd.example/cve-1) | trivy | shop → checkout | checkout/go.mod:3 |",
			"| P1 → P2 | high | [`CVE-2`](",
		} {
			if !strings.Contains(got, want) {
				t.Errorf("%s: missing %q:\n%s", view, want, got)
			}
		}
	}
}

// Moves sit beside the changed table, not in place of it, when a pull request does both.
func TestMovesFollowTheChangedTable(t *testing.T) {
	r := split()
	r.New = []sarif.Result{in(finding("CVE-9", "api/main.go", 1), "api", "repo", "P2")}
	for _, format := range []string{"console", "markdown"} {
		var b bytes.Buffer
		if err := Render(&b, format, r, Options{}); err != nil {
			t.Fatal(err)
		}
		got := b.String()
		changed, moved := strings.Index(got, "CVE-9"), strings.Index(strings.ToLower(got), "moved · 5")
		if format == "console" {
			moved = strings.Index(got, "MOVED  5")
		}
		if changed < 0 || moved < 0 || changed > moved {
			t.Errorf("%s: want the new finding listed before the moves:\n%s", format, got)
		}
		if strings.Contains(got, "Nothing is new") {
			t.Errorf("%s: said nothing was new beside a new finding:\n%s", format, got)
		}
	}
}

// JSON names each move with the component and priority it had, and counts them in the summary.
func TestJSONCarriesEachMove(t *testing.T) {
	var b bytes.Buffer
	if err := Render(&b, "json", split(), Options{}); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Summary struct {
			Moved int `json:"moved"`
		} `json:"summary"`
		Moved []struct {
			Finding       sarif.Result `json:"finding"`
			FromComponent string       `json:"fromComponent"`
			FromPriority  string       `json:"fromPriority"`
		} `json:"moved"`
	}
	if err := json.Unmarshal(b.Bytes(), &got); err != nil {
		t.Fatalf("%v\n%s", err, b.String())
	}
	if got.Summary.Moved != 5 || len(got.Moved) != 5 {
		t.Fatalf("summary.moved %d, moved[] %d; want 5 and 5", got.Summary.Moved, len(got.Moved))
	}
	m := got.Moved[0]
	if m.FromComponent != "shop" || m.FromPriority != "P1" || m.Finding.Component != "checkout" || m.Finding.Priority != "P2" {
		t.Errorf("a move should carry both sides: %+v", m)
	}
}

// A code-scanning upload carries new findings only, so a move annotates nobody.
func TestSARIFLeavesMovesOut(t *testing.T) {
	var b bytes.Buffer
	if err := Render(&b, "sarif", split(), Options{}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "CVE-1") {
		t.Errorf("a moved finding reached the SARIF upload:\n%s", b.String())
	}
}

// Every finding in head is in one strip, so a moved finding has one.
func TestAMovedFindingHasAStrip(t *testing.T) {
	var b bytes.Buffer
	if err := Render(&b, "console", split(), Options{}); err != nil {
		t.Fatal(err)
	}
	if !lineHas(b.String(), "moved", "0 P1", "3 P2", "2 P3") {
		t.Errorf("the moved strip should count head's priorities:\n%s", b.String())
	}
}

// lineHas reports whether one line of out holds every one of parts, in order.
func lineHas(out string, parts ...string) bool {
	for line := range strings.SplitSeq(out, "\n") {
		rest, ok := line, true
		for _, p := range parts {
			i := strings.Index(rest, p)
			if i < 0 {
				ok = false
				break
			}
			rest = rest[i+len(p):]
		}
		if ok {
			return true
		}
	}
	return false
}
