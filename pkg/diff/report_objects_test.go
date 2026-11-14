package diff

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// objectScans are two clusters' 5.2.2: prod gains a pod, staging loses one, and both still fail.
func objectScans() (base, head sarif.Report) {
	base = sarif.Report{Results: []sarif.Result{
		check("cis/5.2.2", "prod", "api", "kube-system/kube-proxy"),
		check("cis/5.2.2", "staging", "web", "apps/old", "kube-system/kube-proxy"),
	}}
	head = sarif.Report{Results: []sarif.Result{
		check("cis/5.2.2", "prod", "api", "default/debug", "kube-system/kube-proxy"),
		check("cis/5.2.2", "staging", "web", "kube-system/kube-proxy"),
	}}
	return base, head
}

// clusterScans are two clusters under three checks: a debug pod joins every check in prod and an
// old one leaves every check in staging, and in staging 5.6.2 also gains a pod as the old one goes.
// Ordered by rule, the checks alternate between an object joining and one leaving.
func clusterScans() (base, head sarif.Report) {
	base = sarif.Report{Results: []sarif.Result{
		check("draugr/cis/5.1.6", "prod", "api", "shop/checkout-7d9f8b6c5-hk2lm"),
		check("draugr/cis/5.1.6", "staging", "web", "apps/old-debug", "shop/cart-5c6d7e8f9-abcde"),
		check("draugr/cis/5.2.2", "prod", "api", "kube-system/kube-proxy-x7k2p/kube-proxy"),
		check("draugr/cis/5.2.2", "staging", "web", "apps/old-debug/app", "kube-system/kube-proxy-q4m8n/kube-proxy"),
		check("draugr/cis/5.6.2", "prod", "api", "shop/checkout-7d9f8b6c5-hk2lm"),
		check("draugr/cis/5.6.2", "staging", "web", "apps/old-debug", "shop/cart-5c6d7e8f9-abcde"),
	}}
	head = sarif.Report{Results: []sarif.Result{
		check("draugr/cis/5.1.6", "prod", "api", "default/debug-shell", "shop/checkout-7d9f8b6c5-hk2lm"),
		check("draugr/cis/5.1.6", "staging", "web", "shop/cart-5c6d7e8f9-abcde"),
		check("draugr/cis/5.2.2", "prod", "api", "default/debug-shell/app", "kube-system/kube-proxy-x7k2p/kube-proxy"),
		check("draugr/cis/5.2.2", "staging", "web", "kube-system/kube-proxy-q4m8n/kube-proxy"),
		check("draugr/cis/5.6.2", "prod", "api", "default/debug-shell", "shop/checkout-7d9f8b6c5-hk2lm"),
		check("draugr/cis/5.6.2", "staging", "web", "apps/new-debug", "shop/cart-5c6d7e8f9-abcde"),
		check("draugr/cis/5.6.4", "prod", "api", "default/debug-shell"),
	}}
	head.Rules = map[string]sarif.Rule{"draugr/cis/5.6.2": {HelpURI: "https://example.test/5.6.2"}}
	return base, head
}

// objectsBlock is the OBJECTS block of out, from its title to the next blank line.
func objectsBlock(t *testing.T, out string) string {
	t.Helper()
	at := strings.Index(out, "OBJECTS")
	if at < 0 {
		t.Fatalf("no OBJECTS block:\n%s", out)
	}
	block, _, _ := strings.Cut(out[at:], "\n\n")
	return block + "\n"
}

// renderAs is r rendered in format, with opts.
func renderAs(t *testing.T, format string, r Result, opts Options) string {
	t.Helper()
	var b bytes.Buffer
	if err := Render(&b, format, r, opts); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// The comparison records what joined each check and what left it, beside the check.
func TestTheComparisonRecordsWhatJoinedAndLeft(t *testing.T) {
	got := Compare(objectScans())
	if len(got.Objects) != 2 {
		t.Fatalf("objects = %+v, want both checks", got.Objects)
	}
	prod, staging := got.Objects[0], got.Objects[1]
	if prod.Component != "api" || len(prod.Joined) != 1 || prod.Joined[0] != "default/debug" || len(prod.Left) != 0 {
		t.Errorf("prod = %+v, want default/debug joined", prod)
	}
	if staging.Component != "web" || len(staging.Left) != 1 || staging.Left[0] != "apps/old" || len(staging.Joined) != 0 {
		t.Errorf("staging = %+v, want apps/old left", staging)
	}
	// A check in no component is placed by its cluster alone.
	staging.Component = ""
	if got := staging.where(); got != "kubernetes/staging" {
		t.Errorf("where = %q, want the cluster alone", got)
	}
}

// Every object that joined a check is listed before any that left one, though the checks alternate,
// and a check that did both is named over each half. The block follows the CHANGED table.
func TestEveryObjectThatJoinedComesBeforeAnyThatLeft(t *testing.T) {
	out := renderAs(t, "console", Compare(clusterScans()), Options{})
	want := "OBJECTS  4 joined, 3 left\n" +
		"  draugr/cis/5.1.6  api · kubernetes/prod\n" +
		"    + joined default/debug-shell\n" +
		"  draugr/cis/5.2.2  api · kubernetes/prod\n" +
		"    + joined default/debug-shell/app\n" +
		"  draugr/cis/5.6.2  api · kubernetes/prod\n" +
		"    + joined default/debug-shell\n" +
		"  draugr/cis/5.6.2  web · kubernetes/staging\n" +
		"    + joined apps/new-debug\n" +
		"  draugr/cis/5.1.6  web · kubernetes/staging\n" +
		"    - left   apps/old-debug\n" +
		"  draugr/cis/5.2.2  web · kubernetes/staging\n" +
		"    - left   apps/old-debug/app\n" +
		"  draugr/cis/5.6.2  web · kubernetes/staging\n" +
		"    - left   apps/old-debug\n"
	if got := objectsBlock(t, out); got != want {
		t.Errorf("got\n%s\nwant\n%s", got, want)
	}
	if strings.Index(out, "CHANGED") > strings.Index(out, "OBJECTS") {
		t.Errorf("OBJECTS comes before CHANGED:\n%s", out)
	}
}

// Under --view compact the block is a line per object with its check and place on the line, in the
// same order, and no line is wider than an ordinary terminal.
func TestTheCompactViewIsALinePerObject(t *testing.T) {
	out := renderAs(t, "console", Compare(clusterScans()), Options{View: ViewCompact})
	want := "OBJECTS  4 joined, 3 left\n" +
		"  + joined  default/debug-shell      draugr/cis/5.1.6  api · kubernetes/prod\n" +
		"  + joined  default/debug-shell/app  draugr/cis/5.2.2  api · kubernetes/prod\n" +
		"  + joined  default/debug-shell      draugr/cis/5.6.2  api · kubernetes/prod\n" +
		"  + joined  apps/new-debug           draugr/cis/5.6.2  web · kubernetes/staging\n" +
		"  - left    apps/old-debug           draugr/cis/5.1.6  web · kubernetes/staging\n" +
		"  - left    apps/old-debug/app       draugr/cis/5.2.2  web · kubernetes/staging\n" +
		"  - left    apps/old-debug           draugr/cis/5.6.2  web · kubernetes/staging\n"
	got := objectsBlock(t, out)
	if got != want {
		t.Errorf("got\n%s\nwant\n%s", got, want)
	}
	for _, line := range strings.Split(got, "\n") {
		if n := utf8.RuneCountInString(line); n > 80 {
			t.Errorf("%d columns: %q", n, line)
		}
	}
}

// A comparison in which only objects left prints the block and nothing else, never "Nothing
// changed", and the block opens straight after the strips rather than after a second blank line.
func TestOnlyObjectsLeavingIsStillAChange(t *testing.T) {
	base, head := objectScans()
	base.Results, head.Results = base.Results[1:], head.Results[1:]
	r := Compare(base, head)

	out := renderAs(t, "console", r, Options{})
	if !strings.Contains(out, "- left   apps/old") || strings.Contains(out, "Nothing changed") {
		t.Errorf("only an object left:\n%s", out)
	}
	if strings.Contains(out, "\n\n\nOBJECTS") {
		t.Errorf("two blank lines over OBJECTS:\n%q", out)
	}

	var b bytes.Buffer
	if !(ScanView{Result: r}).WriteListing(&b, "", 0) {
		t.Fatal("the scan's listing wrote nothing where an object left")
	}
	if !strings.HasPrefix(b.String(), "OBJECTS") {
		t.Errorf("the scan's listing does not open with OBJECTS:\n%q", b.String())
	}

	for _, view := range []View{ViewFindings, ViewActions} {
		md := renderAs(t, "markdown", r, Options{View: view})
		if strings.Contains(md, "Nothing changed") || !strings.Contains(md, "- left `apps/old` · `cis/5.2.2` · web · kubernetes/staging\n") {
			t.Errorf("%s: the comment where only an object left:\n%s", view, md)
		}
	}
}

// The comment names one scanner once, in the Changed heading, with no Scanner column, and lists the
// objects after the table in the order the console does, each rule linked where it has a page.
func TestTheCommentListsTheObjectsAfterTheTable(t *testing.T) {
	md := renderAs(t, "markdown", Compare(clusterScans()), Options{})
	if !strings.Contains(md, "### Changed · 5 from draugr-k8s-policies, by priority\n") {
		t.Errorf("the heading does not name the scanner:\n%s", md)
	}
	if strings.Contains(md, "Scanner") {
		t.Errorf("the table keeps a Scanner column:\n%s", md)
	}
	header := "| Change | Priority | Severity | Rule | Component | Location |"
	if !strings.Contains(md, header+"\n") {
		t.Fatalf("no header %q:\n%s", header, md)
	}
	// Every row has the header's cells, so no column is shifted under another's heading.
	for _, line := range strings.Split(md, "\n") {
		if strings.HasPrefix(line, "| **new**") && strings.Count(line, "|") != strings.Count(header, "|") {
			t.Errorf("row %q has a different number of cells from %q", line, header)
		}
	}

	want := "### Objects · 4 joined, 3 left\n\n" +
		"- **joined** `default/debug-shell` · `draugr/cis/5.1.6` · api · kubernetes/prod\n" +
		"- **joined** `default/debug-shell/app` · `draugr/cis/5.2.2` · api · kubernetes/prod\n" +
		"- **joined** `default/debug-shell` · [`draugr/cis/5.6.2`](https://example.test/5.6.2) · api · kubernetes/prod\n" +
		"- **joined** `apps/new-debug` · [`draugr/cis/5.6.2`](https://example.test/5.6.2) · web · kubernetes/staging\n" +
		"- left `apps/old-debug` · `draugr/cis/5.1.6` · web · kubernetes/staging\n" +
		"- left `apps/old-debug/app` · `draugr/cis/5.2.2` · web · kubernetes/staging\n" +
		"- left `apps/old-debug` · [`draugr/cis/5.6.2`](https://example.test/5.6.2) · web · kubernetes/staging\n"
	if !strings.Contains(md, want) || strings.Index(md, "### Changed") > strings.Index(md, "### Objects") {
		t.Errorf("got\n%s\nwant after the table\n%s", md, want)
	}

	actions := renderAs(t, "markdown", Compare(clusterScans()), Options{View: ViewActions})
	if !strings.Contains(actions, want) {
		t.Errorf("the actions comment does not list the objects:\n%s", actions)
	}
}

// A comment over rows from two scanners keeps the Scanner column and a heading naming none.
func TestACommentOverTwoScannersKeepsTheScannerColumn(t *testing.T) {
	dep := sarif.Result{Tool: "grype", RuleID: "CVE-2026-0001", Level: sarif.LevelError, Message: "a flaw",
		Location: sarif.Location{URI: "go.mod"}}
	head := sarif.Report{Results: []sarif.Result{check("cis/5.6.4", "prod", "api", "default/debug"), dep}}
	md := renderAs(t, "markdown", Compare(sarif.Report{}, head), Options{})
	if !strings.Contains(md, "### Changed · 2, by priority\n") || !strings.Contains(md, "| Rule | Scanner |") {
		t.Errorf("the Scanner column went:\n%s", md)
	}
	if !strings.Contains(md, "| draugr-k8s-policies |") || !strings.Contains(md, "| grype |") {
		t.Errorf("a row lost its scanner:\n%s", md)
	}
	if strings.Contains(md, "### Objects") {
		t.Errorf("objects listed where none joined or left:\n%s", md)
	}
}
