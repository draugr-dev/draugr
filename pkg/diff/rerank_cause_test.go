package diff

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/skald"
)

// declaring is a shop of two components over two repositories: worker declared less exposure and
// criticality between the scans, lowering both its findings, and api's dependency was put on KEV,
// raising one finding there. The base records its declarations, an empty classification on api's
// side included.
func declaring() (base, head sarif.Report) {
	const shop, jobs = "https://github.com/acme/shop", "https://github.com/acme/jobs"
	w1, w2, a := finding("CVE-2", "go.mod", 5), finding("CVE-3", "go.mod", 9), finding("CVE-1", "api/go.mod", 3)
	class := func(r sarif.Result, exposure, criticality string) sarif.Result {
		r.Exposure, r.Criticality = exposure, criticality
		return r
	}
	kev := in(class(a, "public", "critical"), "api", shop, "P1")
	kev.Escalation = &sarif.Escalation{From: sarif.SeverityHigh, To: sarif.SeverityCritical, Signal: "kev", Detail: "on KEV"}
	declared := []sarif.Provenance{{Tool: skald.DeclaredProvenanceTool}}
	base = sarif.Report{Provenance: declared, Results: []sarif.Result{
		in(class(a, "public", "critical"), "api", shop, "P2"),
		in(w1, "worker", shop, "P1"), in(w2, "worker", jobs, "P1"),
	}}
	head = sarif.Report{Provenance: declared, Results: []sarif.Result{
		kev,
		in(class(w1, "internal", "supporting"), "worker", shop, "P3"),
		in(class(w2, "internal", "supporting"), "worker", jobs, "P3"),
	}}
	return base, head
}

func causeTexts(cs []Cause) []string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.Text)
	}
	return out
}

// Each reranked finding records what the two scans ranked it by differently: the component's
// classification, an undeclared half named as the level it was ranked at, and a signal.
func TestARerankedFindingNamesWhatMovedIt(t *testing.T) {
	r := Compare(declaring())
	if len(r.Reranked) != 3 {
		t.Fatalf("reranked = %d, want 3", len(r.Reranked))
	}
	got := map[string][]string{}
	for _, rr := range r.Reranked {
		got[rr.Repository+" "+rr.RuleID] = causeTexts(rr.Causes())
	}
	want := map[string]string{
		"https://github.com/acme/shop CVE-1": "↑ KEV",
		"https://github.com/acme/shop CVE-2": "exposure public (assumed) → internal|criticality critical (assumed) → supporting",
		"https://github.com/acme/jobs CVE-3": "exposure public (assumed) → internal|criticality critical (assumed) → supporting",
	}
	for k, v := range want {
		if strings.Join(got[k], "|") != v {
			t.Errorf("%s: causes %q, want %q", k, got[k], v)
		}
	}
	c := r.Reranked[1].Causes()[0]
	if c.Input != "exposure" || c.From != "" || c.To != "internal" {
		t.Errorf("exposure cause = %+v, want exposure from undeclared to internal", c)
	}
}

// The console says once, under the heading, what moved every row of a component, and under a row
// what moved that finding alone. The compact view keeps the component's line.
func TestTheConsoleSaysWhatMovedEachBand(t *testing.T) {
	r := Compare(declaring())
	got := renderAs(t, "console", r, Options{})
	line := "  worker: exposure public (assumed) → internal, criticality critical (assumed) → supporting\n"
	if strings.Count(got, line) != 1 {
		t.Errorf("want the worker's classification once, under the heading:\n%s", got)
	}
	if strings.Index(got, "RERANKED") > strings.Index(got, line) {
		t.Errorf("the component line should follow the heading:\n%s", got)
	}
	if strings.Count(got, "exposure public") != 1 {
		t.Errorf("a worker row repeated what its component line says:\n%s", got)
	}
	lines := strings.Split(got, "\n")
	for i, l := range lines {
		if strings.Contains(l, "CVE-1") && strings.Contains(l, "P2 → P1") {
			if i+2 >= len(lines) || strings.TrimSpace(lines[i+2]) != "↑ KEV" {
				t.Errorf("want ↑ KEV under the title of the raised row:\n%s", got)
			}
		}
	}
	compact := renderAs(t, "console", r, Options{View: ViewCompact})
	if !strings.Contains(compact, line) || strings.Contains(compact, "↑ KEV") {
		t.Errorf("compact should keep the component line and drop a row's own:\n%s", compact)
	}
}

// The comment carries the component's line as a list item and a row's own cause in a Why column.
func TestTheCommentSaysWhatMovedEachBand(t *testing.T) {
	got := renderAs(t, "markdown", Compare(declaring()), Options{})
	for _, want := range []string{
		"- **worker**: exposure public (assumed) → internal, criticality critical (assumed) → supporting\n",
		"| Priority | Severity | Rule | Scanner | Component | Location | Why |\n|---|---|---|---|---|---|---|\n",
		"| api | api/go.mod:3 | ↑ KEV |\n",
		"| worker | go.mod:5 |  |\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q:\n%s", want, got)
		}
	}
}

// Rows with nothing of their own to say leave the Why column out.
func TestTheCommentLeavesWhyOutWhereNoRowHasOne(t *testing.T) {
	r := Compare(declaring())
	r.Reranked = r.Reranked[1:]
	got := renderAs(t, "markdown", r, Options{})
	if strings.Contains(got, "| Why |") || !strings.Contains(got, "- **worker**:") {
		t.Errorf("want the worker's line and no Why column:\n%s", got)
	}
}

// JSON carries every cause on every row, the component's included.
func TestJSONCarriesWhatMovedEachBand(t *testing.T) {
	var got struct {
		Reranked []struct {
			Finding sarif.Result `json:"finding"`
			Changed []Cause      `json:"changed"`
		} `json:"reranked"`
	}
	out := renderAs(t, "json", Compare(declaring()), Options{})
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, rr := range got.Reranked {
		want := "exposure public (assumed) → internal|criticality critical (assumed) → supporting"
		if rr.Finding.RuleID == "CVE-1" {
			want = "↑ KEV"
		}
		if g := strings.Join(causeTexts(rr.Changed), "|"); g != want {
			t.Errorf("%s: changed %q, want %q", rr.Finding.RuleID, g, want)
		}
	}
	if !strings.Contains(out, `"input": "escalation"`) || !strings.Contains(out, `"to": "KEV"`) {
		t.Errorf("want the escalation's input and value:\n%s", out)
	}
}

// A base that cannot say what its components declared names no change to the classification: an
// empty exposure there is a release that stamped none as much as a component that declared none.
func TestABaseThatRecordsNoClassificationNamesNone(t *testing.T) {
	base, head := declaring()
	base.Provenance = nil
	for i := range base.Results {
		base.Results[i].Exposure, base.Results[i].Criticality = "", ""
	}
	r := Compare(base, head)
	for _, rr := range r.Reranked {
		for _, c := range rr.Causes() {
			if c.context() {
				t.Errorf("%s: named %q from a base that records no classification", rr.RuleID, c.Text)
			}
		}
	}
	if got := renderAs(t, "console", r, Options{}); strings.Contains(got, "worker:") {
		t.Errorf("drew a component line from a base that records no classification:\n%s", got)
	}
	// One finding carrying a classification shows the release stamped them.
	base.Results[0].Exposure = "public"
	if !recordsClassification(base) {
		t.Error("a base with a classified finding read as recording none")
	}
}

// A band that moved with every recorded input the same says nothing about why.
func TestABandWithNoRecordedCauseSaysNothing(t *testing.T) {
	r := Compare(rebanded())
	for _, rr := range r.Reranked {
		if cs := rr.Causes(); len(cs) != 0 {
			t.Errorf("%s: causes %q, want none", rr.RuleID, causeTexts(cs))
		}
	}
	if got := renderAs(t, "markdown", r, Options{}); strings.Contains(got, "Why") {
		t.Errorf("want no Why column:\n%s", got)
	}
	if (Rerank{Result: finding("CVE-1", "go.mod", 1)}).Causes() != nil {
		t.Error("a rerank with no base copy named a cause")
	}
}

// Rows of one component that moved for different classifications, as a carried-over copy can, keep
// their own: one line would claim a reason for a row it does not hold for.
func TestAComponentWhoseRowsDisagreeGetsNoLine(t *testing.T) {
	was := in(finding("CVE-1", "go.mod", 1), "worker", "repo", "P1")
	a, b := was, was
	a.Exposure, b.Exposure = "internal", "authenticated"
	rs := []Rerank{{Result: a, Was: was}, {Result: b, Was: was}}
	why := explainReranks(rs)
	if len(why.components) != 0 || why.rows[0] != "exposure public (assumed) → internal" ||
		why.rows[1] != "exposure public (assumed) → authenticated" {
		t.Errorf("why = %+v, want each row's own exposure and no line", why)
	}
}

// Every mark `draugr scan` prints beside a band is named when one scan has it and the other does
// not, and a change of value says both.
func TestEachMarkIsNamedWhereOneScanHasIt(t *testing.T) {
	plain := finding("CVE-1", "go.mod", 1)
	with := func(f func(*sarif.Result)) sarif.Result {
		r := plain
		f(&r)
		return r
	}
	unreachable := with(func(r *sarif.Result) {
		r.Reachability = &sarif.Reachability{State: sarif.ReachabilityUnreachable, RankedAs: sarif.SeverityLow}
	})
	converter := with(func(r *sarif.Result) {
		r.Converter = &sarif.Converter{Name: "ours", Raise: &sarif.Raise{Priority: "P1", Reason: "on the payments path"}}
		r.PriorityFloor = r.Converter.RaiseNote()
	})
	epss := func(r *sarif.Result) {
		r.Escalation = &sarif.Escalation{From: sarif.SeverityMedium, To: sarif.SeverityHigh, Signal: "epss", Detail: "EPSS 0.91"}
	}
	for _, c := range []struct {
		name     string
		was, now sarif.Result
		want     string
	}{
		{"unreachable", plain, unreachable, "↓ unreachable"},
		{"reachable again", unreachable, plain, "no longer unreachable"},
		{"pinned", plain, with(func(r *sarif.Result) { r.PriorityCap = "pinned by actions.lock" }), "↓ pinned"},
		{"cap reworded", with(func(r *sarif.Result) { r.PriorityCap = "a" }), with(func(r *sarif.Result) { r.PriorityCap = "b" }), ""},
		{"floor", plain, with(func(r *sarif.Result) { r.PriorityFloor = "secrets are not bounded by exposure" }), "↑ floor"},
		{"converter", plain, converter, "↑ converter ours"},
		{"minimum", plain, with(func(r *sarif.Result) { r.SeverityFloor = sarif.SeverityHigh }), "↑ minimum severity high"},
		{"minimum moved", with(func(r *sarif.Result) { r.SeverityFloor = sarif.SeverityHigh }),
			with(func(r *sarif.Result) { r.SeverityFloor = sarif.SeverityCritical }), "↑ minimum severity critical (was high)"},
		{"EPSS gone", with(epss), plain, "no longer EPSS"},
		{"signal swapped", with(epss), with(func(r *sarif.Result) {
			r.Escalation = &sarif.Escalation{To: sarif.SeverityCritical, Signal: "malicious"}
		}), "↑ malicious (was EPSS)"},
		{"raise undone by reachability", with(epss), with(func(r *sarif.Result) {
			epss(r)
			r.Reachability = unreachable.Reachability
		}), "no longer EPSS, ↓ unreachable"},
		{"rescored", plain, with(func(r *sarif.Result) { r.Score, r.HasScore = 9.8, true }), "severity high → critical"},
		{"another tool's rating", plain, with(func(r *sarif.Result) { r.Tool, r.Score, r.HasScore = "grype", 9.8, true }), ""},
	} {
		if got := strings.Join(causeTexts(causes(c.was, c.now, true)), ", "); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}
