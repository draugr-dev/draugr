package skald

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// gateBlock renders a document under gate and returns its gate block as plain JSON values, so a
// test reads the shape a consumer reads rather than this package's own structs.
func gateBlock(t *testing.T, gate *Gate) map[string]any {
	t.Helper()
	var buf bytes.Buffer
	err := RenderJSONFor(&buf, "shop", saga.Release{Version: "1"}, prioritizedRun(),
		sampleVerdict(), "", nil, sarif.MarshalOptions{}, Provenance{Gate: gate})
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Gate map[string]any `json:"gate"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Gate == nil {
		t.Fatal("no gate block")
	}
	return doc.Gate
}

// introducedIn is what a comparison found in api's repository: two P2s, a P3 and a finding nothing
// ranked.
func introducedIn() []sarif.Result {
	api := "https://example.com/api.git"
	return []sarif.Result{
		{RuleID: "CVE-1", Priority: "P2", Component: "api", Repository: api},
		{RuleID: "CVE-2", Priority: "P2", Component: "api", Repository: api},
		{RuleID: "G101", Priority: "P3", Component: "api", Repository: api},
		{RuleID: "unranked", Component: "api", Repository: api},
	}
}

// Two repositories read at two revisions: the base block lists both and names no one commit.
func twoRepositories() []sarif.RepositoryRef {
	return []sarif.RepositoryRef{
		{URL: "https://example.com/api.git", Revision: "3f2a9c1aaaa"},
		{URL: "https://example.com/web.git", Revision: "8b1d004bbbb"},
	}
}

func TestTheGateStatesTheComparisonAndItsVerdict(t *testing.T) {
	got := gateBlock(t, &Gate{
		FailOnNew: "P2",
		New:       &NewFindings{Base: twoRepositories(), Introduced: introducedIn(), Tripped: true},
	})
	if got["failOnNew"] != "P2" {
		t.Errorf("failOnNew = %v, want P2", got["failOnNew"])
	}
	n, ok := got["new"].(map[string]any)
	if !ok {
		t.Fatalf("new = %v, want the comparison", got["new"])
	}
	if n["verdict"] != "fail" {
		t.Errorf("verdict = %v, want fail", n["verdict"])
	}
	// By band, in the spelling of the document's own priorities. A finding nothing ranked has no
	// band to be counted in.
	wantCounts := map[string]any{"p1": 0.0, "p2": 2.0, "p3": 1.0, "p4": 0.0}
	if !reflect.DeepEqual(n["introduced"], wantCounts) {
		t.Errorf("introduced = %v, want %v", n["introduced"], wantCounts)
	}
	base, ok := n["base"].(map[string]any)
	if !ok {
		t.Fatalf("base = %v", n["base"])
	}
	if _, named := base["commit"]; named {
		t.Errorf("base.commit = %v: two repositories at two revisions have no one commit", base["commit"])
	}
	repos, _ := base["repositories"].([]any)
	if len(repos) != 2 {
		t.Fatalf("base.repositories = %v, want both", base["repositories"])
	}
	if first, _ := repos[0].(map[string]any); first["url"] != "https://example.com/api.git" || first["revision"] != "3f2a9c1aaaa" {
		t.Errorf("base.repositories[0] = %v", repos[0])
	}
}

// One repository, whatever the number of components reading it, is one commit, and so is one
// repository spelled two ways.
func TestTheBaseNamesItsCommitWhereItReadOne(t *testing.T) {
	for name, repos := range map[string][]sarif.RepositoryRef{
		"one":               {{URL: "https://example.com/api.git", Revision: "3f2a9c1"}},
		"one spelled twice": {{URL: "https://example.com/api", Revision: "3f2a9c1"}, {URL: "https://example.com/api.git", Revision: "3f2a9c1"}},
	} {
		t.Run(name, func(t *testing.T) {
			got := describeNew(&NewFindings{Base: repos}, "P1")
			if got.Base.Commit != "3f2a9c1" {
				t.Errorf("base.commit = %q, want 3f2a9c1", got.Base.Commit)
			}
			if got.Verdict != string(norn.Pass) {
				t.Errorf("verdict = %q, want pass where nothing met the gate", got.Verdict)
			}
		})
	}
	// A repository whose revision git could not report leaves the commit unknown, rather than
	// naming the other repository's as the base's.
	partial := []sarif.RepositoryRef{
		{URL: "https://example.com/api.git", Revision: "3f2a9c1"},
		{URL: "https://example.com/web.git"},
	}
	if got := describeNew(&NewFindings{Base: partial}, "P1"); got.Base.Commit != "" {
		t.Errorf("base.commit = %q with one revision unknown, want none", got.Base.Commit)
	}
}

// Each band is counted in its own place.
func TestIntroducedCountsEachBand(t *testing.T) {
	var introduced []sarif.Result
	for _, band := range []string{"P1", "P2", "P3", "P4", "P4"} {
		introduced = append(introduced, sarif.Result{RuleID: "R-" + band, Priority: band})
	}
	got := describeNew(&NewFindings{Introduced: introduced}, "").Introduced
	if want := (priorityCounts{P1: 1, P2: 1, P3: 1, P4: 2}); got != want {
		t.Errorf("introduced = %+v, want %+v", got, want)
	}
}

// A gate on new findings with no comparison states the setting and no `new`, which reads as a gate
// asked for that had no base to apply to. A comparison with no threshold states what it found and
// no verdict, because nothing was asked of it.
func TestTheSettingAndTheComparisonAreStatedApart(t *testing.T) {
	asked := gateBlock(t, &Gate{FailOnNew: "high"})
	if asked["failOnNew"] != "high" {
		t.Errorf("failOnNew = %v, want high", asked["failOnNew"])
	}
	if _, ran := asked["new"]; ran {
		t.Errorf("new = %v with no comparison", asked["new"])
	}

	compared := gateBlock(t, &Gate{New: &NewFindings{Introduced: introducedIn()}})
	if _, set := compared["failOnNew"]; set {
		t.Errorf("failOnNew = %v, set by nobody", compared["failOnNew"])
	}
	n, ok := compared["new"].(map[string]any)
	if !ok {
		t.Fatalf("new = %v, want the comparison", compared["new"])
	}
	if _, judged := n["verdict"]; judged {
		t.Errorf("verdict = %v, with no threshold to judge against", n["verdict"])
	}

	// Neither: the block is what it was before either existed.
	plain := gateBlock(t, &Gate{})
	for _, key := range []string{"failOnNew", "new"} {
		if _, there := plain[key]; there {
			t.Errorf("%s = %v on a run that set no gate on new findings", key, plain[key])
		}
	}
}
