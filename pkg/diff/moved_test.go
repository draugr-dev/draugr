package diff

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// in places a finding in a component and a repository.
func in(r sarif.Result, component, repository, priority string) sarif.Result {
	r.Component, r.Repository, r.Priority = component, repository, priority
	return r
}

// A pull request that splits one component into three over the same repository, and changes no
// code. Every finding keeps its file, rule and tool and changes component, so none of them is new
// and none is fixed.
func TestSplittingAComponentMovesItsFindings(t *testing.T) {
	const repo = "https://github.com/acme/shop.git"
	api, web := finding("CVE-1", "api/go.mod", 3), finding("CVE-2", "web/package.json", 9)
	admin := suppressed(finding("CVE-3", "admin/go.mod", 4), "sec@acme.test")
	base := sarif.Report{Results: []sarif.Result{
		in(api, "app", repo, "P1"), in(web, "app", repo, "P2"), in(admin, "app", repo, "P1"),
	}}
	head := sarif.Report{Results: []sarif.Result{
		in(api, "api", repo, "P1"), in(web, "web", repo, "P4"), in(admin, "admin", repo, "P1"),
	}}

	got := Compare(base, head)
	if len(got.New)+len(got.Fixed)+len(got.Accepted)+len(got.Unaccepted)+len(got.Unchanged) != 0 {
		t.Fatalf("new %d, fixed %d, accepted %d, unaccepted %d, unchanged %d; want every finding moved",
			len(got.New), len(got.Fixed), len(got.Accepted), len(got.Unaccepted), len(got.Unchanged))
	}
	if len(got.Moved) != 3 {
		t.Fatalf("moved = %d, want 3", len(got.Moved))
	}
	for _, m := range got.Moved {
		if m.Was.Component != "app" || m.Component == "app" {
			t.Errorf("%s moved %q → %q, want from app", m.RuleID, m.Was.Component, m.Component)
		}
	}
	// A priority that changed with the component is carried on the row, from both sides.
	for _, m := range got.Moved {
		if m.RuleID == "CVE-2" && (m.Was.Priority != "P2" || m.Priority != "P4") {
			t.Errorf("CVE-2 priority %s → %s, want P2 → P4", m.Was.Priority, m.Priority)
		}
	}
	if tripped := got.GateNew(sarif.SeverityLow, "P4"); len(tripped) != 0 {
		t.Errorf("a moved finding tripped the gate: %+v", tripped)
	}
}

// The repository still has to agree. A finding gone from one repository and the same file and rule
// appearing in another, under another component, is two projects: one fixed, one new.
func TestAMoveStaysInItsRepository(t *testing.T) {
	f := finding("CVE-1", "go.mod", 3)
	base := sarif.Report{Results: []sarif.Result{in(f, "app", "repo-a", "P1"), in(f, "app", "repo-b", "P1")}}
	head := sarif.Report{Results: []sarif.Result{in(f, "api", "repo-a", "P1"), in(f, "worker", "repo-c", "P1")}}

	got := Compare(base, head)
	if len(got.Moved) != 1 || got.Moved[0].Repository != "repo-a" {
		t.Errorf("moved = %+v, want only repo-a's finding", got.Moved)
	}
	if len(got.Fixed) != 1 || got.Fixed[0].Repository != "repo-b" {
		t.Errorf("fixed = %+v, want repo-b's finding", got.Fixed)
	}
	if len(got.New) != 1 || got.New[0].Repository != "repo-c" {
		t.Errorf("new = %+v, want repo-c's finding", got.New)
	}
}

// A component that still has its finding keeps it. Where two components' paths overlap and a second
// one starts reporting the same file, that copy is new, and the original is unchanged rather than
// moved.
func TestAFindingStillInItsComponentIsNotMoved(t *testing.T) {
	f := finding("CVE-1", "shared/go.mod", 3)
	base := sarif.Report{Results: []sarif.Result{in(f, "app", "repo", "P1")}}
	head := sarif.Report{Results: []sarif.Result{in(f, "api", "repo", "P1"), in(f, "app", "repo", "P1")}}

	got := Compare(base, head)
	if len(got.Moved) != 0 {
		t.Errorf("moved = %+v, want none", got.Moved)
	}
	if len(got.Unchanged) != 1 || got.Unchanged[0].Component != "app" {
		t.Errorf("unchanged = %+v, want app's finding", got.Unchanged)
	}
	if len(got.New) != 1 || got.New[0].Component != "api" {
		t.Errorf("new = %+v, want api's copy", got.New)
	}
}

// A decision that changed with the component is reported as the decision. An exclusion scoped to
// the old component no longer covers the finding, and one written for the new component excuses
// it; both are a person's call to review, and a move would hide it.
func TestAMoveThatChangesTheDecisionReportsTheDecision(t *testing.T) {
	f := finding("CVE-1", "go.mod", 3)

	lapsed := Compare(
		sarif.Report{Results: []sarif.Result{suppressed(in(f, "app", "repo", "P1"), "sec@acme.test")}},
		sarif.Report{Results: []sarif.Result{in(f, "api", "repo", "P1")}},
	)
	if len(lapsed.Unaccepted) != 1 || len(lapsed.Moved) != 0 {
		t.Errorf("an exclusion left behind: unaccepted %d, moved %d; want 1, 0", len(lapsed.Unaccepted), len(lapsed.Moved))
	}

	taken := Compare(
		sarif.Report{Results: []sarif.Result{in(f, "app", "repo", "P1")}},
		sarif.Report{Results: []sarif.Result{suppressed(in(f, "api", "repo", "P1"), "sec@acme.test")}},
	)
	if len(taken.Accepted) != 1 || len(taken.Moved) != 0 {
		t.Errorf("an exclusion written with the move: accepted %d, moved %d; want 1, 0", len(taken.Accepted), len(taken.Moved))
	}
}

// Counted drops a second scanner's copy from Moved, as it does from every other state.
func TestCountedDropsACopyFromMoved(t *testing.T) {
	copyOf := finding("CVE-1", "go.mod", 3)
	copyOf.Correlation = &sarif.Correlation{CountedUnder: "trivy"}
	r := Result{Moved: []Move{{Result: finding("CVE-1", "go.mod", 3)}, {Result: copyOf}}}
	if got := r.Counted().Moved; len(got) != 1 || got[0].Correlated() {
		t.Errorf("moved after Counted = %+v, want the counted finding alone", got)
	}
}
