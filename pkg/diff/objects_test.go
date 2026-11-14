package diff

import (
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// check is one finding listing the objects that fail a check, its message written from them the way
// a scanner reporting a set writes it.
func check(rule, cluster, component string, objects ...string) sarif.Result {
	return sarif.Result{
		Tool: "draugr-k8s-policies", RuleID: rule, Level: sarif.LevelError,
		Message:  rule + ": " + strings.Join(objects, ", "),
		Location: sarif.Location{URI: "kubernetes/" + cluster}, Component: component,
		Objects: objects,
	}
}

// One object joins a check in one cluster and one leaves the same check in another. The first is
// new and the second unchanged; neither is fixed, since both checks still fail.
func TestAChecksObjectsDecideWhatChanged(t *testing.T) {
	base := sarif.Report{Results: []sarif.Result{
		check("cis/5.2.2", "prod", "api", "kube-system/kube-proxy"),
		check("cis/5.2.2", "staging", "web", "apps/old", "kube-system/kube-proxy"),
	}}
	head := sarif.Report{Results: []sarif.Result{
		check("cis/5.2.2", "prod", "api", "default/debug", "kube-system/kube-proxy"),
		check("cis/5.2.2", "staging", "web", "kube-system/kube-proxy"),
	}}

	got := Compare(base, head)
	if len(got.Fixed) != 0 {
		t.Errorf("fixed = %+v, want none", got.Fixed)
	}
	if len(got.New) != 1 || got.New[0].Component != "api" {
		t.Errorf("new = %+v, want prod's check, which gained a pod", got.New)
	}
	if len(got.Unchanged) != 1 || got.Unchanged[0].Component != "web" {
		t.Errorf("unchanged = %+v, want staging's check, which only lost one", got.Unchanged)
	}
	if len(got.GateNew(sarif.SeverityLow, "")) != 1 {
		t.Error("the gate on new findings did not trip on the check that gained a pod")
	}
}

// A check is still keyed by where it was read and by whom: the same check in two clusters, or in
// two components reading one cluster, does not pair across them.
func TestAChecksObjectsPairOnlyInTheirOwnPlace(t *testing.T) {
	base := sarif.Report{Results: []sarif.Result{
		check("cis/5.2.2", "prod", "api", "a/x"),
		check("cis/5.2.3", "prod", "api", "a/x"),
	}}
	head := sarif.Report{Results: []sarif.Result{
		check("cis/5.2.2", "staging", "api", "a/x", "a/y"),
		check("cis/5.2.4", "prod", "api", "a/x", "a/y"),
	}}
	got := Compare(base, head)
	if len(got.New) != 2 || len(got.Fixed) != 2 || len(got.Unchanged) != 0 {
		t.Errorf("new %d, fixed %d, unchanged %d; want two new and two fixed",
			len(got.New), len(got.Fixed), len(got.Unchanged))
	}
}

// A check under another component in the head, its cluster unchanged, is moved when its objects are
// the ones it had, and new when one joined, so a gate on new findings still sees the object.
func TestAMovedCheckThatGainedAnObjectIsNew(t *testing.T) {
	base := sarif.Report{Results: []sarif.Result{
		check("cis/5.2.2", "prod", "platform", "kube-system/kube-proxy", "apps/agent"),
		check("cis/5.2.3", "prod", "platform", "kube-system/kube-proxy", "apps/agent"),
	}}
	head := sarif.Report{Results: []sarif.Result{
		check("cis/5.2.2", "prod", "cluster", "kube-system/kube-proxy"),
		check("cis/5.2.3", "prod", "cluster", "default/debug", "kube-system/kube-proxy", "apps/agent"),
	}}
	got := Compare(base, head)
	if len(got.Moved) != 1 || got.Moved[0].RuleID != "cis/5.2.2" {
		t.Errorf("moved = %+v, want 5.2.2", got.Moved)
	}
	if len(got.New) != 1 || got.New[0].RuleID != "cis/5.2.3" {
		t.Errorf("new = %+v, want 5.2.3, which gained a pod", got.New)
	}
	if len(got.Fixed) != 0 {
		t.Errorf("fixed = %+v, want none", got.Fixed)
	}
}

// A decision still reads as a decision. A check somebody excused at the head is accepted whatever
// joined it, and one excused in both stays unchanged.
func TestAnExcusedCheckIsADecisionWhateverItsObjects(t *testing.T) {
	base := sarif.Report{Results: []sarif.Result{
		check("cis/5.2.2", "prod", "api", "a/x"),
		suppressed(check("cis/5.2.3", "prod", "api", "a/x")),
	}}
	head := sarif.Report{Results: []sarif.Result{
		suppressed(check("cis/5.2.2", "prod", "api", "a/x", "a/y")),
		suppressed(check("cis/5.2.3", "prod", "api", "a/x", "a/y")),
	}}
	got := Compare(base, head)
	if len(got.Accepted) != 1 || got.Accepted[0].RuleID != "cis/5.2.2" {
		t.Errorf("accepted = %+v, want 5.2.2", got.Accepted)
	}
	if len(got.Unchanged) != 1 || got.Unchanged[0].RuleID != "cis/5.2.3" {
		t.Errorf("unchanged = %+v, want 5.2.3, excused in both", got.Unchanged)
	}
	if len(got.New)+len(got.Fixed) != 0 {
		t.Errorf("new %d, fixed %d, want none", len(got.New), len(got.Fixed))
	}
}

// A finding that lists no objects is compared as before, and so is a base written before findings
// carried their objects: its message is all there is to go on.
func TestAFindingWithoutObjectsIsComparedByItsMessage(t *testing.T) {
	old := check("cis/5.2.2", "prod", "api", "kube-system/kube-proxy")
	old.Objects = nil
	base := sarif.Report{Results: []sarif.Result{old}}
	head := sarif.Report{Results: []sarif.Result{check("cis/5.2.2", "prod", "api", "default/debug", "kube-system/kube-proxy")}}
	got := Compare(base, head)
	if len(got.New) != 1 || len(got.Fixed) != 1 {
		t.Errorf("new %d, fixed %d; want the comparison by message, one of each", len(got.New), len(got.Fixed))
	}
	if gainedObjects(head.Results[0], old) {
		t.Error("gainedObjects with no objects at the base, want false")
	}
	if objectSetKey(old) != "" {
		t.Error("objectSetKey for a finding without objects, want empty")
	}
}
