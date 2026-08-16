package report

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

func pkgFinding(control, rule, prio, loc, name, version, fixed string) finding {
	f := finding{control: control, ruleID: rule, priority: prio, location: loc, message: rule}
	if name != "" {
		f.pkg = &sarif.Package{Name: name, Version: version, FixedVersion: fixed}
		if fixed != "" {
			f.remediation = sarif.RemediationUpgrade
		}
	}
	return f
}

// TestGroupActionsFoldsOneFixIntoOneRow covers the case that pays off most: a library a year out
// of date carries a dozen findings and one upgrade.
func TestGroupActionsFoldsOneFixIntoOneRow(t *testing.T) {
	in := []finding{
		pkgFinding("sca", "CVE-1", "P1", "poetry.lock", "cryptography", "49.0.0", "50.0.1"),
		pkgFinding("sca", "CVE-2", "P3", "poetry.lock", "cryptography", "49.0.0", "50.0.1"),
		pkgFinding("sca", "CVE-3", "P3", "poetry.lock", "cryptography", "49.0.0", "50.0.1"),
	}
	got, _ := groupActions(in, nil)
	if len(got) != 1 {
		t.Fatalf("want one action, got %d: %+v", len(got), got)
	}
	if got[0].title != "Upgrade cryptography 49.0.0" {
		t.Errorf("title = %q", got[0].title)
	}
	// One release fixes all three, so it is named plainly. Where advisories disagree the detail
	// lists them without picking one: version ordering is the ecosystem's, and naming the wrong
	// release as sufficient reads as "do this and you are done" when it would leave findings
	// behind. TestActionNamesEveryFixWithoutPickingOne covers that case.
	if d := got[0].detail(3); d != "fixed in 50.0.1" {
		t.Errorf("detail = %q", d)
	}
	if got[0].count() != 3 {
		t.Errorf("the action should say it clears 3 findings, said %d", got[0].count())
	}
	// The worst band in the group, never lowered by the lesser findings it also clears.
	if got[0].priority != "P1" {
		t.Errorf("priority = %q, want the worst it clears", got[0].priority)
	}
}

// TestGroupActionsKeepsDistinctWorkDistinct is the failure worth guarding against. Twelve
// benchmark checks against one cluster are twelve things to change, and folding them together
// because they share a prefix would hide eleven of them.
func TestGroupActionsKeepsDistinctWorkDistinct(t *testing.T) {
	in := []finding{
		{control: "infrastructure", ruleID: "kube-bench/cis/1.1.1", priority: "P1", message: "API server file permissions"},
		{control: "infrastructure", ruleID: "kube-bench/cis/1.1.2", priority: "P1", message: "API server file ownership"},
		{control: "infrastructure", ruleID: "kube-bench/cis/1.1.3", priority: "P1", message: "Controller manager permissions"},
	}
	got, _ := groupActions(in, nil)
	if len(got) != 3 {
		t.Fatalf("three different checks are three actions, got %d", len(got))
	}
}

// TestGroupActionsFoldsOneRuleAcrossFiles: the same rule in several places is one thing to
// understand and apply.
func TestGroupActionsFoldsOneRuleAcrossFiles(t *testing.T) {
	in := []finding{
		{control: "secrets", ruleID: "generic-api-key", priority: "P1", location: "docs/example.yaml:65", message: "generic-api-key detected"},
		{control: "secrets", ruleID: "generic-api-key", priority: "P1", location: "scripts/build.ps1:164", message: "generic-api-key detected"},
		{control: "secrets", ruleID: "generic-api-key", priority: "P1", location: "test/app.yaml:75", message: "generic-api-key detected"},
	}
	got, _ := groupActions(in, nil)
	if len(got) != 1 {
		t.Fatalf("want one action, got %d", len(got))
	}
	if w := got[0].where(4); len(w) != 3 {
		t.Errorf("every distinct location should be named: %v", w)
	}
}

// TestGroupActionsExcludesWhatNobodyCanFix: a list of things to fix that opens with work the
// reader cannot do teaches them the list is not worth reading.
func TestGroupActionsExcludesWhatNobodyCanFix(t *testing.T) {
	in := []finding{
		{control: "infrastructure", ruleID: "kube-bench/cis/1.1.1", priority: "P1",
			remediation: sarif.RemediationExternal, message: "API server file permissions"},
		pkgFinding("sca", "CVE-1", "P3", "poetry.lock", "cryptography", "49.0.0", "50.0.1"),
	}
	actions, external := groupActions(in, nil)
	if len(actions) != 1 || actions[0].control != "sca" {
		t.Fatalf("only the actionable finding belongs in the list: %+v", actions)
	}
	if len(external) != 1 {
		t.Errorf("the rest must still be reported, got %d", len(external))
	}
}

// TestActionsRankByPriorityBeforeVolume: an action clearing one P1 outranks one clearing forty
// P4s. A P1 is not something to trade away for volume.
func TestActionsRankByPriorityBeforeVolume(t *testing.T) {
	in := []finding{
		pkgFinding("sca", "CVE-1", "P1", "go.mod", "one", "1.0", "1.1"),
		{control: "iac", ruleID: "DS-0002", priority: "P4", message: "root user"},
		{control: "iac", ruleID: "DS-0002", priority: "P4", location: "b", message: "root user"},
		{control: "iac", ruleID: "DS-0002", priority: "P4", location: "c", message: "root user"},
	}
	got, _ := groupActions(in, nil)
	if got[0].priority != "P1" {
		t.Errorf("the P1 action should lead, got %q clearing %d", got[0].priority, got[0].count())
	}
}

// TestActionsWithoutPrioritiesSortLast: "" is lexically below "P1" and must not lead the list.
func TestActionsWithoutPrioritiesSortLast(t *testing.T) {
	in := []finding{
		{control: "sast", ruleID: "no-band", message: "unbanded"},
		pkgFinding("sca", "CVE-1", "P2", "go.mod", "one", "1.0", "1.1"),
	}
	got, _ := groupActions(in, nil)
	if got[0].priority != "P2" {
		t.Errorf("an unprioritized action led the list: %+v", got[0])
	}
}

// TestActionNamesEveryFixWithoutPickingOne covers advisories that disagree about which release
// resolves them, which is the common case for a library a year out of date.
func TestActionNamesEveryFixWithoutPickingOne(t *testing.T) {
	in := []finding{
		pkgFinding("sca", "CVE-1", "P1", "req.txt", "jinja2", "2.10", "2.10.1"),
		pkgFinding("sca", "CVE-2", "P2", "req.txt", "jinja2", "2.10", "3.1.5"),
		pkgFinding("sca", "CVE-3", "P4", "req.txt", "jinja2", "2.10", "2.11.3"),
	}
	got, _ := groupActions(in, nil)
	if len(got) != 1 {
		t.Fatalf("one library is one upgrade, got %d actions", len(got))
	}
	if d := got[0].detail(3); d != "fixed in 2.10.1, 3.1.5, 2.11.3 — take the latest" {
		t.Errorf("detail = %q", d)
	}
}

// TestActionDetailCapsTheReleasesItNames keeps a row inside a terminal when a library has
// collected many advisories.
func TestActionDetailCapsTheReleasesItNames(t *testing.T) {
	var in []finding
	for _, fixed := range []string{"1.1", "1.2", "1.3", "1.4", "1.5", "1.6"} {
		in = append(in, pkgFinding("sca", "CVE-"+fixed, "P2", "req.txt", "lib", "1.0", fixed))
	}
	got, _ := groupActions(in, nil)
	want := "fixed in 1.1, 1.2, 1.3 and 3 other releases — take the latest"
	if d := got[0].detail(3); d != want {
		t.Errorf("detail = %q\nwant     %q", d, want)
	}
}

// TestActionsFlagWhatCameFromCache puts the caveat beside the row it applies to.
//
// A note further down saying an image was reused from a tag makes the reader connect it back to
// whichever rows came from that image. Marking the row says it where the decision is made.
func TestActionsFlagWhatCameFromCache(t *testing.T) {
	in := []finding{
		{control: "images", ruleID: "CVE-1", priority: "P1", location: "acme/api:latest", message: "a"},
		{control: "images", ruleID: "CVE-2", priority: "P1", location: "acme/db:1.2", message: "b"},
	}
	got, _ := groupActions(in, []string{"acme/api:latest"})

	byTitle := map[string]action{}
	for _, a := range got {
		byTitle[a.title] = a
	}
	if !byTitle["a"].cached {
		t.Error("the action from a tag-keyed cache entry is not marked")
	}
	if byTitle["b"].cached {
		t.Error("an action that was freshly scanned was marked as cached")
	}
}

// TestActionIsOnlyCachedWhenAllOfItIs: an action grouping one stale finding with three current
// ones is not a stale action, and marking it so tells a reader to distrust work that is current.
func TestActionIsOnlyCachedWhenAllOfItIs(t *testing.T) {
	in := []finding{
		{control: "iac", ruleID: "DS-0002", priority: "P2", location: "acme/api:latest", message: "x"},
		{control: "iac", ruleID: "DS-0002", priority: "P2", location: "Dockerfile", message: "x"},
	}
	got, _ := groupActions(in, []string{"acme/api:latest"})
	if len(got) != 1 {
		t.Fatalf("want one action, got %d", len(got))
	}
	if got[0].cached {
		t.Error("an action with a freshly scanned finding in it was marked cached")
	}
}
