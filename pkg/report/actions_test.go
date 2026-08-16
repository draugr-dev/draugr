package report

import (
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/tui"
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
	// One release fixes all three, so the action can name it. Where advisories disagree it names
	// none: version ordering is the ecosystem's, and naming the wrong release as sufficient reads
	// as "do this and you are done" when it would leave findings behind.
	if v := got[0].target(); v != "50.0.1" {
		t.Errorf("target = %q, want the single release that fixes all of them", v)
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
	if v := got[0].target(); v != "" {
		t.Errorf("target = %q, but the advisories disagree and none of them is the answer", v)
	}
	if fixes := got[0].fixedVersions(); len(fixes) != 3 {
		t.Errorf("every release that fixes something should still be recorded: %v", fixes)
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

// TestActionRowKeepsAWayIntoTheFindings covers what grouping takes away.
//
// Grouping answers "what do I do" and removes "what exactly is wrong", which is the question a
// reader has next. The rule identifier answers it, and carries the link to whatever the scanner
// published — so one is named and the rest are counted, because a reader following a link reads
// one of them and listing fifty-four to offer the choice fills the screen.
func TestActionRowKeepsAWayIntoTheFindings(t *testing.T) {
	in := []finding{
		pkgFinding("sca", "CVE-2019-10906", "P1", "req.txt", "jinja2", "2.10", "2.10.1"),
		pkgFinding("sca", "CVE-2020-28493", "P4", "req.txt", "jinja2", "2.10", "2.11.3"),
	}
	in[0].helpURI = "https://nvd.nist.gov/vuln/detail/CVE-2019-10906"

	got, _ := groupActions(in, nil)
	detail := actionDetail(tui.Painter{}, got[0], 2)

	if !strings.Contains(detail, "CVE-2019-10906") {
		t.Errorf("the row gives no way to read about any of its findings: %q", detail)
	}
	if !strings.Contains(detail, "+1") {
		t.Errorf("the row should say how many more it stands for: %q", detail)
	}
}

// TestDisplayLocationShortensImageReferences: a digest-pinned reference from a private registry
// runs past 130 characters, and two of them leave no room for anything else on the line. The
// digest is what makes a scan reproducible and belongs in the report; what the reader needs here
// is which image to rebuild.
func TestDisplayLocationShortensImageReferences(t *testing.T) {
	for _, c := range []struct{ name, control, in, want string }{
		{
			name:    "digest dropped, registry host trimmed, namespace kept",
			control: "images",
			in:      "registry.example.com/team/sync/redis:8.2.2@sha256:c892889d1b23c30b5ab1500fa4b3850e",
			want:    "team/sync/redis:8.2.2",
		},
		{
			name:    "an official image is left alone",
			control: "images",
			in:      "ubuntu:22.04",
			want:    "ubuntu:22.04",
		},
		{
			// No dot and no colon in the first segment, so it is a namespace and not a host —
			// the same rule a container runtime uses.
			name:    "a namespace is not mistaken for a host",
			control: "images",
			in:      "myteam/app:1.0",
			want:    "myteam/app:1.0",
		},
		{
			// A path shortened to its basename loses the directory, which is the part that
			// distinguishes two Dockerfiles.
			name:    "a file path is never trimmed",
			control: "iac",
			in:      "deploy/overlays/production/kustomization.yaml:12",
			want:    "deploy/overlays/production/kustomization.yaml:12",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := displayLocation(finding{control: c.control, location: c.in}); got != c.want {
				t.Errorf("got  %q\nwant %q", got, c.want)
			}
		})
	}
}

// TestUpstreamImagesGroupByImageNotPackage is the correction that matters most in this list.
//
// Nobody running a scan can upgrade a library inside an image they do not build. The fix is a
// newer image, or a wait for whoever publishes it — so grouping those findings by package
// scatters one action across every library in the image and names none of them something the
// reader can do, at the top of a list called "fix first".
func TestUpstreamImagesGroupByImageNotPackage(t *testing.T) {
	upstream := func(rule, prio, image, pkg string) finding {
		f := pkgFinding("images", rule, prio, image, pkg, "1.0", "1.1")
		f.imageBuiltUpstream = true
		return f
	}
	in := []finding{
		upstream("CVE-1", "P1", "registry.example.com/vendor/redis:8.2.2", "libcrypto3"),
		upstream("CVE-2", "P2", "registry.example.com/vendor/redis:8.2.2", "libssl3"),
		upstream("CVE-3", "P1", "registry.example.com/vendor/argocd:3.2.11", "libcrypto3"),
	}

	got, _ := groupActions(in, nil)
	if len(got) != 2 {
		t.Fatalf("two images are two actions, got %d: %+v", len(got), got)
	}
	for _, a := range got {
		if !strings.HasPrefix(a.title, "Update ") {
			t.Errorf("the action should be to take a newer image, got %q", a.title)
		}
		if strings.Contains(a.title, "libcrypto3") || strings.Contains(a.title, "libssl3") {
			t.Errorf("the action named a package the reader cannot upgrade: %q", a.title)
		}
	}
	// And the image carrying two of them leads, because it clears more at the same band.
	if got[0].count() != 2 {
		t.Errorf("the image with more findings should lead: %+v", got[0])
	}
}

// TestImagesYouBuildStillGroupByPackage: the default is that you build your images, and there the
// package upgrade is exactly the action.
func TestImagesYouBuildStillGroupByPackage(t *testing.T) {
	in := []finding{
		pkgFinding("images", "CVE-1", "P1", "acme/api:1.0", "libcrypto3", "3.6.0", "3.6.2"),
		pkgFinding("images", "CVE-2", "P1", "acme/worker:1.0", "libcrypto3", "3.6.0", "3.6.2"),
	}
	got, _ := groupActions(in, nil)
	if len(got) != 1 {
		t.Fatalf("one library across two images you build is one upgrade, got %d", len(got))
	}
	if !strings.HasPrefix(got[0].title, "Upgrade libcrypto3") {
		t.Errorf("title = %q", got[0].title)
	}
}
