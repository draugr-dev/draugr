package report

import (
	"fmt"
	"reflect"
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
		{control: "kubernetes", ruleID: "kube-bench/cis/1.1.1", priority: "P1", message: "API server file permissions"},
		{control: "kubernetes", ruleID: "kube-bench/cis/1.1.2", priority: "P1", message: "API server file ownership"},
		{control: "kubernetes", ruleID: "kube-bench/cis/1.1.3", priority: "P1", message: "Controller manager permissions"},
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
		{control: "kubernetes", ruleID: "kube-bench/cis/1.1.1", priority: "P1",
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

	byImage := map[string]action{}
	for _, a := range got {
		byImage[a.findings[0].location] = a
	}
	if !byImage["acme/api:latest"].cached {
		t.Error("the action from a tag-keyed cache entry is not marked")
	}
	if byImage["acme/db:1.2"].cached {
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
// published. So one is named and the rest are counted, because a reader following a link reads one
// of them and listing fifty-four to offer the choice fills the screen.
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
			// No dot and no colon in the first segment, so it is a namespace and not a host, the same rule a
			// container runtime uses.
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
// Nobody running a scan can upgrade a library inside an image they do not build. The fix is a newer
// image, or a wait for whoever publishes it, so grouping those findings by package scatters one
// action across every library in the image and names none of them something the reader can do, at
// the top of a list called "fix first".
func TestUpstreamImagesGroupByImageNotPackage(t *testing.T) {
	upstream := func(rule, prio, image, pkg string) finding {
		f := pkgFinding("images", rule, prio, image, pkg, "1.0", "1.1")
		f.builtUpstream = true
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

// TestActionsForGroupsByControl: the exported entry point keys on the control a run holds
// findings under, so two controls reporting the same rule id stay two things to do.
func TestActionsForGroupsByControl(t *testing.T) {
	res := func(rule, loc string) sarif.Result {
		return sarif.Result{RuleID: rule, Priority: "P2", Level: sarif.LevelWarning,
			Location: sarif.Location{URI: loc}}
	}
	got := ActionsFor(map[string]sarif.Report{
		"iac":  {Results: []sarif.Result{res("same-rule", "a.yaml")}},
		"sast": {Results: []sarif.Result{res("same-rule", "b.py")}},
	})
	if len(got) != 2 {
		t.Fatalf("two controls reporting one rule id are two actions, got %d: %+v", len(got), got)
	}
	if got[0].Control == got[1].Control {
		t.Errorf("each action should name its own control: %+v", got)
	}
}

// TestActionsForWithoutAControlFallsBackToTheRule. A merged results.sarif has already lost which
// control each finding came from, and grouping everything together would be worse than grouping
// by the rule it still has.
func TestActionsForWithoutAControlFallsBackToTheRule(t *testing.T) {
	got := ActionsFor(map[string]sarif.Report{"": {Results: []sarif.Result{
		{RuleID: "rule-a", Priority: "P2", Level: sarif.LevelWarning, Location: sarif.Location{URI: "a"}},
		{RuleID: "rule-a", Priority: "P3", Level: sarif.LevelWarning, Location: sarif.Location{URI: "b"}},
		{RuleID: "rule-b", Priority: "P4", Level: sarif.LevelNote, Location: sarif.Location{URI: "c"}},
	}}})
	if len(got) != 2 {
		t.Fatalf("want one action per rule, got %d: %+v", len(got), got)
	}
	if got[0].Clears != 2 || got[0].Priority != "P2" {
		t.Errorf("the repeated rule should be one action at its worst priority: %+v", got[0])
	}
	// Two distinct places, both named, so a caller knows where to apply it.
	if len(got[0].Where) != 2 {
		t.Errorf("both locations should be named: %+v", got[0].Where)
	}
}

// TestActionsForOmitsAcceptedRisk, as the console listing does: an excluded finding is a decision
// somebody recorded, not work to propose.
func TestActionsForOmitsAcceptedRisk(t *testing.T) {
	got := ActionsFor(map[string]sarif.Report{"sca": {Results: []sarif.Result{
		{RuleID: "CVE-1", Priority: "P1", Level: sarif.LevelError, Location: sarif.Location{URI: "a"},
			Suppression: &sarif.Suppression{Kind: "external", Justification: "accepted"}},
	}}})
	if len(got) != 0 {
		t.Errorf("an accepted finding became an action: %+v", got)
	}
}

// TestActionsForNamesAnUpstreamImageOnce: every vulnerable package inside an image somebody else
// publishes is one action. Take a newer image, not one per library.
func TestActionsForNamesAnUpstreamImageOnce(t *testing.T) {
	img := func(rule, pkgName string) sarif.Result {
		return sarif.Result{
			RuleID: rule, Priority: "P1", Level: sarif.LevelError,
			Location: sarif.Location{URI: "python:3.8-slim"}, Image: "python:3.8-slim",
			BuiltUpstream: true,
			Package:       &sarif.Package{Name: pkgName, Version: "1", FixedVersion: "2"},
		}
	}
	got := ActionsFor(map[string]sarif.Report{"images": {Results: []sarif.Result{
		img("CVE-1", "openssl"), img("CVE-2", "libssl3"), img("CVE-3", "zlib"),
	}}})
	if len(got) != 1 {
		t.Fatalf("want one action for the image, got %d: %+v", len(got), got)
	}
	if !got[0].Upstream || got[0].Clears != 3 {
		t.Errorf("the image should be one upstream action clearing all three: %+v", got[0])
	}
	if len(got[0].RuleIDs) != 3 {
		t.Errorf("the rules it clears should travel with it: %+v", got[0].RuleIDs)
	}
}

// An action's Key is what a caller matches membership on, and Title is not.
//
// A package upgrade groups on the package, not on the control that reported it. So one action can
// be fed by two controls and takes one of their names. A caller working out which findings belong
// to which action from Title and Control silently drops the other control's half: the row says it
// clears six and opens to two, and four findings with a published fix appear on no list at all.
func TestAnActionsKeyIdentifiesItWhereItsTitleCannot(t *testing.T) {
	pkg := func(fixed string) *sarif.Package {
		return &sarif.Package{Name: "flask", Ecosystem: "pypi", Version: "0.12.2", FixedVersion: fixed}
	}
	res := func(rule, fixed string) sarif.Result {
		return sarif.Result{RuleID: rule, Priority: "P1", Level: sarif.LevelError,
			Location: sarif.Location{URI: "requirements.txt"}, Package: pkg(fixed)}
	}
	// The same library, found by two controls: one reading the manifest, one reading the image.
	reports := map[string]sarif.Report{
		"sca":    {Results: []sarif.Result{res("CVE-1", "2.3.2")}},
		"images": {Results: []sarif.Result{res("CVE-2", "1.0")}},
	}

	got := ActionsFor(reports)
	if len(got) != 1 {
		t.Fatalf("one library is one upgrade, got %d: %+v", len(got), got)
	}
	if got[0].Clears != 2 {
		t.Errorf("clears = %d, want both findings", got[0].Clears)
	}
	if got[0].Key == "" {
		t.Fatal("the action carries no key to match on")
	}

	// Each finding on its own produces the key of the action it belongs to. This is the whole of
	// what membership needs, and it holds across the control boundary that Title does not.
	for control, rep := range reports {
		alone := ActionsFor(map[string]sarif.Report{control: rep})
		if len(alone) != 1 || alone[0].Key != got[0].Key {
			t.Errorf("%s alone keyed as %q, want %q", control, alone[0].Key, got[0].Key)
		}
	}
}

// Every release the advisories named, not the newest.
//
// Advisories disagree about which release resolves them, and version ordering belongs to the
// ecosystem. One entry is an answer a caller can print; several says the reader's package manager
// settles it, and naming one of them as sufficient would read as "do this and you are done" while
// leaving findings behind.
func TestAnActionCarriesEveryVersionThatClearsIt(t *testing.T) {
	res := func(rule, fixed string) sarif.Result {
		return sarif.Result{RuleID: rule, Priority: "P1", Level: sarif.LevelError,
			Location: sarif.Location{URI: "go.mod"},
			Package: &sarif.Package{
				Name: "golang.org/x/text", Ecosystem: "golang",
				Version: "0.3.0", FixedVersion: fixed,
			}}
	}
	agreed := ActionsFor(map[string]sarif.Report{"sca": {Results: []sarif.Result{
		res("CVE-1", "0.3.8"), res("CVE-2", "0.3.8"),
	}}})
	if len(agreed) != 1 || !reflect.DeepEqual(agreed[0].FixedVersions, []string{"0.3.8"}) {
		t.Errorf("fixedVersions = %+v, want the one they agree on", agreed[0].FixedVersions)
	}

	split := ActionsFor(map[string]sarif.Report{"sca": {Results: []sarif.Result{
		res("CVE-1", "0.3.8"), res("CVE-2", "0.4.0"),
	}}})
	if len(split) != 1 || len(split[0].FixedVersions) != 2 {
		t.Errorf("fixedVersions = %+v, want both releases named", split[0].FixedVersions)
	}
}

// A repository somebody else publishes is one action: theirs.
//
// The unit of work is their software, not a file inside it. Keying on the location would title the
// action after `requirements.txt`, an instruction to edit a file in a repository the reader cannot
// push to, which is exactly the advice `builtBy: upstream` exists to stop. Two packages here, so
// the test can tell one action from two.
//
// Its licenses are a second action, a review. A newer version carries the same licenses, so an
// update that claimed to clear them would claim findings it leaves in place.
func TestFindingsInSomebodyElsesRepositoryBecomeOneAction(t *testing.T) {
	fs := []finding{
		{control: "sca", ruleID: "CVE-1", location: "requirements.txt:1", repository: "https://github.com/vendor/console.git",
			component: "analytics", builtUpstream: true, priority: "P2", pkg: &sarif.Package{Name: "Flask", Version: "0.12.2"}},
		{control: "sca", ruleID: "CVE-2", location: "requirements.txt:2", repository: "https://github.com/vendor/console.git",
			component: "analytics", builtUpstream: true, priority: "P2", pkg: &sarif.Package{Name: "PyYAML", Version: "5.1"}},
		{control: "licenses", ruleID: "license/GPL-3.0-only/x", location: "requirements.txt:3",
			repository: "https://github.com/vendor/console.git", component: "analytics", builtUpstream: true, priority: "P3"},
		{control: "licenses", ruleID: "license/AGPL-3.0-only/y", location: "requirements.txt:4",
			repository: "https://github.com/vendor/console.git", component: "analytics", builtUpstream: true, priority: "P3"},
	}

	got, _ := groupActions(fs, nil)
	if len(got) != 2 {
		t.Fatalf("grouped into %d actions, want an update and a review: %+v", len(got), got)
	}
	// Named as a reader would say it, not as a clone URL.
	if got[0].title != "Update vendor/console" || len(got[0].findings) != 2 {
		t.Errorf("first action = %q clearing %d, want the repository named, clearing both packages",
			got[0].title, len(got[0].findings))
	}
	if got[1].title != "Review the licenses in vendor/console" || len(got[1].findings) != 2 {
		t.Errorf("second action = %q clearing %d, want one review of every license in it",
			got[1].title, len(got[1].findings))
	}
	if !got[0].upstream || !got[1].upstream {
		t.Error("an action does not say it is somebody else's")
	}
}

// A checkout scanned by path records the path as its repository, and "Update ." names nothing. The
// component is the fallback, because it is the thing the reader actually decided to depend on.
func TestAnUpstreamCheckoutIsNamedByItsComponent(t *testing.T) {
	got, _ := groupActions([]finding{
		{control: "sca", ruleID: "CVE-1", location: "requirements.txt:1", repository: ".",
			component: "vendor-console", builtUpstream: true, priority: "P2",
			pkg: &sarif.Package{Name: "Flask", Version: "0.12.2"}},
	}, nil)
	if len(got) != 1 || got[0].title != "Update vendor-console" {
		t.Errorf("actions = %+v, want one named after the component", got)
	}
}

// An image keeps the action it always had: the image is the thing to take a newer copy of, and it
// is already the location, so the two upstream cases must not collapse into one another.
func TestAnUpstreamImageIsStillNamedByTheImage(t *testing.T) {
	got, _ := groupActions([]finding{
		{control: "images", ruleID: "CVE-1", location: "ghcr.io/vendor/console:4.2",
			repository: "https://github.com/vendor/console.git", component: "analytics",
			builtUpstream: true, priority: "P2", pkg: &sarif.Package{Name: "openssl", Version: "1.1.1n"}},
	}, nil)
	if len(got) != 1 || got[0].title != "Update vendor/console:4.2" {
		t.Errorf("actions = %+v, want one named after the image", got)
	}
}

// TestARuleActionIsTitledWithAVerbAndTheRulesName holds every shape a rule identifier comes in to
// a title that says what to do.
//
// The scanner's message describes the flaw, and under a heading promising things to do a row
// reading "Privileged" or "By not specifying a USER, a program in the container may run as 'root'"
// is a complaint rather than an action. Each case is an identifier shape a built-in scanner emits.
func TestARuleActionIsTitledWithAVerbAndTheRulesName(t *testing.T) {
	for _, tc := range []struct {
		name, control, ruleID, message, want string
	}{
		{"a dotted path names itself in its last segment", "sast",
			"dockerfile.security.missing-user.missing-user",
			"By not specifying a USER, a program in the container may run as 'root'. This is a security hazard.",
			"Fix missing-user"},
		{"a namespaced path names itself after the last slash", "dast",
			"headers/csp-unsafe-inline", "Content-Security-Policy allows 'unsafe-inline' scripts.",
			"Fix csp-unsafe-inline"},
		{"a slug is already a name", "dast", "tls-cert-expired",
			"Certificate expired on 2026-01-31. Clients will refuse to connect, renew it now.",
			"Fix tls-cert-expired"},
		{"a catalog number carries the scanner's summary beside it", "iac", "KSV-0017", "Privileged",
			"Fix KSV-0017 “Privileged”"},
		{"a CIS section is dotted and still a number", "kubernetes", "kube-bench/cis/1.2.3",
			"Ensure that the --anonymous-auth argument is set to false",
			"Fix 1.2.3 “Ensure that the --anonymous-auth argument is set to false”"},
		{"a catalog number with no message is left alone", "iac", "KSV-0017", "", "Fix KSV-0017"},
		{"a committed credential is removed and rotated", "secrets", "private-key",
			"private-key has detected secret for file app/config.example.pem.",
			"Remove and rotate private-key"},
		{"a host on a threat feed is investigated", "threats", "urlhaus/malware-host",
			"URLhaus lists this host as serving malware", "Investigate malware-host"},
		{"no rule leaves the title to the message", "sast", "",
			"Something is wrong here. And more detail.", "Something is wrong here"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := titleFor(finding{control: tc.control, ruleID: tc.ruleID, message: tc.message})
			if got != tc.want {
				t.Errorf("title = %q, want %q", got, tc.want)
			}
		})
	}
}

// A finding scored below low reports a fact about a target, and the verb says there is nothing to
// fix. Nuclei's info templates score 1.0; its low ones 2.0, and those are still something to fix.
func TestAnInformationalFindingIsReviewed(t *testing.T) {
	info := finding{control: "dast", ruleID: "ssl-issuer", score: 1, hasScore: true}
	if got := titleFor(info); got != "Review ssl-issuer" {
		t.Errorf("title = %q, want Review", got)
	}
	low := finding{control: "dast", ruleID: "weak-cipher-suites", score: 2, hasScore: true}
	if got := titleFor(low); got != "Fix weak-cipher-suites" {
		t.Errorf("title = %q, want Fix", got)
	}
	// No score is not a score of zero.
	if got := titleFor(finding{control: "dast", ruleID: "tech-detect"}); got != "Fix tech-detect" {
		t.Errorf("title = %q, want Fix for a finding with no score", got)
	}
}

// An abbreviation's full stop is not the end of the sentence. Cutting there leaves a summary ending
// on an open parenthesis.
func TestTheFirstSentenceRunsPastAnAbbreviation(t *testing.T) {
	for msg, want := range map[string]string{
		"Missing Strict-Transport-Security: add HSTS (e.g. 'max-age=31536000') to force HTTPS. More.": "Missing Strict-Transport-Security: add HSTS (e.g. 'max-age=31536000') to force HTTPS",
		"Pin it, i.e. name a digest. Tags move.":                                                      "Pin it, i.e. name a digest",
		"Reported by J. Smith. Details follow.":                                                       "Reported by J. Smith",
		"Use str.format_map. It is safer.":                                                            "Use str.format_map",
		"Fixed in 4.3.1. Upgrade.":                                                                    "Fixed in 4.3.1",
		"No boundary at all":                                                                          "No boundary at all",
		"Its own  set of rules. More.":                                                                "Its own set of rules",
	} {
		if got := firstSentence(msg); got != want {
			t.Errorf("firstSentence(%q) = %q, want %q", msg, got, want)
		}
	}
}

// A rule's name says which rule and nothing about what it found, so the scanner's description goes
// on its own line. Only where every finding agrees on it: one host's expiry date printed under an
// action covering three hosts is wrong about two of them.
func TestARuleActionCarriesTheScannersSummary(t *testing.T) {
	rule := func(loc, msg string) finding {
		return finding{control: "sast", ruleID: "python.lang.eval-detected.eval-detected", location: loc,
			message: msg, priority: "P2"}
	}
	got, _ := groupActions([]finding{
		rule("a.py:1", "Detected the use of eval(). It is dangerous."),
		rule("b.py:1", "Detected the use of eval(). It is dangerous."),
	}, nil)
	if len(got) != 1 || got[0].summary != "Detected the use of eval()" {
		t.Errorf("actions = %+v, want one with the message's first sentence as its summary", got)
	}

	got, _ = groupActions([]finding{
		{control: "tls", ruleID: "tls-cert-expiring", location: "a.example", message: "Certificate expires in 3 day(s).", priority: "P2"},
		{control: "tls", ruleID: "tls-cert-expiring", location: "b.example", message: "Certificate expires in 9 day(s).", priority: "P2"},
	}, nil)
	if len(got) != 1 || got[0].summary != "" {
		t.Errorf("summary = %q, want none where the findings disagree", got[0].summary)
	}

	// The rule's own description describes every occurrence; a message naming one file does not.
	got, _ = groupActions([]finding{
		{control: "secrets", ruleID: "private-key", location: "a.pem", priority: "P1",
			message:     "private-key has detected secret for file a.pem.",
			ruleSummary: "Identified a Private Key, which may compromise cryptographic security."},
		{control: "secrets", ruleID: "private-key", location: "b.pem", priority: "P1",
			message:     "private-key has detected secret for file b.pem.",
			ruleSummary: "Identified a Private Key, which may compromise cryptographic security."},
	}, nil)
	if want := "Identified a Private Key, which may compromise cryptographic security"; len(got) != 1 || got[0].summary != want {
		t.Errorf("summary = %q, want the rule's description", got[0].summary)
	}

	// A description that only names the rule describes nothing, and the message does better.
	got, _ = groupActions([]finding{{control: "sast", ruleID: "x.y.missing-user", location: "Dockerfile:1",
		priority: "P2", message: "By not specifying a USER, a program may run as root. More.",
		ruleSummary: "Semgrep Finding: x.y.missing-user"}}, nil)
	if want := "By not specifying a USER, a program may run as root"; got[0].summary != want {
		t.Errorf("summary = %q, want the message's", got[0].summary)
	}

	for _, f := range []finding{
		// The title quotes it already.
		{control: "iac", ruleID: "KSV-0017", location: "pod.yaml", message: "Privileged", priority: "P1"},
		// The title is the message.
		{control: "sast", location: "main.py:1", message: "Something is wrong here.", priority: "P1"},
		// An upgrade says what to do and needs no description of the advisory.
		{control: "sca", ruleID: "CVE-1", location: "go.mod", message: "A flaw.", priority: "P1",
			pkg: &sarif.Package{Name: "x", Version: "1", FixedVersion: "2"}},
	} {
		got, _ := groupActions([]finding{f}, nil)
		if got[0].summary != "" {
			t.Errorf("%q has summary %q, want none", got[0].title, got[0].summary)
		}
	}
}

// A license is not cleared by a newer version, so it never folds into an update. In an image
// somebody else publishes, every license is one review of that image; in the reader's own code, each
// is a decision about one package.
func TestLicensesAreReviewedNotUpdated(t *testing.T) {
	got, _ := groupActions([]finding{
		{control: "images", ruleID: "CVE-1", location: "python:3.8-slim", builtUpstream: true, priority: "P1",
			image: "python:3.8-slim", pkg: &sarif.Package{Name: "openssl", Version: "1", FixedVersion: "2"}},
		{control: "licenses", ruleID: "license/GPL-2.0-or-later/adduser", location: "python:3.8-slim",
			builtUpstream: true, priority: "P2", component: "api", image: "python:3.8-slim"},
		{control: "licenses", ruleID: "license/GPL-3.0-only/bash", location: "python:3.8-slim",
			builtUpstream: true, priority: "P2", component: "api", image: "python:3.8-slim"},
		{control: "licenses", ruleID: "license/LGPL-2.1-only/libc", location: "cgr.dev/chainguard/static@sha256:abc",
			builtUpstream: true, priority: "P2", component: "api", image: "cgr.dev/chainguard/static@sha256:abc"},
		{control: "licenses", ruleID: "license/AGPL-3.0-only/golang.org/x/thing", location: "go.mod",
			priority: "P3", component: "api"},
		{control: "licenses", ruleID: "license/GPL-3.0-only", location: "vendor/COPYING", priority: "P3"},
	}, nil)
	var titles []string
	for _, a := range got {
		titles = append(titles, fmt.Sprintf("%s (%d)", a.title, a.count()))
	}
	want := []string{
		"Update python:3.8-slim (1)",
		"Review the licenses in python:3.8-slim (2)",
		"Review the licenses in chainguard/static (1)",
		"Replace or accept golang.org/x/thing, licensed AGPL-3.0-only (1)",
		"Review the files licensed GPL-3.0-only (1)",
	}
	if !reflect.DeepEqual(titles, want) {
		t.Errorf("actions =\n  %s\nwant\n  %s", strings.Join(titles, "\n  "), strings.Join(want, "\n  "))
	}
}

// ActionsFor answers for the same findings the console lists. A flaw two scanners report is one
// finding there, counted under one of them, and the fix list an assistant reads cannot clear more
// than the console says exist.
func TestActionsForSkipsWhatAnotherScannerCounts(t *testing.T) {
	jquery := &sarif.Package{Name: "jquery", Version: "1.8.1", FixedVersion: "3.5.0", Ecosystem: "npm"}
	got := ActionsFor(map[string]sarif.Report{"sca": {Results: []sarif.Result{
		{Tool: "trivy", RuleID: "CVE-2020-11023", Priority: "P1", Package: jquery,
			Location: sarif.Location{URI: "web/package-lock.json"}},
		{Tool: "retirejs", RuleID: "CVE-2020-11023", Priority: "P1", Package: jquery,
			Location:    sarif.Location{URI: "web/static/js/jquery.min.js"},
			Correlation: &sarif.Correlation{CountedUnder: "trivy"}},
	}}})
	if len(got) != 1 || got[0].Clears != 1 {
		t.Errorf("actions = %+v, want one clearing the one finding the console counts", got)
	}
}

// The summary reaches a caller outside the package, which is what an issue body is written from.
func TestActionsForCarriesTheSummary(t *testing.T) {
	got := ActionsFor(map[string]sarif.Report{"secrets": {
		Results: []sarif.Result{{Tool: "gitleaks", RuleID: "private-key", Priority: "P1",
			Message: "private-key has detected secret for file a.pem.", Location: sarif.Location{URI: "a.pem"}}},
		Rules: map[string]sarif.Rule{"private-key": {ShortDescription: "Identified a Private Key."}},
	}})
	if len(got) != 1 || got[0].Summary != "Identified a Private Key" {
		t.Errorf("actions = %+v, want the rule's description as the summary", got)
	}
}

// An action carries every finding it clears, uncapped where Where is capped, across the controls
// that fed it, with enough of each to list it: a publisher that writes the findings under the
// action reads them here rather than regrouping the run itself.
func TestAnActionCarriesEveryFindingItClears(t *testing.T) {
	var sca []sarif.Result
	for i := range 7 {
		sca = append(sca, sarif.Result{RuleID: fmt.Sprintf("CVE-%d", i), Priority: "P2", Level: sarif.LevelWarning,
			Tool: "trivy", Component: "api", Location: sarif.Location{URI: fmt.Sprintf("svc%d/requirements.txt", i), StartLine: 3},
			Package: &sarif.Package{Name: "flask", Ecosystem: "pypi", Version: "0.12.2", FixedVersion: "2.3.2"}})
	}
	images := sarif.Result{RuleID: "CVE-9", Priority: "P1", Level: sarif.LevelError, Tool: "grype", Component: "api",
		Location: sarif.Location{URI: "requirements.txt"},
		Package:  &sarif.Package{Name: "flask", Ecosystem: "pypi", Version: "0.12.2", FixedVersion: "2.3.2"}}
	rule := func(loc string) sarif.Result {
		return sarif.Result{RuleID: "no-root", Priority: "P3", Level: sarif.LevelWarning, Tool: "checkov",
			Component: "api", Location: sarif.Location{URI: loc}}
	}
	got := ActionsFor(map[string]sarif.Report{
		"sca":    {Results: sca},
		"images": {Results: []sarif.Result{images}},
		"iac": {Results: []sarif.Result{rule("a/Dockerfile"), rule("b/Dockerfile")},
			Rules: map[string]sarif.Rule{"no-root": {ShortDescription: "Image runs as root"}}},
	})
	if len(got) != 2 {
		t.Fatalf("want the upgrade and the rule, got %d: %+v", len(got), got)
	}
	upgrade, byRule := got[0], got[1]
	if len(upgrade.Findings) != 8 || upgrade.Clears != 8 {
		t.Fatalf("the upgrade lists %d findings and clears %d, want 8 of each", len(upgrade.Findings), upgrade.Clears)
	}
	if !upgrade.OneChange || byRule.OneChange {
		t.Errorf("OneChange: upgrade %v, rule %v; want true, false", upgrade.OneChange, byRule.OneChange)
	}
	first := upgrade.Findings[0]
	want := ActionFinding{Control: "images", RuleID: "CVE-9", Tool: "grype", Priority: "P1",
		Severity: sarif.SeverityHigh, Component: "api", Location: "requirements.txt",
		HelpURI:     "https://nvd.nist.gov/vuln/detail/CVE-9",
		Fingerprint: images.Fingerprint(), Upgrade: "flask 0.12.2 → 2.3.2"}
	if first != want {
		t.Errorf("first finding = %+v\nwant %+v", first, want)
	}
	if upgrade.Findings[1].Location != "svc0/requirements.txt:3" {
		t.Errorf("a location carries its line: %q", upgrade.Findings[1].Location)
	}
	if len(byRule.Findings) != 2 || byRule.Findings[0].Control != "iac" {
		t.Errorf("rule findings = %+v", byRule.Findings)
	}
}

// TestADependencyIsOneActionPerComponent: two components carrying the same library are two owners,
// and a row naming both could be handed to neither.
func TestADependencyIsOneActionPerComponent(t *testing.T) {
	web := pkgFinding("sca", "CVE-1", "P1", "web/package-lock.json:12", "jquery", "1.8.3", "1.12.2")
	web.component = "web"
	admin := pkgFinding("sca", "CVE-1", "P2", "admin/package-lock.json:30", "jquery", "1.8.3", "1.12.2")
	admin.component = "admin"
	got, _ := groupActions([]finding{web, admin}, nil)
	if len(got) != 2 {
		t.Fatalf("one library in two components is two actions, got %d: %+v", len(got), got)
	}
	if got[0].component != "web" || got[1].component != "admin" {
		t.Errorf("each action should belong to one component, most urgent first: %q, %q",
			got[0].component, got[1].component)
	}
	exported := ActionsFor(map[string]sarif.Report{"sca": {Results: []sarif.Result{
		{RuleID: "CVE-1", Priority: "P1", Component: "web", Location: sarif.Location{URI: "web/package-lock.json"},
			Package: &sarif.Package{Name: "jquery", Version: "1.8.3", FixedVersion: "1.12.2"}},
		{RuleID: "CVE-1", Priority: "P2", Component: "admin", Location: sarif.Location{URI: "admin/package-lock.json"},
			Package: &sarif.Package{Name: "jquery", Version: "1.8.3", FixedVersion: "1.12.2"}},
	}}})
	if len(exported) != 2 || exported[0].Component != "web" || exported[1].Component != "admin" {
		t.Errorf("the exported actions should carry their component: %+v", exported)
	}
}

// TestTwoInstalledVersionsAreTwoActions: a title names the version in hand, so a row folding a
// second copy at another version is wrong about that copy.
func TestTwoInstalledVersionsAreTwoActions(t *testing.T) {
	got, _ := groupActions([]finding{
		pkgFinding("sca", "CVE-1", "P1", "package-lock.json:12", "jquery", "1.8.3", "1.12.2"),
		pkgFinding("sca", "CVE-2", "P2", "static/jquery-3.4.0.min.js", "jquery", "3.4.0", "3.5.0"),
	}, nil)
	if len(got) != 2 {
		t.Fatalf("two installed versions are two actions, got %d: %+v", len(got), got)
	}
	titles := []string{got[0].title + " → " + got[0].target(), got[1].title + " → " + got[1].target()}
	want := []string{"Upgrade jquery 1.8.3 → 1.12.2", "Upgrade jquery 3.4.0 → 3.5.0"}
	if !reflect.DeepEqual(titles, want) {
		t.Errorf("titles = %q, want %q", titles, want)
	}
}

// TestTheSamePathInTwoRepositoriesIsTwoPlaces: paths are repository-relative, so two
// repositories' lockfiles share a path and are still two files to edit.
func TestTheSamePathInTwoRepositoriesIsTwoPlaces(t *testing.T) {
	a := pkgFinding("sca", "CVE-1", "P1", "package-lock.json:12", "jquery", "1.8.3", "1.12.2")
	a.component, a.repository = "web", "https://github.com/acme/web-ui"
	b := pkgFinding("sca", "CVE-1", "P1", "package-lock.json:12", "jquery", "1.8.3", "1.12.2")
	b.component, b.repository = "web", "https://github.com/acme/web-legacy"
	got, _ := groupActions([]finding{a, b}, nil)
	if len(got) != 1 {
		t.Fatalf("one component, one version, one upgrade: got %d", len(got))
	}
	where := got[0].where(5)
	want := []string{"acme/web-ui package-lock.json:12", "acme/web-legacy package-lock.json:12"}
	if !reflect.DeepEqual(where, want) {
		t.Errorf("where = %q, want %q", where, want)
	}
	if n := countDistinct(got[0].findings); n != 2 {
		t.Errorf("two repositories are two places, counted %d", n)
	}

	// One repository names none: every location would carry the same prefix.
	got, _ = groupActions([]finding{a}, nil)
	if where := got[0].where(5); !reflect.DeepEqual(where, []string{"package-lock.json:12"}) {
		t.Errorf("a single repository should not prefix its locations: %q", where)
	}
}

// TestAVendoredCopyIsMarked: bumping a lockfile leaves a copy of the library beside it untouched,
// so the row says which locations are copies.
func TestAVendoredCopyIsMarked(t *testing.T) {
	got, _ := groupActions([]finding{
		pkgFinding("sca", "CVE-1", "P1", "package-lock.json:12", "jquery", "1.8.3", "1.12.2"),
		pkgFinding("sca", "CVE-2", "P1", "static/js/jquery.min.js", "jquery", "1.8.3", "1.12.2"),
		pkgFinding("images", "CVE-3", "P1", "acme/api:1.0", "libssl3", "3.0.1", "3.0.2"),
	}, nil)
	var where []string
	for _, a := range got {
		where = append(where, a.where(5)...)
	}
	want := []string{"package-lock.json:12", "static/js/jquery.min.js vendored", "acme/api:1.0"}
	if !reflect.DeepEqual(where, want) {
		t.Errorf("where = %q, want %q", where, want)
	}
}

// TestComponentsAreNamedOnlyWhenTheyDiffer: one component on every row says nothing a reader can
// use, so the label appears once the list spans two.
func TestComponentsAreNamedOnlyWhenTheyDiffer(t *testing.T) {
	one := []action{{component: "web"}, {component: "web"}, {}}
	if actionsNameComponents(one) {
		t.Error("a list with one component should not name it")
	}
	two := []action{{component: "web"}, {}, {component: "admin"}}
	if !actionsNameComponents(two) {
		t.Error("a list spanning two components should name them")
	}
}

// TestALongDetailGivesWayInOrder: where a detail does not fit, the second location goes first, then
// the directories in front of the first, then the rule reference. The file name and the count of
// what is not named stay, because they say what to edit and that there is more than one place.
func TestALongDetailGivesWayInOrder(t *testing.T) {
	one := action{findings: []finding{{ruleID: "CVE-2018-1000656", location: "services/payments/app/requirements.txt:2"}}}
	two := action{findings: append(append([]finding{}, one.findings...),
		finding{ruleID: "CVE-2018-1000656", location: "worker/requirements.txt:2"})}
	for _, c := range []struct {
		name string
		a    action
		room int
		want string
	}{
		{"everything fits", two, 120,
			"services/payments/app/requirements.txt:2 · worker/requirements.txt:2 · CVE-2018-1000656 +1"},
		{"the second location is counted", two, 80,
			"services/payments/app/requirements.txt:2 · and 1 more · CVE-2018-1000656 +1"},
		{"directories go before the rule", two, 55,
			"…/requirements.txt:2 · and 1 more · CVE-2018-1000656 +1"},
		{"directories go whole", one, 45,
			"…/app/requirements.txt:2 · CVE-2018-1000656"},
		{"the rule goes before the file name", two, 36,
			"…/requirements.txt:2 · and 1 more"},
		{"narrower than a file name cuts the first part", two, 12,
			elide("services/payments/app/requirements.txt:2", minTitleWidth)},
		{"whole parts while they fit", action{findings: []finding{
			{ruleID: "CVE-1", location: "requirements.txt:2"}, {ruleID: "CVE-1", location: "setup.cfg:9"},
		}}, 20, "requirements.txt:2"},
	} {
		if got := fitDetail(tui.Plain(), c.a, c.room, 2); got != c.want {
			t.Errorf("%s: fitDetail(room %d) = %q, want %q", c.name, c.room, got, c.want)
		}
		if strings.HasSuffix(fitDetail(tui.Plain(), c.a, c.room, 2), "·…") {
			t.Errorf("%s: a detail should never end on a cut separator", c.name)
		}
	}
}

func TestClipDirsKeepsTheFileName(t *testing.T) {
	for _, c := range []struct {
		in    string
		width int
		want  string
		ok    bool
	}{
		{"a/b/c/requirements.txt:2", 20, "…/requirements.txt:2", true},
		{"a/b/c/requirements.txt:2", 22, "…/c/requirements.txt:2", true},
		{"app/static/js/jquery.min.js vendored", 30, "…/js/jquery.min.js vendored", true},
		{"a/requirements.txt:2", 10, "", false},
		{"requirements.txt:2", 10, "", false},
	} {
		got, ok := clipDirs(c.in, c.width)
		if got != c.want || ok != c.ok {
			t.Errorf("clipDirs(%q, %d) = %q, %v, want %q, %v", c.in, c.width, got, ok, c.want, c.ok)
		}
	}
}

// TestAnExportedActionNamesItsDependencyAndEachPlace: report.json and MCP carry what a reader
// needs to act without parsing a title, and every place the action applies, with what kind of edit
// each one is.
func TestAnExportedActionNamesItsDependencyAndEachPlace(t *testing.T) {
	jq := func(fixed string) *sarif.Package {
		return &sarif.Package{Name: "jquery", Version: "1.8.3", FixedVersion: fixed, Ecosystem: "npm"}
	}
	got := ActionsFor(map[string]sarif.Report{
		"sca": {Results: []sarif.Result{
			{RuleID: "CVE-1", Priority: "P1", Component: "web", Repository: "https://github.com/acme/web",
				Location: sarif.Location{URI: "web/package-lock.json", StartLine: 12}, Package: jq("3.5.0")},
			{RuleID: "CVE-2", Priority: "P2", Component: "web", Repository: "https://github.com/acme/web",
				Location: sarif.Location{URI: "web/static/js/jquery.min.js"}, Package: jq("1.9.0")},
			{RuleID: "CVE-3", Priority: "P2", Component: "web", Repository: "https://github.com/acme/web",
				Location: sarif.Location{URI: "web/package.json", StartLine: 4}, Package: jq("3.5.0")},
		}},
		"sast": {Results: []sarif.Result{
			{RuleID: "python.exec", Priority: "P3", Component: "web", Location: sarif.Location{URI: "setup.py", StartLine: 3}},
		}},
		"licenses": {Results: []sarif.Result{
			{RuleID: "license/0BSD/tslib", Priority: "P4", Component: "web", Location: sarif.Location{URI: "yarn.lock"}},
		}},
		"images": {Results: []sarif.Result{
			{RuleID: "CVE-4", Priority: "P2", Component: "web", Location: sarif.Location{URI: "redis:7"},
				Package: &sarif.Package{Name: "libssl3", Version: "3.0.1", FixedVersion: "3.0.2", Ecosystem: "debian"}},
		}},
	})
	byPackage := map[string]Action{}
	for _, a := range got {
		byPackage[a.Package+"|"+a.Control] = a
	}

	up := byPackage["jquery|sca"]
	if up.Ecosystem != "npm" || up.From != "1.8.3" || up.Target != "3.5.0" || up.Component != "web" {
		t.Errorf("the upgrade should name its dependency and both versions: %+v", up)
	}
	wantLocs := []ActionLocation{
		{Repository: "https://github.com/acme/web", Path: "web/package-lock.json", Line: 12, Kind: "lockfile"},
		{Repository: "https://github.com/acme/web", Path: "web/package.json", Line: 4, Kind: "manifest"},
		{Repository: "https://github.com/acme/web", Path: "web/static/js/jquery.min.js", Kind: "vendored"},
	}
	if !reflect.DeepEqual(up.Locations, wantLocs) {
		t.Errorf("locations = %+v\nwant %+v", up.Locations, wantLocs)
	}
	if len(up.Findings) != 3 || up.Findings[0].Fingerprint == "" {
		t.Errorf("the action should carry each finding with the fingerprint results.sarif records: %+v", up.Findings)
	}

	if img := byPackage["libssl3|images"]; len(img.Locations) != 1 ||
		img.Locations[0] != (ActionLocation{Path: "redis:7", Kind: "image"}) {
		t.Errorf("an image reference is one place of kind image, its tag left whole: %+v", img.Locations)
	}
	for _, a := range got {
		switch a.Control {
		case "sast":
			if a.Package != "" || a.Locations[0].Kind != "file" {
				t.Errorf("a SAST finding in setup.py is about the code, not a dependency: %+v", a)
			}
		case "licenses":
			if a.Locations[0].Kind != "lockfile" {
				t.Errorf("a package's license read from yarn.lock is in a lockfile: %+v", a.Locations)
			}
		}
	}
}

// TestAnActionIDIsStableAndSaysWhatItMovesTo: the same findings give the same ID on the next run,
// and a different component or target is a different action.
func TestAnActionIDIsStableAndSaysWhatItMovesTo(t *testing.T) {
	run := func(component, fixed string) string {
		return ActionsFor(map[string]sarif.Report{"sca": {Results: []sarif.Result{
			{RuleID: "CVE-1", Priority: "P1", Component: component, Location: sarif.Location{URI: "package-lock.json"},
				Package: &sarif.Package{Name: "jquery", Version: "1.8.3", FixedVersion: fixed, Ecosystem: "npm"}},
		}}})[0].ID
	}
	first := run("web", "3.5.0")
	if len(first) != 16 {
		t.Errorf("id = %q, want sixteen hex characters", first)
	}
	if again := run("web", "3.5.0"); again != first {
		t.Errorf("the same action should keep its id: %q, then %q", first, again)
	}
	if run("admin", "3.5.0") == first || run("web", "3.6.0") == first {
		t.Error("another component or another target should be another id")
	}
}

// TestFindingsThatRankAlikeKeepOneOrder: a scanner that reports concurrently writes its findings in
// a different order on every run, and the list has to come out the same either way.
func TestFindingsThatRankAlikeKeepOneOrder(t *testing.T) {
	a := finding{control: "secrets", ruleID: "generic-api-key", priority: "P1", component: "api", location: "shared.env:1"}
	b := finding{control: "secrets", ruleID: "generic-api-key", priority: "P1", component: "api", location: "api.env:1"}
	one, two := []finding{a, b}, []finding{b, a}
	sortFindings(one)
	sortFindings(two)
	if !reflect.DeepEqual(one, two) || one[0].location != "api.env:1" {
		t.Errorf("findings that rank alike should sort by place: %+v, then %+v", one, two)
	}
}
