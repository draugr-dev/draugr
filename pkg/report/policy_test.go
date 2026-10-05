package report

import (
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/tui"
)

// upgradeFinding is a dependency finding in one component, with the policy its component set.
func upgradeFinding(rule, prio, component, policy, ecosystem, name, version, fixed string) finding {
	f := pkgFinding("sca", rule, prio, "package-lock.json:12", name, version, fixed)
	f.component, f.upgradePolicy = component, policy
	f.pkg.Ecosystem = ecosystem
	return f
}

func TestStepOfSizesAChange(t *testing.T) {
	for _, c := range []struct {
		ecosystem, from, to string
		want                string
		ok                  bool
	}{
		{"npm", "1.8.3", "1.8.4", "patch", true},
		{"npm", "1.8.3", "1.12.2", "minor", true},
		{"npm", "1.8.3", "3.5.0", "major", true},
		// In 0.x a minor step may break, so it is a major one.
		{"Go", "v0.3.0", "v0.3.8", "patch", true},
		{"Go", "v0.3.0", "v0.39.0", "major", true},
		{"PyPI", "2.10", "2.11.3", "minor", true},
		{"npm", "1.8.3", "1.9.0b1", "minor", true},
		{"npm", "1.8.3", "1.9.0-rc.1", "minor", true},
		// A Maven qualifier names a flavor, so the version is not semantic.
		{"Maven", "31.1-jre", "32.0-jre", "", false},
		{"Maven", "2.14.1", "2.15.0", "minor", true},
		// A calendar version is not read as a major upgrade it is not.
		{"PyPI", "2024.1", "2025.3", "", false},
		{"npm", "not-a-version", "1.0.0", "", false},
	} {
		got, ok := stepOf(c.ecosystem, c.from, c.to)
		if string(got) != c.want || ok != c.ok {
			t.Errorf("stepOf(%s, %s, %s) = %q, %v, want %q, %v", c.ecosystem, c.from, c.to, got, ok, c.want, c.ok)
		}
	}
}

// TestAPolicySplitsAnUpgradeInTwo: every finding stays in exactly one action. The step the policy
// allows clears what it can, and the step past it carries only what it alone clears, banded by
// those findings and following the first.
func TestAPolicySplitsAnUpgradeInTwo(t *testing.T) {
	in := []finding{
		upgradeFinding("CVE-1", "P1", "web", "minor", "npm", "jquery", "1.8.3", "3.5.0"),
		upgradeFinding("CVE-2", "P2", "web", "minor", "npm", "jquery", "1.8.3", "1.12.2, 3.0.0"),
		upgradeFinding("CVE-3", "P3", "web", "minor", "npm", "jquery", "1.8.3", "1.9.0"),
	}
	got, _ := groupActions(in, nil)
	if len(got) != 2 {
		t.Fatalf("want the step within the policy and the step past it, got %d: %+v", len(got), got)
	}
	within, beyond := got[0], got[1]
	if within.title+" → "+within.target() != "Upgrade jquery 1.8.3 → 1.12.2" || within.count() != 2 || within.priority != "P2" {
		t.Errorf("within = %q → %q, %d findings, %s", within.title, within.target(), within.count(), within.priority)
	}
	if beyond.title+" → "+beyond.target() != "Upgrade jquery 1.12.2 → 3.5.0" || beyond.count() != 1 || beyond.priority != "P1" {
		t.Errorf("beyond = %q → %q, %d findings, %s", beyond.title, beyond.target(), beyond.count(), beyond.priority)
	}
	if l := beyond.step.label(); l != "major · beyond policy minor" {
		t.Errorf("label = %q", l)
	}
	if within.step.label() != "" {
		t.Errorf("the step within the policy needs no label: %q", within.step.label())
	}
	if beyond.step.after != within.id() || beyond.key == within.key || beyond.id() == within.id() {
		t.Error("the step past the policy should follow the first and be its own action")
	}
}

// TestAPackagesStepsStayTogether: ranked by the package's worst band, so a P2 minor step is read
// beside the P1 major step that follows it, ahead of another package's P1.
func TestAPackagesStepsStayTogether(t *testing.T) {
	in := []finding{
		upgradeFinding("CVE-1", "P1", "api", "minor", "npm", "jquery", "1.8.3", "3.5.0"),
		upgradeFinding("CVE-1", "P1", "api", "minor", "npm", "jquery", "1.8.3", "3.5.0"),
		upgradeFinding("CVE-9", "P1", "api", "minor", "npm", "lodash", "4.17.10", "4.17.21"),
		upgradeFinding("CVE-2", "P2", "api", "minor", "npm", "jquery", "1.8.3", "1.12.0"),
	}
	got, _ := groupActions(in, nil)
	var titles []string
	for _, a := range got {
		titles = append(titles, a.priority+" "+a.title)
	}
	want := []string{"P2 Upgrade jquery 1.8.3", "P1 Upgrade jquery 1.12.0", "P1 Upgrade lodash 4.17.10"}
	if !reflect.DeepEqual(titles, want) {
		t.Errorf("order = %q, want %q", titles, want)
	}
}

func TestAPolicyLeavesWhatItCannotSplit(t *testing.T) {
	t.Run("everything within", func(t *testing.T) {
		got, _ := groupActions([]finding{upgradeFinding("CVE-1", "P1", "web", "minor", "npm", "jquery", "1.8.3", "1.12.2")}, nil)
		if len(got) != 1 || got[0].step == nil || !got[0].step.applies || got[0].step.label() != "" {
			t.Errorf("an upgrade inside the policy is one unlabeled action: %+v", got)
		}
	})
	t.Run("everything beyond", func(t *testing.T) {
		got, _ := groupActions([]finding{upgradeFinding("CVE-1", "P1", "web", "patch", "pip", "Flask", "0.12.2", "3.1.3")}, nil)
		if len(got) != 1 || got[0].step.label() != "major · beyond policy patch" || got[0].step.after != "" {
			t.Errorf("an upgrade only a larger step clears is one action, labeled: %+v", got[0].step)
		}
	})
	t.Run("not semantic", func(t *testing.T) {
		got, _ := groupActions([]finding{upgradeFinding("CVE-1", "P1", "api", "minor", "debian", "libssl3", "3.0.14-1~deb12u2", "3.0.22-1~deb12u1")}, nil)
		if len(got) != 1 || got[0].step == nil || got[0].step.applies || got[0].step.label() != "" {
			t.Errorf("a distribution's versions are not split: %+v", got[0].step)
		}
	})
	t.Run("default", func(t *testing.T) {
		for _, policy := range []string{"", "major"} {
			got, _ := groupActions([]finding{upgradeFinding("CVE-1", "P1", "web", policy, "npm", "jquery", "1.8.3", "3.5.0")}, nil)
			if len(got) != 1 || got[0].step != nil {
				t.Errorf("policy %q should leave the action as it was: %+v", policy, got[0].step)
			}
		}
	})
	t.Run("no release within clears them all", func(t *testing.T) {
		// Each finding has a fix within the policy, on lines no one release reaches.
		got, _ := groupActions([]finding{
			upgradeFinding("CVE-1", "P1", "web", "minor", "npm", "jquery", "1.8.3", "1.9.1, 3.0.0"),
			upgradeFinding("CVE-2", "P1", "web", "minor", "npm", "jquery", "1.8.3", "1.10.1, 3.0.0"),
		}, nil)
		if len(got) != 1 || got[0].target() != "3.0.0" || got[0].step.label() != "major · beyond policy minor" {
			t.Errorf("with no single release inside the policy the action stays whole and says where it goes: %q, %+v",
				got[0].target(), got[0].step)
		}
	})
}

// TestTheExportedActionStatesItsPolicy: report.json and MCP carry the policy, whether each step is
// within it, which step a step past it follows, and where the policy could not apply.
func TestTheExportedActionStatesItsPolicy(t *testing.T) {
	pkg := func(fixed string) *sarif.Package {
		return &sarif.Package{Name: "jquery", Version: "1.8.3", FixedVersion: fixed, Ecosystem: "npm"}
	}
	res := func(rule, prio, fixed string) sarif.Result {
		return sarif.Result{RuleID: rule, Priority: prio, Component: "web", UpgradePolicy: "minor",
			Location: sarif.Location{URI: "package-lock.json"}, Package: pkg(fixed)}
	}
	got := ActionsFor(map[string]sarif.Report{"sca": {Results: []sarif.Result{
		res("CVE-1", "P1", "3.5.0"), res("CVE-2", "P2", "1.12.2"),
		{RuleID: "CVE-3", Priority: "P2", Component: "api", UpgradePolicy: "minor", Location: sarif.Location{URI: "python:3.8-slim"},
			Package: &sarif.Package{Name: "libssl3", Version: "3.0.14-1~deb12u2", FixedVersion: "3.0.22-1~deb12u1", Ecosystem: "debian"}},
	}}})
	by := map[string]Action{}
	for _, a := range got {
		by[a.Title] = a
	}
	within, beyond, deb := by["Upgrade jquery 1.8.3"], by["Upgrade jquery 1.12.2"], by["Upgrade libssl3 3.0.14-1~deb12u2"]
	if within.Policy != "minor" || within.WithinPolicy == nil || !*within.WithinPolicy || within.After != "" {
		t.Errorf("within = %+v", within)
	}
	if beyond.WithinPolicy == nil || *beyond.WithinPolicy || beyond.After != within.ID || beyond.Target != "3.5.0" {
		t.Errorf("beyond = %+v", beyond)
	}
	if deb.Policy != "minor" || deb.PolicyApplies == nil || *deb.PolicyApplies || deb.WithinPolicy != nil {
		t.Errorf("a distribution package should say the policy did not apply: %+v", deb)
	}
}

func TestAllows(t *testing.T) {
	if !allows(saga.UpgradeMinor, saga.UpgradePatch) || allows(saga.UpgradeMinor, saga.UpgradeMajor) || allows(saga.UpgradePatch, saga.UpgradeMinor) {
		t.Error("a policy admits steps up to its own size and no larger")
	}
}

// TestAStepPastThePolicySaysSoOnItsTitle: the label sits beside the instruction it qualifies, in
// the console and the HTML report alike, and the step within the policy carries none.
func TestAStepPastThePolicySaysSoOnItsTitle(t *testing.T) {
	got, _ := groupActions([]finding{
		upgradeFinding("CVE-1", "P1", "web", "minor", "npm", "jquery", "1.8.3", "3.5.0"),
		upgradeFinding("CVE-2", "P2", "web", "minor", "npm", "jquery", "1.8.3", "1.12.2"),
	}, nil)
	var buf strings.Builder
	renderActions(&buf, tui.Plain(), got, false)
	lines := strings.Split(buf.String(), "\n")
	if lines[0] != "  P2  Upgrade jquery 1.8.3 → 1.12.2" {
		t.Errorf("the step within the policy = %q", lines[0])
	}
	if lines[2] != "  P1  Upgrade jquery 1.12.2 → 3.5.0  major · beyond policy minor" {
		t.Errorf("the step past it = %q", lines[2])
	}
	if h := toHTMLAction(got[1]); h.Policy != "major · beyond policy minor" || toHTMLAction(got[0]).Policy != "" {
		t.Errorf("html policy = %q and %q", toHTMLAction(got[0]).Policy, h.Policy)
	}
}

// TestTheHTMLReportOpensEachStepsOwnFindings: findings of one package split across two actions
// belong to the one the grouping put them in, which the finding's own key cannot tell apart.
func TestTheHTMLReportOpensEachStepsOwnFindings(t *testing.T) {
	d := goldenFullData()
	pkg := func(fixed string) *sarif.Package {
		return &sarif.Package{Name: "jquery", Version: "1.8.3", FixedVersion: fixed, Ecosystem: "npm"}
	}
	d.Run.Controls["sca"] = plugin.ControlResult{Report: sarif.Report{Results: []sarif.Result{
		{RuleID: "CVE-1", Priority: "P1", Level: sarif.LevelError, Component: "web", UpgradePolicy: "minor",
			Location: sarif.Location{URI: "package-lock.json"}, Package: pkg("3.5.0")},
		{RuleID: "CVE-2", Priority: "P2", Level: sarif.LevelError, Component: "web", UpgradePolicy: "minor",
			Location: sarif.Location{URI: "package-lock.json"}, Package: pkg("1.12.2")},
	}}}
	page := renderHTML(t, d)
	if !strings.Contains(page, "major · beyond policy minor") {
		t.Fatal("the step past the policy is not labeled")
	}
	acts := section(t, page, `id="acts"`, `</section>`)
	keys := regexp.MustCompile(`<div class="act" data-a="([^"]+)"`).FindAllStringSubmatch(acts, -1)
	if len(keys) < 2 {
		t.Fatalf("want both steps on the page, got %d actions", len(keys))
	}
	// A finding row names its action after its scanner; an action row names it too, but never there.
	opens := map[string]int{}
	for _, m := range regexp.MustCompile(`data-sc="[^"]*" data-a="([^"]+)"`).FindAllStringSubmatch(page, -1) {
		opens[m[1]]++
	}
	var steps []string
	for _, k := range keys {
		if strings.Contains(k[1], "jquery") {
			steps = append(steps, k[1])
		}
	}
	if len(steps) != 2 || opens[steps[0]] != 1 || opens[steps[1]] != 1 {
		t.Errorf("each step should open its own one finding: steps %q, findings by action %v", steps, opens)
	}
}

// TestThePolicyNoteCountsWhatItCouldNotSplit: one line per policy, naming each ecosystem with its
// count, over the actions given, and nothing when the policy applied everywhere.
func TestThePolicyNoteCountsWhatItCouldNotSplit(t *testing.T) {
	deb := func(name string) finding {
		f := upgradeFinding("CVE-1", "P1", "api", "minor", "debian", name, "3.0.14-1~deb12u2", "3.0.22-1~deb12u1")
		f.control = "images"
		return f
	}
	maven := upgradeFinding("CVE-2", "P2", "api", "minor", "pom", "guava", "31.1-jre", "32.0.0-jre")
	patch := upgradeFinding("CVE-3", "P2", "web", "patch", "debian", "zlib1g", "1:1.2.13-1", "1:1.2.13-1+deb12u1")
	split := upgradeFinding("CVE-4", "P1", "web", "minor", "npm", "jquery", "1.8.3", "1.12.2")
	got, _ := groupActions([]finding{deb("libssl3"), deb("openssl"), maven, patch, split}, nil)
	want := []string{
		"policy patch · not applied to 1 action · debian 1",
		"policy minor · not applied to 3 actions · debian 2 · maven 1",
	}
	if notes := policyNotes(got); !reflect.DeepEqual(notes, want) {
		t.Errorf("notes = %q, want %q", notes, want)
	}
	// Over the rows given: a list showing none of them says nothing.
	var none []action
	for _, a := range got {
		if a.step == nil || a.step.applies {
			none = append(none, a)
		}
	}
	if notes := policyNotes(none); len(notes) != 0 {
		t.Errorf("no note where the policy applied to everything listed: %q", notes)
	}

	// The HTML report carries the same lines, and marks each row so its script can recount them
	// over what a narrowing leaves.
	d := goldenFullData()
	d.Run.Controls["images"] = plugin.ControlResult{Report: sarif.Report{Results: []sarif.Result{
		{RuleID: "CVE-1", Priority: "P1", Level: sarif.LevelError, Component: "api", UpgradePolicy: "minor",
			Location: sarif.Location{URI: "python:3.8-slim"},
			Package:  &sarif.Package{Name: "libssl3", Version: "3.0.14-1~deb12u2", FixedVersion: "3.0.22-1~deb12u1", Ecosystem: "debian"}},
	}}}
	page := renderHTML(t, d)
	for _, want := range []string{
		`<div class="note" id="policy-na"><div>policy minor · not applied to 1 action · debian 1</div></div>`,
		`data-na="minor" data-eco="debian"`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the HTML report is missing %q", want)
		}
	}
	if !strings.Contains(renderHTML(t, goldenFullData()), `id="policy-na" hidden>`) {
		t.Error("with nothing unsplit the note should be present and hidden, for the script to fill")
	}
}
