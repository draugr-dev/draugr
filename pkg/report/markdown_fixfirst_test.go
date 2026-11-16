package report

import (
	"fmt"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// fixFirstActionsData is a run of twelve upgrades across two components in two repositories: one
// clearing a P1 and a P2 advisory, one whose package sits in four lockfiles, and ten more, one of
// them raised by KEV so the run has a Signals section.
func fixFirstActionsData() Data {
	const repoA, repoB = "https://github.com/acme/a.git", "https://github.com/acme/b.git"
	dep := func(rule, priority, component, repo, uri, pkg, fixed string) sarif.Result {
		return sarif.Result{RuleID: rule, Tool: "trivy", Level: sarif.LevelError, Priority: priority,
			Component: component, Repository: repo, Message: rule + " in " + pkg,
			Location: sarif.Location{URI: uri, StartLine: 3},
			Package:  &sarif.Package{Name: pkg, Version: "1.0.0", FixedVersion: fixed, Ecosystem: "npm"}}
	}
	results := []sarif.Result{
		dep("CVE-2026-0001", "P1", "api", repoA, "package-lock.json", "lodash", "1.0.1"),
		dep("CVE-2026-0002", "P2", "api", repoA, "package-lock.json", "lodash", "1.0.1"),
	}
	for _, uri := range []string{"a/package-lock.json", "b/package-lock.json", "c/package-lock.json", "d/package-lock.json"} {
		results = append(results, dep("CVE-2026-0003", "P2", "web", repoB, uri, "minimist", "1.0.2"))
	}
	for i := range 10 {
		results = append(results, dep(fmt.Sprintf("CVE-2026-01%02d", i), "P3", "web", repoB, "package-lock.json",
			fmt.Sprintf("pkg-%02d", i), "2.0.0"))
	}
	results[len(results)-1].Escalation = &sarif.Escalation{Signal: "kev", From: "high", To: "critical"}
	return Data{Verdict: norn.Result{Verdict: norn.Fail}, Run: engine.Result{Controls: map[string]plugin.ControlResult{
		"sca": {Control: "sca", Report: sarif.Report{Tool: "trivy", Results: results}},
	}}}
}

// Fix first in markdown lists actions under the band counts, ahead of the whole-run tables: how many
// findings each clears and how many sit at its own band where they differ, a place list cut short
// with where the rest are, and ten actions before pointing at the HTML report for the others.
func TestMarkdownFixFirstListsActionsUnderTheCounts(t *testing.T) {
	md := renderWith(t, markdownReporter{}, fixFirstActionsData())
	counts, fixFirst, signals := strings.Index(md, "| Findings |"), strings.Index(md, "### Fix first"), strings.Index(md, "### Signals")
	if counts < 0 || fixFirst < 0 || signals < 0 || counts > fixFirst || fixFirst > signals {
		t.Fatalf("want the counts, then Fix first, then Signals:\n%s", md)
	}
	section := md[fixFirst:signals]
	for _, want := range []string{
		// One upgrade clearing a P1 and a P2 says how many of its two are at its band.
		"- **P1** Upgrade lodash 1.0.0 → 1.0.1 · 2 findings, 1 at P1 · api · ",
		// Every finding at the row's band: the total alone.
		"- **P2** Upgrade minimist 1.0.0 → 1.0.2 · 4 findings · web · ",
		"and 2 more places, in the HTML report\n",
		"\n_…and 2 more actions, in the HTML report's What to do._\n",
	} {
		if !strings.Contains(section, want) {
			t.Errorf("Fix first lacks %q:\n%s", want, section)
		}
	}
	if rows := strings.Count(section, "\n- **"); rows != markdownActionsN {
		t.Errorf("Fix first lists %d actions, want %d:\n%s", rows, markdownActionsN, section)
	}
	if strings.Contains(md, "| Rule |") || strings.Contains(md, "CVE-2026-0001") {
		t.Errorf("the markdown still lists findings one by one:\n%s", md)
	}
}

// A place list cut short by one says place, singular; a run under --min-priority keeps the filter
// in the heading.
func TestMarkdownFixFirstSingularPlaceAndFilteredHeading(t *testing.T) {
	d := fixFirstActionsData()
	sca := d.Run.Controls["sca"]
	sca.Report.Results = append(sca.Report.Results[:5:5], sca.Report.Results[6])
	d.Run.Controls["sca"] = sca
	d.MinPriority = "P2"
	md := renderWith(t, markdownReporter{}, d)
	for _, want := range []string{"### Fix first (P2 and above; 1 lower-priority finding hidden)\n", "and 1 more place, in the HTML report\n"} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown lacks %q:\n%s", want, md)
		}
	}
	if strings.Contains(md, "more actions") {
		t.Errorf("a list that fits says more are elsewhere:\n%s", md)
	}
}

// A finding on infrastructure somebody else operates is no action, and Fix first says how many such
// findings there are rather than leaving them out of a list that counts the rest; where every finding
// is of that kind, it says that alone.
func TestMarkdownFixFirstCountsWhatIsNotYoursToFix(t *testing.T) {
	provider := sarif.Result{RuleID: "kube-bench/1.1.1", Tool: "kube-bench", Level: sarif.LevelError, Priority: "P1",
		ProviderOperated: true, Message: "API server file permissions"}
	const line = "_1 finding on infrastructure operated by your provider (kubernetes), reported, and not yours to fix._\n"

	d := fixFirstActionsData()
	d.Run.Controls["kubernetes"] = plugin.ControlResult{Control: "kubernetes",
		Report: sarif.Report{Tool: "kube-bench", Results: []sarif.Result{provider}}}
	md := renderWith(t, markdownReporter{}, d)
	if !strings.Contains(md, "What to do._\n\n"+line) {
		t.Errorf("Fix first does not count the provider's finding under its actions:\n%s", md)
	}

	only := Data{Verdict: norn.Result{Verdict: norn.Fail}, Run: engine.Result{Controls: map[string]plugin.ControlResult{
		"kubernetes": d.Run.Controls["kubernetes"],
	}}}
	md = renderWith(t, markdownReporter{}, only)
	if !strings.Contains(md, "### Fix first\n\n"+line) {
		t.Errorf("Fix first with no action of the reader's:\n%s", md)
	}
}
