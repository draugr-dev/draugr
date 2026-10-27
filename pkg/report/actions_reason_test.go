package report

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/skald"
)

// depResult is a dependency finding as results.sarif carries it.
func depResult(component, repo, rule, priority string, score float64, name, version, fixed string) sarif.Result {
	return sarif.Result{RuleID: rule, Tool: "trivy", Control: "sca", Priority: priority, Level: sarif.LevelError,
		Score: score, HasScore: true, Component: component, Repository: repo,
		Location: sarif.Location{URI: "web/package-lock.json", StartLine: 12},
		Package:  &sarif.Package{Name: name, Version: version, FixedVersion: fixed, Ecosystem: "npm"}}
}

// raised is r with the escalation a feed recorded on it.
func raised(r sarif.Result, signal, detail string, to sarif.Severity) sarif.Result {
	r.Escalation = &sarif.Escalation{From: r.Severity(""), To: to, Signal: signal, Detail: detail, AsOf: "2026-10-20"}
	return r
}

// byPackage indexes actions by component and package.
func byPackage(actions []Action) map[string]Action {
	out := map[string]Action{}
	for _, a := range actions {
		out[a.Component+"/"+a.Package] = a
	}
	return out
}

// TestAnActionSaysWhatItRanksBy: each action carries the keys that order it inside its band, the
// exploitation evidence and the worst severity as ranked, with the scanners' worst where something
// moved it, so a reader can say why it sits where it does instead of guessing from its count.
func TestAnActionSaysWhatItRanksBy(t *testing.T) {
	const shop, admin = "https://github.com/acme/shop", "https://github.com/acme/admin"
	results := []sarif.Result{
		// One library in two repositories of one component: one upgrade, whose medium flaw KEV raised.
		raised(depResult("web", shop, "CVE-2020-11023", "P1", 6.1, "jquery", "1.8.3", "3.5.0"), "kev", "on KEV", sarif.SeverityCritical),
		depResult("web", admin, "CVE-2020-11022", "P2", 6.1, "jquery", "1.8.3", "3.5.0"),
		// A high flaw EPSS raised.
		raised(depResult("web", shop, "CVE-2022-0001", "P1", 7.5, "requests", "2.19.0", "2.20.0"), "epss", "EPSS 0.87", sarif.SeverityCritical),
		// Both signals in one package: KEV decides, whichever finding comes first.
		raised(depResult("web", shop, "CVE-2022-0002", "P1", 7.5, "minimist", "1.2.5", "1.2.6"), "epss", "EPSS 0.95", sarif.SeverityCritical),
		raised(depResult("web", admin, "CVE-2021-44906", "P1", 3.1, "minimist", "1.2.5", "1.2.6"), "kev", "on KEV", sarif.SeverityCritical),
		// More findings, no evidence.
		depResult("web", shop, "CVE-2020-8203", "P1", 7.4, "lodash", "4.17.15", "4.17.21"),
		depResult("web", admin, "CVE-2021-23337", "P1", 7.2, "lodash", "4.17.15", "4.17.21"),
		depResult("web", admin, "CVE-2020-28500", "P1", 5.3, "lodash", "4.17.15", "4.17.21"),
	}
	// Reachability lowered a critical to high: the action ranks as high and says it was critical.
	lowered := depResult("web", shop, "GO-2024-0001", "P1", 9.8, "x/net", "0.17.0", "0.23.0")
	lowered.Reachability = &sarif.Reachability{State: sarif.ReachabilityUnreachable, Analyzer: "govulncheck",
		RankedAs: sarif.SeverityHigh}
	results = append(results, lowered)

	got := ActionsFor(map[string]sarif.Report{"": {Results: results}})
	by := byPackage(got)
	for name, want := range map[string]struct {
		severity, from sarif.Severity
		exploitation   *skald.ActionExploitation
	}{
		"web/jquery": {sarif.SeverityCritical, sarif.SeverityMedium,
			&skald.ActionExploitation{Signal: "kev", RuleID: "CVE-2020-11023", Detail: "on KEV", AsOf: "2026-10-20"}},
		"web/requests": {sarif.SeverityCritical, sarif.SeverityHigh,
			&skald.ActionExploitation{Signal: "epss", RuleID: "CVE-2022-0001", Detail: "EPSS 0.87", AsOf: "2026-10-20"}},
		"web/minimist": {sarif.SeverityCritical, sarif.SeverityHigh,
			&skald.ActionExploitation{Signal: "kev", RuleID: "CVE-2021-44906", Detail: "on KEV", AsOf: "2026-10-20"}},
		"web/lodash": {sarif.SeverityHigh, "", nil},
		"web/x/net":  {sarif.SeverityHigh, sarif.SeverityCritical, nil},
	} {
		a, ok := by[name]
		if !ok {
			t.Fatalf("no action for %s in %+v", name, got)
		}
		if a.Severity != want.severity || a.SeverityFrom != want.from || !reflect.DeepEqual(a.Exploitation, want.exploitation) {
			t.Errorf("%s: severity %q from %q, exploitation %+v; want %q from %q, %+v",
				name, a.Severity, a.SeverityFrom, a.Exploitation, want.severity, want.from, want.exploitation)
		}
	}
	// The fields account for the order: KEV, then EPSS, then the rest by severity and count. jQuery
	// and minimist are alike in every key, and either may lead.
	var order []string
	for _, a := range got {
		order = append(order, a.Package)
	}
	if len(order) != 5 || !reflect.DeepEqual(order[2:], []string{"requests", "lodash", "x/net"}) ||
		order[0] == order[1] || (order[0] != "jquery" && order[0] != "minimist") ||
		(order[1] != "jquery" && order[1] != "minimist") {
		t.Errorf("order = %v, want jquery and minimist, then requests, lodash, x/net", order)
	}
	if by["web/jquery"].Clears != 2 || by["web/lodash"].Clears != 3 {
		t.Errorf("jquery clears %d and lodash %d; the fixture wants KEV to outrank the larger action",
			by["web/jquery"].Clears, by["web/lodash"].Clears)
	}
}

// TestTheReasonIsInReportJSONOnlyWhereThereIsOne: the fields are additive, named in the words a
// finding's escalation uses, and absent from an action nothing moved.
func TestTheReasonIsInReportJSONOnlyWhereThereIsOne(t *testing.T) {
	got := ActionsFor(map[string]sarif.Report{"": {Results: []sarif.Result{
		raised(depResult("web", "", "CVE-2020-11023", "P1", 6.1, "jquery", "1.8.3", "3.5.0"), "kev", "on KEV", sarif.SeverityCritical),
		depResult("web", "", "CVE-2020-8203", "P1", 7.4, "lodash", "4.17.15", "4.17.21"),
	}}})
	if len(got) != 2 {
		t.Fatalf("want two actions, got %d", len(got))
	}
	kev, err := json.Marshal(got[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`"severity":"critical"`, `"severityFrom":"medium"`,
		`"exploitation":{"signal":"kev","ruleId":"CVE-2020-11023","detail":"on KEV","asOf":"2026-10-20"}`,
	} {
		if !strings.Contains(string(kev), want) {
			t.Errorf("the KEV action's JSON lacks %s:\n%s", want, kev)
		}
	}
	plain, err := json.Marshal(got[1])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(plain), `"severity":"high"`) ||
		strings.Contains(string(plain), "severityFrom") || strings.Contains(string(plain), "exploitation") {
		t.Errorf("an action nothing moved carries its severity and nothing else:\n%s", plain)
	}
}

// TestBothStepsOfASplitUpgradeGiveThePackagesReason: the two steps rank together, by what either
// clears, so the step within the policy carries the KEV finding the step past it clears; without it
// the step would sit above actions it outranks on nothing it states. The same library in a second
// component is another owner's action and ranks on its own findings.
func TestBothStepsOfASplitUpgradeGiveThePackagesReason(t *testing.T) {
	const shop, admin = "https://github.com/acme/shop", "https://github.com/acme/admin"
	step := func(component, repo, rule, priority, fixed string) sarif.Result {
		r := depResult(component, repo, rule, priority, 6.1, "jquery", "1.8.3", fixed)
		r.UpgradePolicy = "minor"
		return r
	}
	got := ActionsFor(map[string]sarif.Report{"": {Results: []sarif.Result{
		step("web", shop, "CVE-2015-9251", "P2", "1.12.2"),
		raised(step("web", admin, "CVE-2020-11023", "P1", "3.5.0"), "kev", "on KEV", sarif.SeverityCritical),
		step("api", shop, "CVE-2020-11023", "P2", "3.5.0"),
	}}})
	var web []Action
	var api *Action
	for i, a := range got {
		switch a.Component {
		case "web":
			web = append(web, a)
		case "api":
			api = &got[i]
		}
	}
	if len(web) != 2 || web[1].After != web[0].ID {
		t.Fatalf("want web's upgrade split in two steps, the second after the first: %+v", web)
	}
	want := &skald.ActionExploitation{Signal: "kev", RuleID: "CVE-2020-11023", Detail: "on KEV", AsOf: "2026-10-20"}
	for _, s := range web {
		if s.Severity != sarif.SeverityCritical || s.SeverityFrom != sarif.SeverityMedium || !reflect.DeepEqual(s.Exploitation, want) {
			t.Errorf("%q should carry the package's reason: severity %q from %q, exploitation %+v",
				s.Title, s.Severity, s.SeverityFrom, s.Exploitation)
		}
	}
	if web[0].Priority != "P2" {
		t.Errorf("the step within the policy keeps its own band, P2, got %q", web[0].Priority)
	}
	if api == nil || api.Exploitation != nil || api.Severity != sarif.SeverityMedium || api.SeverityFrom != "" {
		t.Errorf("api's jquery is ranked on its own findings, none of them raised: %+v", api)
	}
}

// TestListsOfSplitsTheFixListAsTheConsoleDoes: one list per kind, in the order the console prints
// them, each keeping the order the ranking gave it, and a kind no list names after the rest.
func TestListsOfSplitsTheFixListAsTheConsoleDoes(t *testing.T) {
	actions := []Action{
		{ID: "decide-1", Kind: skald.KindDecide},
		{ID: "code-1", Kind: skald.KindCode},
		{ID: "bump-1", Kind: skald.KindBump},
		{ID: "odd-1", Kind: "unlisted"},
		{ID: "code-2", Kind: skald.KindCode},
		{ID: "credential-1", Kind: skald.KindCredential},
	}
	var got [][]string
	for _, l := range ListsOf(actions) {
		var ids []string
		for _, a := range l.Actions {
			if a.Kind != l.Kind {
				t.Errorf("%s holds a %s action", l.Kind, a.Kind)
			}
			ids = append(ids, a.ID)
		}
		got = append(got, ids)
	}
	want := [][]string{{"bump-1"}, {"code-1", "code-2"}, {"credential-1"}, {"decide-1"}, {"odd-1"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("lists = %v, want %v", got, want)
	}
	if ListsOf(nil) == nil || len(ListsOf(nil)) != 0 {
		t.Error("no actions are no lists, as an empty slice")
	}
}
