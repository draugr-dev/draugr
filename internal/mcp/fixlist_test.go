package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/report"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/skald"
)

// fixListRun is a run with what makes the grouping hard to get right from a merged file: one
// component holding two images somebody else publishes, the licenses inside both, the same library
// at the same version in two components with an upgrade policy that splits one of them into a step
// within the policy and a step past it, a committed credential, a finding set aside, and a copy of
// a flaw another scanner already counted.
func fixListRun() engine.Result {
	const (
		python    = "python:3.8-slim"
		chainward = "cgr.dev/chainguard/static:latest"
	)
	image := func(ref, rule, pkg, priority string) sarif.Result {
		return sarif.Result{RuleID: rule, Tool: "trivy", Priority: priority, Level: sarif.LevelError,
			Component: "api", Image: ref, BuiltUpstream: true, Location: sarif.Location{URI: ref},
			Message: rule + " in " + pkg,
			Package: &sarif.Package{Name: pkg, Version: "1.0", FixedVersion: "1.1", Ecosystem: "debian"}}
	}
	license := func(ref, rule, priority string) sarif.Result {
		return sarif.Result{RuleID: rule, Tool: "trivy", Priority: priority, Level: sarif.LevelWarning,
			Component: "api", Image: ref, BuiltUpstream: true, Location: sarif.Location{URI: ref},
			Message: rule}
	}
	jquery := func(component, policy, rule, fixed, priority string, line int) sarif.Result {
		return sarif.Result{RuleID: rule, Tool: "trivy", Priority: priority, Level: sarif.LevelError,
			Component: component, UpgradePolicy: policy, Message: rule + " in jquery",
			Location: sarif.Location{URI: "web/package-lock.json", StartLine: line},
			Package: &sarif.Package{Name: "jquery", Version: "1.8.3", FixedVersion: fixed, Ecosystem: "npm",
				PURL: "pkg:npm/jquery@1.8.3"}}
	}
	return engine.Result{Controls: map[string]plugin.ControlResult{
		"images": {Report: sarif.Report{Results: []sarif.Result{
			image(python, "CVE-2025-0001", "openssl", "P1"),
			image(python, "CVE-2025-0002", "libc6", "P2"),
			image(python, "CVE-2025-0003", "zlib1g", "P2"),
			image(chainward, "CVE-2025-0004", "ca-certificates", "P3"),
		}}},
		"licenses": {Report: sarif.Report{Results: []sarif.Result{
			license(python, "license/GPL-2.0/bash", "P2"),
			license(python, "license/LGPL-2.1/libc6", "P3"),
			license(chainward, "license/MPL-2.0/ca-certificates", "P3"),
		}}},
		"sca": {Report: sarif.Report{Results: []sarif.Result{
			// One library, two components. In storefront a minor policy splits the upgrade: two
			// findings clear at 1.12.2, and two need 3.5.0, a major step past it.
			jquery("storefront", "minor", "CVE-2012-6708", "1.9.0", "P1", 12),
			jquery("storefront", "minor", "CVE-2015-9251", "1.12.2, 3.0.0", "P2", 12),
			jquery("storefront", "minor", "CVE-2020-11022", "3.5.0", "P1", 12),
			jquery("storefront", "minor", "CVE-2020-11023", "3.5.0", "P2", 12),
			jquery("api", "", "CVE-2020-11022", "3.5.0", "P1", 3),
			// The same flaw retire.js reported, counted under trivy's finding.
			{RuleID: "retire-jquery-11022", Tool: "retirejs", Priority: "P1", Component: "api",
				Location:    sarif.Location{URI: "web/package-lock.json", StartLine: 3},
				Correlation: &sarif.Correlation{CountedUnder: "trivy"}},
			// Accepted, so neither a row nor a count.
			{RuleID: "CVE-2019-0001", Tool: "trivy", Priority: "P1", Component: "api",
				Location:    sarif.Location{URI: "app/requirements.txt", StartLine: 4},
				Package:     &sarif.Package{Name: "pyyaml", Version: "5.1", FixedVersion: "5.4", Ecosystem: "pip"},
				Suppression: &sarif.Suppression{Kind: "external", Justification: "not loaded"}},
		}}},
		"secrets": {Report: sarif.Report{Results: []sarif.Result{
			{RuleID: "aws-access-token", Tool: "gitleaks", Priority: "P1", Level: sarif.LevelError,
				Component: "api", Message: "AWS access key",
				Location: sarif.Location{URI: "services/api/deploy/aws.env", StartLine: 1}},
		}}},
	}}
}

// liveFindings is how many findings a run reports as work: neither accepted nor counted under
// another scanner's.
func liveFindings(run engine.Result) int {
	n := 0
	for _, cr := range run.Controls {
		for _, res := range cr.Report.Results {
			if !res.Suppressed() && !res.Correlated() {
				n++
			}
		}
	}
	return n
}

// writeRunSARIF writes the run's results.sarif the way `draugr scan -o` does.
func writeRunSARIF(t *testing.T, run engine.Result) string {
	t.Helper()
	var buf bytes.Buffer
	if err := skald.WriteSARIFWith(&buf, run, sarif.MarshalOptions{}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "results.sarif")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// actionRow is what a reader of any of the three surfaces is told about one action.
type actionRow struct {
	ID, Title, Control, Component, Priority string
	Kind                                    skald.ActionKind
	Clears                                  int
}

// allActions is every action fix_list returned, list after list.
func allActions(out FixListOutput) []report.Action {
	var acts []report.Action
	for _, l := range out.Lists {
		acts = append(acts, l.Actions...)
	}
	return acts
}

// summarized is what summarize_report returns for a report read from disk, its next step named
// from the same report's fix list.
func summarized(rep sarif.Report, minPriority string, limit int) SummarizeOutput {
	return summarize(rep, actionsOf(rep), minPriority, limit)
}

func rowsOf(actions []report.Action) []actionRow {
	out := make([]actionRow, 0, len(actions))
	for _, a := range actions {
		out = append(out, actionRow{ID: a.ID, Title: a.Title, Control: a.Control, Component: a.Component,
			Priority: a.Priority, Kind: a.Kind, Clears: a.Clears})
	}
	return out
}

// TestFixListAgreesWithTheConsoleAndReportJSON: one scan, read three ways, is one list of things to
// do. The console prints it from the run, report.json records it from the run, and fix_list
// rebuilds it from results.sarif; a difference in any field is an assistant and a terminal giving
// the same reader two answers.
func TestFixListAgreesWithTheConsoleAndReportJSON(t *testing.T) {
	run := fixListRun()

	_, all, err := FixListTool(context.Background(), nil, FixListInput{Path: writeRunSARIF(t, run), Limit: 100})
	if err != nil {
		t.Fatal(err)
	}

	doc, err := report.Build(saga.ReportConfig{Format: "json"}, report.Data{Run: run})
	if err != nil {
		t.Fatal(err)
	}
	var recorded struct {
		Actions []report.Action `json:"actions"`
	}
	if err := json.Unmarshal(doc.Bytes, &recorded); err != nil {
		t.Fatal(err)
	}
	// report.json keeps one list in rank order, each action naming its kind; fix_list splits it by
	// kind. Each fix_list list is report.json's actions of that kind, in the same order.
	byKind := map[skald.ActionKind][]report.Action{}
	for _, a := range recorded.Actions {
		byKind[a.Kind] = append(byKind[a.Kind], a)
	}
	if len(all.Lists) != len(byKind) {
		t.Fatalf("fix_list has %d lists and report.json's actions span %d kinds", len(all.Lists), len(byKind))
	}
	for _, list := range all.Lists {
		got, want := rowsOf(list.Actions), rowsOf(byKind[list.Kind])
		if len(got) != len(want) {
			t.Fatalf("%s: fix_list has %d actions and report.json %d:\n%+v\n%+v", list.Kind, len(got), len(want), got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("%s action %d differs:\n fix_list    %+v\n report.json %+v", list.Kind, i+1, got[i], want[i])
			}
		}
	}
	if len(allActions(all)) != len(recorded.Actions) {
		t.Errorf("fix_list returns %d actions, report.json %d", len(allActions(all)), len(recorded.Actions))
	}

	// The console, cut short so each list says what it left out. Its heading counts every action,
	// and each list counts its own, which fix_list answers for the whole and for one kind.
	const shown = 1
	console, err := report.Build(saga.ReportConfig{Format: "console"},
		report.Data{Run: run, View: report.ViewActions, TopN: shown})
	if err != nil {
		t.Fatal(err)
	}
	heading := regexp.MustCompile(`WHAT TO DO\s+(\d+) actions clear (\d+) findings`).FindSubmatch(console.Bytes)
	if heading == nil {
		t.Fatalf("no actions heading in the console:\n%s", console.Bytes)
	}
	total, _ := strconv.Atoi(string(heading[1]))
	clears, _ := strconv.Atoi(string(heading[2]))
	if all.TotalActions != total || all.TotalClears != clears {
		t.Errorf("console says %d actions clear %d; fix_list says %d clear %d",
			total, clears, all.TotalActions, all.TotalClears)
	}

	lists := 0
	for _, kind := range skald.WorkOrder {
		_, one, err := FixListTool(context.Background(), nil,
			FixListInput{Path: writeRunSARIF(t, run), Limit: shown, Kind: string(kind)})
		if err != nil {
			t.Fatal(err)
		}
		line := regexp.MustCompile(regexp.QuoteMeta(kind.ListName()) +
			`\s+(\d+) actions? clears? (\d+) findings?`).FindSubmatch(console.Bytes)
		if one.TotalActions == 0 {
			if line != nil {
				t.Errorf("the console lists %q, which fix_list says is empty", kind.ListName())
			}
			continue
		}
		lists++
		if line == nil {
			t.Fatalf("no %q list in the console:\n%s", kind.ListName(), console.Bytes)
		}
		n, _ := strconv.Atoi(string(line[1]))
		m, _ := strconv.Atoi(string(line[2]))
		if one.TotalActions != n || one.TotalClears != m {
			t.Errorf("%s: console says %d actions clear %d; fix_list says %d clear %d",
				kind, n, m, one.TotalActions, one.TotalClears)
		}
		for i, a := range allActions(one) {
			if !bytes.Contains(console.Bytes, []byte(a.Title)) {
				t.Errorf("%s: fix_list's action %d, %q, is not a console row", kind, i+1, a.Title)
			}
		}
	}
	if lists < 2 {
		t.Fatalf("the fixture should span at least two kinds of work, got %d", lists)
	}
	_, top, err := FixListTool(context.Background(), nil,
		FixListInput{Path: writeRunSARIF(t, run), Limit: shown, Kind: string(skald.KindBump)})
	if err != nil {
		t.Fatal(err)
	}
	if top.Note != fmt.Sprintf("showing the %d most urgent of %d actions; raise limit to see more", shown, top.TotalActions) {
		t.Errorf("the note should say what the limit left out: %q", top.Note)
	}

	// Asked for nothing in particular, fix_list returns what the console prints by default: every
	// list, each cut to the same number of rows and counting the rest.
	byDefault, err := report.Build(saga.ReportConfig{Format: "console"}, report.Data{Run: run, View: report.ViewActions})
	if err != nil {
		t.Fatal(err)
	}
	_, lists0, err := FixListTool(context.Background(), nil, FixListInput{Path: writeRunSARIF(t, run)})
	if err != nil {
		t.Fatal(err)
	}
	cut := false
	for _, list := range lists0.Lists {
		if len(list.Actions) > report.ActionsPerList {
			t.Errorf("%s: %d actions, more than the console's %d", list.Kind, len(list.Actions), report.ActionsPerList)
		}
		if list.TotalActions > len(list.Actions) {
			cut = true
			notListed := fmt.Sprintf("… and %d action", list.TotalActions-len(list.Actions))
			if !bytes.Contains(byDefault.Bytes, []byte(notListed)) {
				t.Errorf("%s: fix_list leaves %d out, which the console does not say:\n%s",
					list.Kind, list.TotalActions-len(list.Actions), byDefault.Bytes)
			}
		}
		if list.Name != list.Kind.ListName() || !bytes.Contains(byDefault.Bytes, []byte(list.Name)) {
			t.Errorf("%s: list named %q, which the console does not print", list.Kind, list.Name)
		}
		for _, a := range list.Actions {
			if !bytes.Contains(byDefault.Bytes, []byte(a.Title)) {
				t.Errorf("%s: %q is not a row the console prints by default", list.Kind, a.Title)
			}
		}
	}
	if !cut {
		t.Fatal("the fixture should hold a list longer than the console shows")
	}
	if lists0.Note == "" || lists0.TotalActions != len(recorded.Actions) {
		t.Errorf("a cut list should be noted and the totals should count every list: note %q, %d of %d actions",
			lists0.Note, lists0.TotalActions, len(recorded.Actions))
	}
}

// TestFixListCountsEachFindingOnce: the total a reply quotes is a number of findings, so it cannot
// exceed the findings the scan reports, and the steps of a split upgrade clear disjoint findings
// rather than the second step counting the first step's again.
func TestFixListCountsEachFindingOnce(t *testing.T) {
	run := fixListRun()
	_, out, err := FixListTool(context.Background(), nil, FixListInput{Path: writeRunSARIF(t, run), Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if live := liveFindings(run); out.TotalClears != live || out.Clears != live {
		t.Errorf("every action together clears the %d live findings, each once; got clears %d, totalClears %d",
			live, out.Clears, out.TotalClears)
	}

	// Each finding in exactly one action, read from the actions that still carry them.
	seen := map[string]string{}
	for _, a := range report.ActionsFor(map[string]sarif.Report{"": skald.MergedSARIF(run)}) {
		for _, fp := range a.Fingerprints {
			if other, dup := seen[fp]; dup {
				t.Errorf("one finding is in %q and %q", other, a.Title)
			}
			seen[fp] = a.Title
		}
	}

	var steps []report.Action
	for _, a := range allActions(out) {
		if a.Package == "jquery" && a.Component == "storefront" {
			steps = append(steps, a)
		}
	}
	if len(steps) != 2 || steps[0].Clears+steps[1].Clears != 4 || steps[1].After != steps[0].ID {
		t.Errorf("storefront's jquery should be a step within its minor policy and one past it, "+
			"clearing its 4 findings between them: %+v", steps)
	}
}

// TestFixListKeepsEachControlsAction: results.sarif carries the control each finding came from, so
// an upstream image is one action per image, its licenses are a review of their own, and a
// committed credential is a credential to rotate. Without it, both images and their licenses fold
// into one action named after the component, and the key reads as code to fix.
func TestFixListKeepsEachControlsAction(t *testing.T) {
	_, out, err := FixListTool(context.Background(), nil,
		FixListInput{Path: writeRunSARIF(t, fixListRun()), Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	type row struct {
		control string
		kind    skald.ActionKind
		clears  int
	}
	want := map[string]row{
		"Update python:3.8-slim":                          {"images", skald.KindBump, 3},
		"Update chainguard/static:latest":                 {"images", skald.KindBump, 1},
		"Review the licenses in python:3.8-slim":          {"licenses", skald.KindDecide, 2},
		"Review the licenses in chainguard/static:latest": {"licenses", skald.KindDecide, 1},
		"Remove and rotate aws-access-token":              {"secrets", skald.KindCredential, 1},
		"Upgrade jquery 1.8.3":                            {"sca", skald.KindBump, 0},
		"Upgrade jquery 1.12.2":                           {"sca", skald.KindBump, 2},
	}
	got := map[string]int{}
	for _, a := range allActions(out) {
		got[a.Title]++
		w, ok := want[a.Title]
		if !ok {
			t.Errorf("unexpected action %q (%s, %s)", a.Title, a.Control, a.Kind)
			continue
		}
		if a.Control != w.control || a.Kind != w.kind || (w.clears > 0 && a.Clears != w.clears) {
			t.Errorf("%q: control %s, kind %s, clears %d; want %s, %s, %d",
				a.Title, a.Control, a.Kind, a.Clears, w.control, w.kind, w.clears)
		}
	}
	for title := range want {
		if got[title] == 0 {
			t.Errorf("no action %q", title)
		}
	}
	// Two components, two owners: api's jquery is its own action beside storefront's step.
	if got["Upgrade jquery 1.8.3"] != 2 {
		t.Errorf("jquery 1.8.3 in two components should be two actions, got %d", got["Upgrade jquery 1.8.3"])
	}
}
