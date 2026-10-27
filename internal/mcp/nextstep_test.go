package mcp

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/draugr-dev/draugr/internal/builtins"
	"github.com/draugr-dev/draugr/pkg/report"
	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/skald"
)

// stamped is a finding as results.sarif carries it, with its control, component and band.
func stamped(control, rule, priority, uri string, line int) sarif.Result {
	return sarif.Result{RuleID: rule, Tool: "scanner", Control: control, Priority: priority,
		Level: sarif.LevelError, Component: "api", Message: rule,
		Location: sarif.Location{URI: uri, StartLine: line}}
}

// withPackage is r about a dependency, fixed where fixed is not empty.
func withPackage(r sarif.Result, name, version, fixed string) sarif.Result {
	r.Package = &sarif.Package{Name: name, Version: version, FixedVersion: fixed, Ecosystem: "npm"}
	return r
}

// TestNextNamesTheFirstActionInItsOwnWords: the instruction is the action's title and target as
// fix_list states them, where it applies and how many findings it clears, so a code flaw reads as a
// change to code and a secret as a credential to rotate rather than as a dependency with no fix.
func TestNextNamesTheFirstActionInItsOwnWords(t *testing.T) {
	jquery := func(rule, repo string) sarif.Result {
		r := withPackage(stamped("sca", rule, "P1", "web/package-lock.json", 12), "jquery", "1.8.3", "3.5.0")
		r.Repository = repo
		return r
	}
	key := func(path string) sarif.Result { return stamped("secrets", "private-key", "P1", path, 1) }
	image := func(rule string) sarif.Result {
		r := withPackage(stamped("images", rule, "P1", "python:3.8-slim", 0), "openssl", "3.0.14", "3.0.22")
		r.Image, r.BuiltUpstream = "python:3.8-slim", true
		return r
	}
	operated := stamped("kubernetes", "KCV-0001", "P1", "kube-apiserver", 0)
	operated.ProviderOperated = true
	below := stamped("sast", "eval", "P4", "app/app.py", 3)

	for name, tc := range map[string]struct {
		results []sarif.Result
		min     string
		want    string
	}{
		// One dependency in two repositories of one component is one upgrade in two places.
		"bump": {results: []sarif.Result{
			jquery("CVE-2020-11022", "https://github.com/acme/shop"),
			jquery("CVE-2020-11023", "https://github.com/acme/admin"),
		}, want: `Start with "Upgrade jquery 1.8.3 → 3.5.0" in acme/admin web/package-lock.json:12 and acme/shop web/package-lock.json:12, which clears 2 findings. Then scan again to confirm they are gone.`},
		"code": {results: []sarif.Result{func() sarif.Result {
			r := stamped("sast", "B602", "P1", "app/app.py", 17)
			r.Message = "Command built from request input"
			return r
		}()}, want: `Start with "Fix “Command built from request input”" in app/app.py:17, which clears 1 finding. Then scan again to confirm it is gone.`},
		"credential": {results: []sarif.Result{key("deploy/a.pem"), key("deploy/b.pem"), key("deploy/c.pem")},
			want: `Start with "Remove and rotate private-key" in deploy/a.pem:1, deploy/b.pem:1 and 1 more, which clears 3 findings. Then scan again to confirm they are gone.`},
		"wait": {results: []sarif.Result{withPackage(stamped("sca", "CVE-2022-40303", "P1", "package-lock.json", 0), "libxml2", "2.9.10", "")},
			want: `Start with "Replace or accept libxml2 2.9.10, no fix available" in package-lock.json, which clears 1 finding. Record an acceptance with an expiry for any finding kept, then scan again.`},
		"decide": {results: []sarif.Result{stamped("licenses", "license/GPL-3.0/readline", "P1", "package-lock.json", 0)},
			want: `Start with "Replace or accept readline, licensed GPL-3.0" in package-lock.json, which clears 1 finding. Record an acceptance with an expiry for any finding kept, then scan again.`},
		// The image is the title, so the instruction does not name it twice.
		"upstream image": {results: []sarif.Result{image("CVE-2025-0001"), image("CVE-2025-0002")},
			want: `Start with "Update python:3.8-slim", which clears 2 findings. Then scan again to confirm they are gone.`},
		"external": {results: []sarif.Result{operated},
			want: "Every finding is on a surface somebody else operates. Report them to whoever operates it; nothing in this project changes them."},
		"external above a floor": {results: []sarif.Result{operated}, min: "p1",
			want: "Every finding at or above P1 is on a surface somebody else operates. Report them to whoever operates it; nothing in this project changes them."},
		"filtered": {results: []sarif.Result{below}, min: "p1",
			want: "Nothing at or above P1. Lower minPriority to see the 1 below it."},
		"clean": {want: "Nothing to fix in the controls that ran."},
	} {
		t.Run(name, func(t *testing.T) {
			if got := summarized(sarif.Report{Results: tc.results}, tc.min, 0).Next; got != tc.want {
				t.Errorf("next =\n %s\nwant\n %s", got, tc.want)
			}
		})
	}
}

// kevReport is the case two rankings disagree on: the finding summarize_report lists first is a
// critical glibc flaw with no fix, while fix_list leads with the jQuery upgrade that clears a medium
// flaw KEV raised to critical, ahead of a lodash upgrade clearing more. A command injection in the
// project's own code heads the code list. jQuery is in two repositories of one component.
func kevReport() sarif.Report {
	jquery := func(rule, repo string, kev bool) sarif.Result {
		r := withPackage(stamped("sca", rule, "P2", "web/package-lock.json", 12), "jquery", "1.8.3", "3.5.0")
		r.Component, r.Repository, r.Score, r.HasScore = "web", repo, 6.1, true
		if kev {
			r.Priority = "P1"
			r.Escalation = &sarif.Escalation{From: sarif.SeverityMedium, To: sarif.SeverityCritical,
				Signal: "kev", Detail: "on KEV", AsOf: "2026-10-20"}
		}
		return r
	}
	lodash := func(rule string) sarif.Result {
		r := withPackage(stamped("sca", rule, "P1", "web/package-lock.json", 40), "lodash", "4.17.15", "4.17.21")
		r.Component, r.Repository, r.Score, r.HasScore = "web", "https://github.com/acme/shop", 7.4, true
		return r
	}
	glibc := withPackage(stamped("images", "CVE-2019-1010022", "P1", "python:3.8-slim", 0), "libc6", "2.31-13", "")
	glibc.Score, glibc.HasScore, glibc.Image = 9.8, true, "python:3.8-slim"
	injection := stamped("sast", "B602", "P1", "app/app.py", 17)
	injection.Score, injection.HasScore, injection.Message = 7.8, true, "Command built from request input"
	return sarif.Report{Results: []sarif.Result{
		glibc,
		jquery("CVE-2020-11023", "https://github.com/acme/shop", true),
		jquery("CVE-2020-11022", "https://github.com/acme/admin", false),
		lodash("CVE-2020-8203"), lodash("CVE-2021-23337"), lodash("CVE-2020-28500"),
		injection,
	}}
}

// TestNextIsFixListsFirstAction: summarize_report's first step is the action fix_list leads with,
// read from the same results.sarif, so the server gives one answer to "what first".
func TestNextIsFixListsFirstAction(t *testing.T) {
	path := writeSARIF(t, kevReport())
	_, sum, err := SummarizeReportTool(context.Background(), nil, SummarizeInput{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	_, fix, err := FixListTool(context.Background(), nil, FixListInput{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	// The premise: summarize_report's own order leads with a finding fix_list does not.
	if len(sum.Findings) == 0 || sum.Findings[0].RuleID != "CVE-2019-1010022" {
		t.Fatalf("the fixture should put the glibc flaw first among the findings: %+v", sum.Findings)
	}
	if len(fix.Lists) < 2 || fix.Lists[0].Kind != skald.KindBump || fix.Lists[1].Kind != skald.KindCode {
		t.Fatalf("want the bump list, then the code list: %+v", fix.Lists)
	}
	first := fix.Lists[0].Actions[0]
	if first.Title != "Upgrade jquery 1.8.3" || first.Target != "3.5.0" {
		t.Fatalf("fix_list should lead with the jQuery upgrade, got %q → %q", first.Title, first.Target)
	}
	if sum.Next != startWith(first) {
		t.Errorf("next =\n %s\nwant fix_list's first action\n %s", sum.Next, startWith(first))
	}
	if !strings.Contains(sum.Next, `"Upgrade jquery 1.8.3 → 3.5.0"`) || strings.Contains(sum.Next, "CVE-2019-1010022") {
		t.Errorf("next names something other than the jQuery upgrade: %s", sum.Next)
	}
	if code := fix.Lists[1].Actions[0]; code.Kind != skald.KindCode || code.Where[0] != "app/app.py:17" {
		t.Errorf("the code list should lead with the command injection: %+v", code)
	}
}

// TestNextComparesTheHeadsOfTheListsByBand: priority means the same in every list, so a P1 credential
// is the first step ahead of a P3 upgrade, although the bump list is returned first. In one band
// the earlier list leads, as fix_list returns them.
func TestNextComparesTheHeadsOfTheListsByBand(t *testing.T) {
	bump := withPackage(stamped("sca", "CVE-2020-8203", "P3", "package-lock.json", 0), "lodash", "4.17.15", "4.17.21")
	credential := stamped("secrets", "aws-access-token", "P1", "deploy/aws.env", 1)
	code := stamped("sast", "B602", "P1", "app/app.py", 17)

	got := summarized(sarif.Report{Results: []sarif.Result{bump, credential}}, "", 0).Next
	if !strings.HasPrefix(got, `Start with "Remove and rotate aws-access-token"`) {
		t.Errorf("a P1 credential should come before a P3 upgrade: %s", got)
	}
	bump.Priority = "P1"
	got = summarized(sarif.Report{Results: []sarif.Result{code, bump, credential}}, "", 0).Next
	if !strings.HasPrefix(got, `Start with "Upgrade lodash 4.17.15 → 4.17.21"`) {
		t.Errorf("in one band the bump list, returned first, should lead: %s", got)
	}
}

// TestNextRespectsMinPriority: the first step is the first action at or above the floor. Of an
// upgrade split by the component's policy, the step within it clears only a P2 here, so above P1
// the step past it is the first.
func TestNextRespectsMinPriority(t *testing.T) {
	step := func(rule, priority, fixed string) sarif.Result {
		r := withPackage(stamped("sca", rule, priority, "package-lock.json", 0), "jquery", "1.8.3", fixed)
		r.UpgradePolicy = "minor"
		return r
	}
	rep := sarif.Report{Results: []sarif.Result{step("CVE-2015-9251", "P2", "1.12.2"), step("CVE-2020-11023", "P1", "3.5.0")}}
	if got := summarized(rep, "", 0).Next; !strings.HasPrefix(got, `Start with "Upgrade jquery 1.8.3 → 1.12.2"`) {
		t.Errorf("without a floor, the step within the policy comes first: %s", got)
	}
	if got := summarized(rep, "p1", 0).Next; !strings.HasPrefix(got, `Start with "Upgrade jquery 1.12.2 → 3.5.0"`) {
		t.Errorf("above P1, the step that clears the P1 comes first: %s", got)
	}
}

// TestNextLeavesAcceptedRiskOut: a suppressed finding is a decision somebody recorded, so it cannot
// be the first step however urgent it was ranked.
func TestNextLeavesAcceptedRiskOut(t *testing.T) {
	rep := kevReport()
	for i := range rep.Results {
		if rep.Results[i].Package != nil && rep.Results[i].Package.Name == "jquery" {
			rep.Results[i].Suppression = &sarif.Suppression{Kind: "external", Justification: "not loaded"}
		}
	}
	got := summarized(rep, "", 0).Next
	if strings.Contains(got, "jquery") || !strings.HasPrefix(got, `Start with "Upgrade lodash 4.17.15 → 4.17.21"`) {
		t.Errorf("with jQuery accepted, the lodash upgrade is first: %s", got)
	}
}

// TestScanNextIsFixListsFirstAction: the scan tool names its first step from the same ranking. The
// scan imports a dependency report and reads KEV from a file, so the escalation is the run's own,
// and fix_list over the results.sarif the scan delivered leads with the action next names.
func TestScanNextIsFixListsFirstAction(t *testing.T) {
	dir := t.TempDir()
	deps := sarif.Report{Tool: "deps", Results: []sarif.Result{
		withPackage(sarif.Result{RuleID: "CVE-2020-11023", Level: sarif.LevelWarning, Score: 6.1, HasScore: true,
			Message: "jQuery passes untrusted HTML to its DOM methods", Location: sarif.Location{URI: "web/package-lock.json"}},
			"jquery", "1.8.3", "3.5.0"),
		withPackage(sarif.Result{RuleID: "CVE-2020-8203", Level: sarif.LevelError, Score: 7.4, HasScore: true,
			Message: "Prototype pollution in zipObjectDeep", Location: sarif.Location{URI: "web/package-lock.json"}},
			"lodash", "4.17.15", "4.17.21"),
		withPackage(sarif.Result{RuleID: "CVE-2021-23337", Level: sarif.LevelError, Score: 7.2, HasScore: true,
			Message: "Command injection in template", Location: sarif.Location{URI: "web/package-lock.json"}},
			"lodash", "4.17.15", "4.17.21"),
	}}
	data, err := deps.MarshalSARIF()
	if err != nil {
		t.Fatal(err)
	}
	imported, kev, out := filepath.Join(dir, "deps.sarif"), filepath.Join(dir, "kev.json"), filepath.Join(dir, "out")
	if err := os.WriteFile(imported, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kev, []byte(`{"vulnerabilities":[{"cveID":"CVE-2020-11023"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "shop.saga.yaml")
	if err := os.WriteFile(path, []byte("project: shop\n"+
		"config:\n  exploitability:\n    kev: "+kev+"\n"+
		"  publishers:\n    - kind: file\n      dir: "+out+"\n      reports:\n        - format: sarif\n"+
		"components:\n  - name: web\n    exposure: public\n    criticality: critical\n"+
		"    imports:\n      - control: sca\n        file: "+imported+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, scan, err := scanTool(builtins.Registry(), ScanAlways)(context.Background(), nil, ScanInput{Path: path})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	_, fix, err := FixListTool(context.Background(), nil, FixListInput{Path: filepath.Join(out, "results.sarif")})
	if err != nil {
		t.Fatal(err)
	}
	if len(fix.Lists) == 0 {
		t.Fatal("fix_list returned no lists")
	}
	first := fix.Lists[0].Actions[0]
	if first.Title != "Upgrade jquery 1.8.3" || first.Exploitation == nil || first.Exploitation.Signal != "kev" {
		t.Fatalf("the KEV upgrade should lead, ahead of the larger lodash one: %+v", first)
	}
	if scan.Next != startWith(first) {
		t.Errorf("scan's next =\n %s\nwant fix_list's first action\n %s", scan.Next, startWith(first))
	}
}

// TestFixListsFirstActionAgreesWithTheReportsOrder holds firstAction to the lists: with no floor
// and every head in one band, it is the head of the first list.
func TestFixListsFirstActionAgreesWithTheReportsOrder(t *testing.T) {
	actions := actionsOf(kevReport())
	got, ok := firstAction(actions, "")
	lists := report.ListsOf(actions)
	if !ok || len(lists) == 0 || got.ID != lists[0].Actions[0].ID {
		t.Errorf("first action %q, want the head of the first list", got.Title)
	}
	if _, ok := firstAction(nil, ""); ok {
		t.Error("no actions, no first action")
	}
}

// TestFixListAnswersOverASession: the lists and each action's reason reach a client through the
// schema the SDK derives from the output type, which a call to the handler alone does not check.
func TestFixListAnswersOverASession(t *testing.T) {
	ctx := context.Background()
	sess := connect(t, Options{Registry: builtins.Registry(), Root: t.TempDir()})
	res, err := sess.CallTool(ctx, &mcp.CallToolParams{
		Name: "fix_list", Arguments: map[string]any{"path": writeSARIF(t, kevReport())},
	})
	if err != nil {
		t.Fatalf("fix_list: %v", err)
	}
	if res.IsError {
		t.Fatalf("fix_list errored: %+v", res.Content)
	}
	var out FixListOutput
	decode(t, res, &out)
	if len(out.Lists) < 2 || out.Lists[0].Actions[0].Exploitation == nil || out.Lists[0].Actions[0].Severity != sarif.SeverityCritical {
		t.Errorf("want the lists, the first action with its KEV reason: %+v", out.Lists)
	}
}

// TestTheLimitHintStatesTheDefaults: the hint names the numbers a model is told to expect, so it is
// held to the constants the tool applies.
func TestTheLimitHintStatesTheDefaults(t *testing.T) {
	field, _ := reflect.TypeFor[FixListInput]().FieldByName("Limit")
	hint := field.Tag.Get("jsonschema")
	for _, n := range []int{report.ActionsPerList, defaultLimit} {
		if !strings.Contains(hint, strconv.Itoa(n)) {
			t.Errorf("the limit hint does not name the default %d: %q", n, hint)
		}
	}
}
