package publish

import (
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/draugr-dev/draugr/pkg/ci"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/report"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/skald"
)

const zw = "\u200b"

func codeFinding(component, rule, priority, file string) sarif.Result {
	return sarif.Result{
		Tool: "semgrep", RuleID: rule, Level: sarif.LevelError, Message: "flaw in " + file,
		Component: component, Priority: priority, Location: sarif.Location{URI: file, StartLine: 3},
	}
}

func upgradeFinding(component, advisory, priority string) sarif.Result {
	r := codeFinding(component, advisory, priority, "go.mod")
	r.Tool = "trivy"
	r.Message = "openssl 1.1.1: " + advisory
	r.Package = &sarif.Package{Name: "openssl", Version: "1.1.1", FixedVersion: "1.1.1w", Ecosystem: "gomod"}
	return r
}

func acceptedFinding(r sarif.Result) sarif.Result {
	r.Suppression = &sarif.Suppression{Kind: "external", Justification: "reviewed"}
	return r
}

// runOver is a run of the demo project, whose api component belongs to payments and web to the web
// team.
func runOver(controls map[string][]sarif.Result) report.Data {
	d := report.Data{
		Project: "demo",
		Run:     engine.Result{Controls: map[string]plugin.ControlResult{}},
		Labels: map[string]map[string]string{
			"api": {"team": "payments"},
			"web": {"team": "web"},
		},
	}
	for c, rs := range controls {
		d.Run.Controls[c] = plugin.ControlResult{Control: c, Report: sarif.Report{Results: rs}}
	}
	return d
}

func onlyPart(t *testing.T, data report.Data, entry issueEntry) issuePart {
	t.Helper()
	parts := issueParts(data, entry)
	if len(parts) != 1 {
		t.Fatalf("parts = %d, want 1", len(parts))
	}
	return parts[0]
}

func renderMarkdown(data report.Data, entry issueEntry) string {
	part := issueParts(data, entry)[0]
	return newIssueBody(data, scopeKey(data.Requested), entry, part).render(markdownFormat{}, 60_000)
}

func TestTheScopeKeyIsTheRequestInAStableOrder(t *testing.T) {
	cases := []struct {
		scope engine.Scope
		want  string
	}{
		{engine.Scope{}, "all"},
		{engine.Scope{Controls: []string{"secrets", "sca"}}, "controls=sca,secrets"},
		{engine.Scope{Labels: []string{"team=payments"}, Controls: []string{"sca"}}, "controls=sca;labels=team=payments"},
		{
			engine.Scope{
				Exposure: []saga.Exposure{"public"}, Criticality: []saga.Criticality{"critical"},
				Components: []string{"web", "api"},
			},
			"components=api,web;criticality=critical;exposure=public",
		},
	}
	for _, c := range cases {
		if got := scopeKey(c.scope); got != c.want {
			t.Errorf("scopeKey(%+v) = %q, want %q", c.scope, got, c.want)
		}
	}
}

func TestRelabelingAComponentLeavesTheKeysUnchanged(t *testing.T) {
	entry := issueEntry{Select: issueSelection{Labels: map[string]string{"team": "payments"}, Controls: []string{"sca"}}}
	requested := engine.Scope{Labels: []string{"team=payments"}}

	before := runOver(map[string][]sarif.Result{"sca": {codeFinding("api", "r", "P1", "a.go")}})
	after := before
	after.Labels = map[string]map[string]string{"api": {"team": "web"}, "web": {"team": "payments"}}

	for _, d := range []report.Data{before, after} {
		part := issueParts(d, entry)[0]
		got := issueMarker(d.Project, scopeKey(requested), entry, part)
		want := "<!-- draugr:issue v1 project=demo scope=labels=team=payments select=controls=sca;labels=team=payments -->"
		if got != want {
			t.Errorf("marker = %q, want %q", got, want)
		}
	}
}

func TestAMarkerValueCannotEndTheComment(t *testing.T) {
	entry := issueEntry{Split: splitComponent}
	got := issueMarker("demo --> <b>", "all", entry, issuePart{Split: splitComponent, Value: "a---b c"})
	inner := strings.TrimSuffix(strings.TrimPrefix(got, "<!-- "), " -->")
	if strings.Contains(inner, "--") || strings.Contains(inner, ">") {
		t.Errorf("marker %q holds a value that could end it", got)
	}
	if !strings.Contains(got, "project=demo%20-%2D%3E%20%3Cb%3E") || !strings.Contains(got, "component=a-%2D-b%20c") {
		t.Errorf("marker = %q", got)
	}
}

func TestTheTitleNamesWhatTellsTheItemApartFirst(t *testing.T) {
	pii := issueEntry{Select: issueSelection{Labels: map[string]string{"data-class": "pii"}}, Split: splitControl}
	platform := issueEntry{Select: issueSelection{Labels: map[string]string{"team": "platform"}}}
	for _, c := range []struct {
		name  string
		scope engine.Scope
		entry issueEntry
		part  issuePart
		want  string
	}{
		{"the whole run", engine.Scope{}, issueEntry{}, issuePart{}, "draugr-demo fails the Draugr gate"},
		{"a selection", engine.Scope{}, platform, issuePart{},
			"team=platform fails the Draugr gate · draugr-demo"},
		{"a split part, named bare", engine.Scope{}, pii, issuePart{Split: splitControl, Value: "sca"},
			"sca fails the Draugr gate · data-class=pii · draugr-demo"},
		{"a narrowed run", engine.Scope{Controls: []string{"sca"}}, issueEntry{}, issuePart{},
			"control sca fails the Draugr gate · draugr-demo"},
		{"alternatives and selectors", engine.Scope{
			Controls: []string{"sast", "sca"}, Labels: []string{"tier=1", "team=web"},
			Exposure: []saga.Exposure{saga.ExposurePublic}, Criticality: []saga.Criticality{saga.CriticalityCritical},
		}, issueEntry{}, issuePart{},
			"team=web, tier=1, control sast or sca, exposure public, criticality critical fails the Draugr gate · draugr-demo"},
		{"every source at once", engine.Scope{Components: []string{"web", "api"}},
			issueEntry{Select: issueSelection{Components: []string{"api"}}, Split: splitControl},
			issuePart{Split: splitControl, Value: "iac"},
			"iac fails the Draugr gate · component api · component api or web · draugr-demo"},
	} {
		if got := issueTitle("draugr-demo", c.scope, c.entry, c.part); got != c.want {
			t.Errorf("%s: title = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestATitleActsOnNothingAndFitsGitHub(t *testing.T) {
	if got := issueTitle("@demo", engine.Scope{}, issueEntry{}, issuePart{}); got != "@"+zw+"demo fails the Draugr gate" {
		t.Errorf("title = %q", got)
	}
	long := issueTitle(strings.Repeat("a", 300), engine.Scope{}, issueEntry{}, issuePart{})
	if n := len([]rune(long)); n != maxTitle || !strings.HasSuffix(long, "…") {
		t.Errorf("a long title is %d characters, ending %q", n, long[len(long)-8:])
	}
}

func TestScannerTextActsOnNothing(t *testing.T) {
	got := mdText("@user fixed #12 :tada: in %1 with *emphasis* see GH-7 and www.example.com")
	for _, want := range []string{
		"@" + zw + "user", "#" + zw + "12", ":" + zw + "tada:" + zw, "%" + zw + "1", `\*emphasis\*`,
		"GH-" + zw + "7", "w" + zw + "ww.example.com",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("mdText = %q, missing %q", got, want)
		}
	}
	if got := mdText("/close\n  now"); got != `\/close now` {
		t.Errorf("mdText(/close) = %q", got)
	}
	if got := mdText("a|b ~c"); got != `a\|b \~`+zw+"c" {
		t.Errorf("mdText(pipe, tilde) = %q", got)
	}
	if got := htmlText("<b>@x</b> & ~y"); got != "&lt;b&gt;@"+zw+"x&lt;/b&gt; &amp;"+zw+" ~"+zw+"y" {
		t.Errorf("htmlText = %q", got)
	}
}

func TestACodeSpanFenceIsLongerThanAnyRunInside(t *testing.T) {
	cases := map[string]string{
		"CVE-1":    "`CVE-1`",
		"a``b":     "```a``b```",
		"`x":       "`` `x ``",
		"a|b":      "`a|b`",
		"a\n b  c": "`a b c`",
	}
	for in, want := range cases {
		if got := mdCode(in, false); got != want {
			t.Errorf("mdCode(%q) = %q, want %q", in, got, want)
		}
	}
	if got := mdCode("a|b", true); got != "`a\\|b`" {
		t.Errorf("mdCode in a table = %q", got)
	}
}

func TestOnlyAWebAddressIsLinked(t *testing.T) {
	cases := map[string]string{
		"https://avd.aquasec.com/nvd/cve-1": "https://avd.aquasec.com/nvd/cve-1",
		"https://x.test/a_(b)":              "https://x.test/a_%28b%29",
		"javascript:alert(1)":               "",
		"ftp://x.test/":                     "",
		"https:///nohost":                   "",
		"not a url":                         "",
	}
	for in, want := range cases {
		if got := safeURL(in); got != want {
			t.Errorf("safeURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNoBodyLineStartsWithScannerText(t *testing.T) {
	hostile := codeFinding("/api", "/rule", "P1", "/etc/passwd")
	hostile.Message = "/close\n/label ~bug"
	data := runOver(map[string][]sarif.Result{"sast": {hostile}})
	data.Run.Controls["sast"] = plugin.ControlResult{Control: "sast", Report: sarif.Report{
		Results: []sarif.Result{hostile},
		Rules:   map[string]sarif.Rule{"/rule": {ShortDescription: "/assign @me"}},
	}}
	data.Incomplete = true
	data.Run.ScanErrors = map[string][]string{"sast": {"/unlabel ~x"}}

	part := issueParts(data, issueEntry{})[0]
	body := newIssueBody(data, "all", issueEntry{}, part).render(markdownFormat{}, 60_000)
	for _, line := range strings.Split(body, "\n") {
		if line != "" && !strings.ContainsRune("<|*`#-AFCN", rune(line[0])) {
			t.Errorf("line starts with text Draugr did not write: %q", line)
		}
	}
}

func TestAnUpgradeListsTenFindingsAndTheRest(t *testing.T) {
	var findings []sarif.Result
	for i := range 12 {
		findings = append(findings, upgradeFinding("api", fmt.Sprintf("CVE-2026-%04d", i), "P1"))
	}
	body := renderMarkdown(runOver(map[string][]sarif.Result{"sca": findings}), issueEntry{})

	if n := strings.Count(body, "| P1 "); n != oneChangeRows {
		t.Errorf("rows = %d, want %d\n%s", n, oneChangeRows, body)
	}
	for _, want := range []string{
		"<details><summary><b>P1</b> Upgrade openssl 1.1.1 · <code>sca</code> · 12 findings</summary>",
		"And 2 more, cleared by the same action.",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body lacks %q\n%s", want, body)
		}
	}
}

func TestARuleActionListsEveryFinding(t *testing.T) {
	var findings []sarif.Result
	for i := range 12 {
		findings = append(findings, codeFinding("web", "sql-injection", "P1", fmt.Sprintf("h%02d.go", i)))
	}
	body := renderMarkdown(runOver(map[string][]sarif.Result{"sast": findings}), issueEntry{})
	if n := strings.Count(body, "| P1 "); n != 12 {
		t.Errorf("rows = %d, want 12\n%s", n, body)
	}
	if strings.Contains(body, "more, cleared") {
		t.Errorf("a rule action summarized its findings\n%s", body)
	}
}

func TestAFindingRowNamesTheRuleMessageAndPlace(t *testing.T) {
	f := upgradeFinding("api", "CVE-2019-1010022", "P1")
	f.Score, f.HasScore = 9.8, true
	data := runOver(nil)
	data.Run.Controls["sca"] = plugin.ControlResult{Control: "sca", Report: sarif.Report{
		Results: []sarif.Result{f},
		Rules:   map[string]sarif.Rule{"CVE-2019-1010022": {HelpURI: "https://avd.aquasec.com/nvd/cve-2019-1010022"}},
	}}
	body := renderMarkdown(data, issueEntry{})
	want := "| P1 critical | [`CVE-2019-1010022`](https://avd.aquasec.com/nvd/cve-2019-1010022)<br>openssl 1.1.1" +
		`:` + zw + " CVE-2019-1010022 | `api` · trivy<br>`go.mod:3` |"
	if !strings.Contains(body, want) {
		t.Errorf("body lacks row\n%s\nwant %s", body, want)
	}
}

func TestTheVerdictLineCountsWhatThePartCovers(t *testing.T) {
	data := runOver(map[string][]sarif.Result{
		"licenses": {codeFinding("api", "gpl", "P2", "a"), codeFinding("web", "gpl", "P2", "b")},
		"sca":      {codeFinding("api", "c1", "P1", "go.mod"), acceptedFinding(codeFinding("api", "c2", "P1", "go.mod"))},
		"secrets":  {codeFinding("web", "key", "P1", "k"), codeFinding("web", "key2", "P1", "k2"), codeFinding("web", "key3", "P3", "k3")},
	})
	data.Gate = report.GateSettings{PerControlBand: map[string]string{"licenses": "P2", "secrets": "P1"}}
	data.Incomplete = true

	body := renderMarkdown(data, issueEntry{})
	for _, want := range []string{
		"**5 findings fail the gate** · gate P1, P2 for `licenses` · 1 accepted · incomplete",
		"`licenses` 2 · `secrets` 2 · `sca` 1",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body lacks %q\n%s", want, body)
		}
	}

	narrowed := renderMarkdown(data, issueEntry{Select: issueSelection{Controls: []string{"sca"}}})
	if !strings.Contains(narrowed, "**1 finding fails the gate** · gate P1 · 1 accepted · incomplete") {
		t.Errorf("a part without licenses shows its override\n%s", narrowed)
	}

	data.Gate = report.GateSettings{Threshold: sarif.SeverityHigh, PerControl: map[string]sarif.Severity{"sca": sarif.SeverityCritical}}
	data.Incomplete = false
	if got := renderMarkdown(data, issueEntry{}); !strings.Contains(got, "gate high, critical for `sca`") {
		t.Errorf("severity gate not named\n%s", got)
	}
}

func TestASelectedPartPassesWhileTheRunFails(t *testing.T) {
	data := runOver(map[string][]sarif.Result{
		"sca": {codeFinding("web", "c1", "P1", "go.mod"), codeFinding("api", "c2", "P3", "go.mod")},
	})
	payments := issueEntry{Select: issueSelection{Labels: map[string]string{"team": "payments"}}}
	web := issueEntry{Select: issueSelection{Components: []string{"web", "gateway"}}}

	if p := onlyPart(t, data, payments); p.Fails || p.failingTotal() != 0 {
		t.Errorf("payments part = %+v, want passing", p)
	}
	if p := onlyPart(t, data, web); !p.Fails || p.failingTotal() != 1 {
		t.Errorf("web part = %+v, want failing on one finding", p)
	}
}

func TestAFindingThatNamesNoComponentCountsForEverySelection(t *testing.T) {
	data := runOver(map[string][]sarif.Result{"infrastructure": {codeFinding("", "open-port", "P1", "")}})
	for _, team := range []string{"payments", "web"} {
		entry := issueEntry{Select: issueSelection{Labels: map[string]string{"team": team}}}
		if p := onlyPart(t, data, entry); !p.Fails {
			t.Errorf("%s part passes on a finding with no component", team)
		}
	}
}

func TestASplitByControlHasAPartForEachCoveredControl(t *testing.T) {
	data := runOver(map[string][]sarif.Result{
		"sca":      {codeFinding("api", "c1", "P1", "go.mod")},
		"secrets":  nil,
		"licenses": {codeFinding("api", "gpl", "P1", "x")},
	})
	entry := issueEntry{Select: issueSelection{Controls: []string{"sca", "secrets"}}, Split: splitControl}
	parts := issueParts(data, entry)
	if len(parts) != 2 || parts[0].Value != "sca" || parts[1].Value != "secrets" {
		t.Fatalf("parts = %+v", parts)
	}
	if !parts[0].Fails || parts[1].Fails {
		t.Errorf("sca fails = %v, secrets fails = %v", parts[0].Fails, parts[1].Fails)
	}
	if got := issueMarker("demo", "all", entry, parts[0]); !strings.HasSuffix(got, "select=controls=sca,secrets control=sca -->") {
		t.Errorf("marker = %q", got)
	}
}

func TestASplitByControlBodyCountsNoControlAgain(t *testing.T) {
	data := runOver(map[string][]sarif.Result{
		"sca":  {codeFinding("api", "c1", "P1", "go.mod"), codeFinding("web", "c2", "P1", "go.mod")},
		"sast": {codeFinding("web", "r1", "P1", "a.go")},
	})
	split := issueEntry{Split: splitControl}
	body := newIssueBody(data, "all", split, issueParts(data, split)[1]).render(markdownFormat{}, 60_000)
	if strings.Contains(body, "`sca` 2") {
		t.Errorf("a body split by control counts its control again\n%s", body)
	}

	whole := newIssueBody(data, "all", issueEntry{}, onlyPart(t, data, issueEntry{})).render(markdownFormat{}, 60_000)
	if !strings.Contains(whole, "`sca` 2 · `sast` 1") {
		t.Errorf("a body covering several controls lacks the count of each\n%s", whole)
	}
}

func TestASplitByComponentCoversEveryDeclaredComponent(t *testing.T) {
	data := runOver(map[string][]sarif.Result{
		"sca":   {codeFinding("api", "c1", "P1", "go.mod"), codeFinding("worker", "c2", "P1", "go.mod")},
		"iac":   {codeFinding("web", "d1", "P4", "Dockerfile")},
		"infra": {codeFinding("", "open-port", "P3", "")},
	})
	parts := issueParts(data, issueEntry{Split: splitComponent})
	var got []string
	for _, p := range parts {
		got = append(got, fmt.Sprintf("%s:%v", p.Value, p.Fails))
	}
	if strings.Join(got, " ") != "api:true web:false worker:true" {
		t.Errorf("parts = %v", got)
	}
	if _, ok := parts[1].Reports["infra"]; !ok {
		t.Errorf("the web part lacks the finding that names no component")
	}
}

func TestMinPriorityOpensOnlyAtOrAboveItsBand(t *testing.T) {
	data := runOver(map[string][]sarif.Result{
		"sca":  {codeFinding("api", "c1", "P2", "go.mod")},
		"sast": {codeFinding("web", "r1", "P2", "a.go")},
	})
	data.Gate = report.GateSettings{FailOnPriority: "P2"}
	entry := issueEntry{MinPriority: "P1"}

	p := onlyPart(t, data, entry)
	if p.Fails || !p.BelowMinimum {
		t.Errorf("part = %+v, want passing below the minimum", p)
	}

	data.Run.Controls["sca"] = plugin.ControlResult{Control: "sca", Report: sarif.Report{
		Results: []sarif.Result{upgradeFinding("api", "c1", "P1")},
	}}
	p = onlyPart(t, data, entry)
	if !p.Fails || p.BelowMinimum {
		t.Errorf("part = %+v, want failing", p)
	}
	body := newIssueBody(data, "all", entry, p).render(markdownFormat{}, 60_000)
	if strings.Contains(body, "<b>P2</b>") || !strings.Contains(body, "<b>P1</b>") {
		t.Errorf("body lists an action below minPriority\n%s", body)
	}
	for _, want := range []string{"**2 findings fail the gate**", "or no finding at or above P1 fails it."} {
		if !strings.Contains(body, want) {
			t.Errorf("body lacks %q\n%s", want, body)
		}
	}
}

func TestErrorsCountOnlyWhenTheScanIsIncomplete(t *testing.T) {
	data := runOver(map[string][]sarif.Result{"sca": nil, "sast": nil})
	data.Run.ScanErrors = map[string][]string{"sca": {"trivy: not found"}, "sast": {"semgrep: exit 2"}}

	if p := onlyPart(t, data, issueEntry{}); p.Fails || len(p.Errors) != 0 {
		t.Errorf("complete run: part = %+v, want no errors", p)
	}

	data.Incomplete = true
	entry := issueEntry{Select: issueSelection{Controls: []string{"sca"}}}
	p := onlyPart(t, data, entry)
	if !p.Fails || len(p.Errors) != 1 {
		t.Fatalf("incomplete run: part = %+v, want failing on the sca error", p)
	}
	body := newIssueBody(data, "all", entry, p).render(markdownFormat{}, 60_000)
	for _, want := range []string{"**No finding fails the gate** · gate P1 · incomplete", "### Errors\n\n- `sca`: trivy:" + zw + " not found"} {
		if !strings.Contains(body, want) {
			t.Errorf("body lacks %q\n%s", want, body)
		}
	}
	if strings.Contains(body, "### Actions") || strings.Contains(body, "semgrep") {
		t.Errorf("body holds what the part does not cover\n%s", body)
	}
}

func TestTheRunTableNamesEachRepositoryWhenThereAreSeveral(t *testing.T) {
	data := runOver(map[string][]sarif.Result{"sca": {codeFinding("api", "c1", "P1", "go.mod")}})
	data.CI = &ci.Context{RunID: "36435749004", URL: "https://github.com/acme/demo/actions/runs/36435749004"}
	data.Descriptor = &skald.DescriptorRef{Digest: "sha256:721eb9e476cb00000000"}
	data.Version = "v0.139.0"
	data.Repositories = []report.RepositoryProvenance{{URL: "https://github.com/acme/api.git", Revision: "a1034201ffff"}}

	one := renderMarkdown(data, issueEntry{})
	want := "| Job | Commit | Descriptor | Draugr |\n|---|---|---|---|\n" +
		"| [36435749004](https://github.com/acme/demo/actions/runs/36435749004) | `a103420` | `sha256:721eb9e476cb` | `v0.139.0` |"
	if !strings.Contains(one, want) {
		t.Errorf("body lacks run table\n%s", one)
	}

	data.Repositories = append(data.Repositories, report.RepositoryProvenance{URL: "https://github.com/acme/web", Revision: "b20f"})
	if two := renderMarkdown(data, issueEntry{}); !strings.Contains(two, "| `a103420` acme/api<br>`b20f` acme/web |") {
		t.Errorf("body lacks both commits\n%s", two)
	}

	data.CI, data.Descriptor, data.Version, data.Repositories = nil, nil, "", nil
	if bare := renderMarkdown(data, issueEntry{}); strings.Contains(bare, "### Run") {
		t.Errorf("a run with nothing recorded has a Run section\n%s", bare)
	}
}

func TestTheClosingLineNamesTheBranches(t *testing.T) {
	data := runOver(map[string][]sarif.Result{"sca": {codeFinding("api", "c1", "P1", "go.mod")}})
	cases := map[string][]string{
		"Closes itself when the gate passes on the default branch.":            nil,
		"Closes itself when the gate passes on `main`.":                        {"main"},
		"Closes itself when the gate passes on `main`, `next` or `release/*`.": {"main", "next", "release/*"},
	}
	for want, branches := range cases {
		if got := renderMarkdown(data, issueEntry{ClosesOn: branches}); !strings.HasSuffix(got, "---\n\n"+want) {
			t.Errorf("body does not end with %q\n%s", want, got)
		}
	}
}

func TestTheBodyEndsWithHowToAccept(t *testing.T) {
	data := runOver(map[string][]sarif.Result{"sca": {codeFinding("api", "c1", "P1", "go.mod")}})
	want := "### Accept\n\nA [`config.exclude`](https://draugr.dev/docs/latest/reference/saga-schema/#configexclude) " +
		"entry in the descriptor accepts a finding. It stays in the report, marked accepted."
	if got := renderMarkdown(data, issueEntry{}); !strings.Contains(got, want) {
		t.Errorf("body lacks the Accept section\n%s", got)
	}
}

// manyActions is a run with one rule action per priority band, each with several findings.
func manyActions() report.Data {
	var findings []sarif.Result
	for i, band := range []string{"P1", "P2", "P3", "P4"} {
		for j := range 5 {
			findings = append(findings, codeFinding("api", "rule-"+band, band, fmt.Sprintf("f%d%d.go", i, j)))
		}
	}
	d := runOver(map[string][]sarif.Result{"sast": findings})
	d.CI = &ci.Context{RunID: "7", URL: "https://ci.test/runs/7"}
	return d
}

func TestAnOversizedBodyDropsTheLowestPriorityTablesFirst(t *testing.T) {
	data := manyActions()
	body := newIssueBody(data, "all", issueEntry{}, issueParts(data, issueEntry{})[0])
	full := body.render(markdownFormat{}, 1_000_000)

	budget := utf8.RuneCountInString(full) - 1
	got := body.render(markdownFormat{}, budget)
	if n := utf8.RuneCountInString(got); n > budget {
		t.Fatalf("body is %d characters, budget %d", n, budget)
	}
	for _, want := range []string{
		"<details><summary><b>P1</b>", "<details><summary><b>P3</b>",
		"- <b>P4</b> Fix rule-P4",
		"Findings of the last action are left out for size, and listed in [job 7](https://ci.test/runs/7).",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("body lacks %q\n%s", want, got)
		}
	}
	if strings.Contains(got, "f30.go") {
		t.Errorf("the lowest-priority action kept its table\n%s", got)
	}
}

func TestABodyOverBudgetWithoutTablesLeavesOutTheLastActions(t *testing.T) {
	data := manyActions()
	body := newIssueBody(data, "all", issueEntry{}, issueParts(data, issueEntry{})[0])
	// The budget one short of the body in which every action is a summary line and none has a table.
	withoutActions := issueBody{Marker: body.Marker, Gate: body.Gate, Failing: body.Failing, Controls: body.Controls, Run: body.Run}
	allSummaries := body.render(markdownFormat{}, utf8.RuneCountInString(withoutActions.render(markdownFormat{}, 1_000_000))+400)
	if strings.Contains(allSummaries, "<details>") || strings.Contains(allSummaries, "left out for size, listed") {
		t.Fatalf("fixture budget does not give a body of summary lines\n%s", allSummaries)
	}
	budget := utf8.RuneCountInString(allSummaries) - 1

	got := body.render(markdownFormat{}, budget)
	if n := utf8.RuneCountInString(got); n > budget {
		t.Fatalf("body is %d characters, budget %d\n%s", n, budget, got)
	}
	if !strings.Contains(got, "- <b>P1</b>") || strings.Contains(got, "<b>P4</b>") {
		t.Errorf("wrong actions kept\n%s", got)
	}
	if !strings.Contains(got, "more actions, left out for size, listed in [job 7](https://ci.test/runs/7).") &&
		!strings.Contains(got, "more action, left out for size, listed in [job 7](https://ci.test/runs/7).") {
		t.Errorf("body does not say actions were left out\n%s", got)
	}
}

func TestAnUnchangedFindingSetIsAnUnchangedBody(t *testing.T) {
	data := runOver(map[string][]sarif.Result{"sca": {codeFinding("api", "c1", "P1", "go.mod")}})
	f := markdownFormat{}
	render := func(d report.Data) string {
		return newIssueBody(d, "all", issueEntry{}, issueParts(d, issueEntry{})[0]).render(f, 900_000)
	}
	data.CI = &ci.Context{RunID: "1", URL: "https://ci.test/1"}
	first := render(data)
	data.CI = &ci.Context{RunID: "2", URL: "https://ci.test/2"}
	second := render(data)
	if first == second || bodyChanged(f, first, strings.ReplaceAll(second, "\n", "\r\n")) {
		t.Error("a new run with the same findings changed the body")
	}
	changed := runOver(map[string][]sarif.Result{"sca": {codeFinding("api", "c9", "P1", "go.mod")}})
	changed.CI = data.CI
	if !bodyChanged(f, second, render(changed)) {
		t.Error("a different finding left the body unchanged")
	}
}

func TestARunWithoutALinkIsNamedNotLinked(t *testing.T) {
	data := manyActions()
	body := newIssueBody(data, "all", issueEntry{}, issueParts(data, issueEntry{})[0])

	body.Run = issueRun{JobID: "7", JobURL: "javascript:alert(1)"}
	if got := body.render(markdownFormat{}, 1_000_000); !strings.Contains(got, "| Job |\n|---|\n| 7 |") {
		t.Errorf("an unsafe job URL was linked\n%s", got)
	}
	body.Run = issueRun{JobURL: "https://ci.test/runs/7"}
	if got := body.render(markdownFormat{}, 1_000_000); !strings.Contains(got, "| [job](https://ci.test/runs/7) |") {
		t.Errorf("a job with no id lacks its link\n%s", got)
	}
	if got := body.render(markdownFormat{}, 1500); !strings.Contains(got, "listed in [the job](https://ci.test/runs/7).") {
		t.Errorf("a job with no id is not named where actions are left out\n%s", got)
	}
	body.Run = issueRun{}
	if got := body.render(markdownFormat{}, 1500); !strings.Contains(got, "listed in the scan report.") {
		t.Errorf("a body with no job does not point at the report\n%s", got)
	}
}
