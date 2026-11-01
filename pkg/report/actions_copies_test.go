package report

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// gjson is CVE-2020-36067 in github.com/tidwall/gjson v1.6.5 as one scanner reports it in one Go
// module, marked as correlation marks it. countedUnder is empty on the finding that is counted, and
// on a copy names the scanner it is counted under.
func gjson(tool, component, repository, manifest string, line int, countedUnder string) sarif.Result {
	rule, ecosystem := "CVE-2020-36067", "gomod"
	if tool == "grype" {
		rule, ecosystem = "CVE-2020-36067-github.com/tidwall/gjson", "go-module"
	}
	res := sarif.Result{
		Tool: tool, RuleID: rule, Level: sarif.LevelError, Priority: "P1",
		Component: component, Repository: repository,
		Location: sarif.Location{URI: manifest, StartLine: line},
		Package: &sarif.Package{Name: "github.com/tidwall/gjson", Version: "v1.6.5", FixedVersion: "v1.6.6",
			Ecosystem: ecosystem, PURL: "pkg:golang/github.com/tidwall/gjson@v1.6.5"},
		Correlation: &sarif.Correlation{CountedUnder: countedUnder},
	}
	if countedUnder == "" {
		res.Correlation = &sarif.Correlation{AlsoFoundBy: []sarif.Observation{{Tool: "grype"}, {Tool: "trivy"}}}
	}
	return res
}

// twoModules is a run over two components in two repositories. api requires gjson in go.mod and in
// tools/go.mod, worker only in go.mod, and Trivy and Grype report every one. Correlation counts one
// finding per component, Trivy's at go.mod, and the rest are copies.
func twoModules() []sarif.Result {
	return []sarif.Result{
		gjson("trivy", "api", "repo-api", "go.mod", 5, ""),
		gjson("trivy", "api", "repo-api", "tools/go.mod", 5, "trivy"),
		gjson("grype", "api", "repo-api", "go.mod", 1, "trivy"),
		gjson("grype", "api", "repo-api", "tools/go.mod", 1, "trivy"),
		gjson("trivy", "worker", "repo-worker", "go.mod", 5, ""),
		gjson("grype", "worker", "repo-worker", "go.mod", 1, "trivy"),
	}
}

// A flaw in a dependency two Go modules require is one finding and two places to upgrade it. The fix
// list names both modules and clears the flaw once, and the component with one module is told about
// that module only.
func TestAnActionNamesEveryModuleItsFlawIsIn(t *testing.T) {
	got := ActionsFor(map[string]sarif.Report{"sca": {Results: twoModules()}})
	if len(got) != 2 {
		t.Fatalf("actions = %+v, want one per component", got)
	}
	byComponent := map[string]Action{}
	for _, a := range got {
		byComponent[a.Component] = a
	}
	for component, want := range map[string][]ActionLocation{
		"api": {
			{Repository: "repo-api", Path: "go.mod", Line: 5, Kind: "manifest"},
			{Repository: "repo-api", Path: "tools/go.mod", Line: 5, Kind: "manifest"},
		},
		"worker": {{Repository: "repo-worker", Path: "go.mod", Line: 5, Kind: "manifest"}},
	} {
		a := byComponent[component]
		if !reflect.DeepEqual(a.Locations, want) {
			t.Errorf("%s: locations = %+v\nwant %+v", component, a.Locations, want)
		}
		if a.Clears != 1 || len(a.Fingerprints) != 1 {
			t.Errorf("%s: clears %d with %d fingerprints, want the flaw counted once", component, a.Clears, len(a.Fingerprints))
		}
	}
	if w := byComponent["api"].Where; !reflect.DeepEqual(w, []string{"go.mod:5", "tools/go.mod:5"}) {
		t.Errorf("api: where = %q, want both modules", w)
	}
	if n := Cleared(got); n != 2 {
		t.Errorf("cleared = %d, want one flaw per component", n)
	}
}

// The console's list of actions and the HTML report name the same places report.json does, and
// count what the console counts everywhere else.
func TestEveryFixListNamesTheSecondModule(t *testing.T) {
	// No terminal width, so the row is not fitted to the shell running the test.
	t.Setenv("COLUMNS", "")
	d := Data{
		Verdict: norn.Result{Verdict: norn.Fail},
		View:    ViewActions,
		Run: engine.Result{Controls: map[string]plugin.ControlResult{
			"sca": {Control: "sca", Report: sarif.Report{Tool: "trivy", Results: twoModules()}},
		}},
	}
	var console bytes.Buffer
	if err := (consoleReporter{}).Render(&console, d); err != nil {
		t.Fatal(err)
	}
	if out := console.String(); !strings.Contains(out, "1 finding · go.mod:5 · tools/go.mod:5") ||
		!strings.Contains(out, "2 actions clear 2 findings") {
		t.Errorf("the console should name both modules on one action clearing one finding:\n%s", out)
	}
	var page strings.Builder
	if err := (htmlReporter{}).Render(&page, d); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(page.String(), "go.mod:5 · tools/go.mod:5") {
		t.Error("the HTML report should name both modules on the action")
	}
}

// Two scanners reading one go.mod write the line differently, or not at all. A copy in a file the
// action already names is the same edit, and a copy whose action is not in the list, filtered out
// by --min-priority, is never a row of its own.
func TestACopyOnlyAddsAFile(t *testing.T) {
	gj := func(loc string) finding { return pkgFinding("sca", "CVE-1", "P1", loc, "gjson", "v1.6.5", "v1.6.6") }
	got, _ := groupActions([]finding{gj("go.mod:5")}, nil,
		gj("go.mod:1"), gj("tools/go.mod:5"), gj("tools/go.mod"), gj(""))
	if len(got) != 1 || got[0].count() != 1 {
		t.Fatalf("actions = %+v, want one clearing one finding", got)
	}
	if w := got[0].where(5); !reflect.DeepEqual(w, []string{"go.mod:5", "tools/go.mod:5"}) {
		t.Errorf("where = %q, want each file once", w)
	}

	if got, _ := groupActions(nil, nil, gj("tools/go.mod:5")); len(got) != 0 {
		t.Errorf("actions = %+v, want none from a copy alone", got)
	}

	// A tag is not a line: two tags of one image are two images.
	img := func(ref string) finding { return pkgFinding("images", "CVE-2", "P1", ref, "libssl3", "3.0.1", "3.0.2") }
	got, _ = groupActions([]finding{img("redis:7")}, nil, img("redis:8"), img("redis:7"))
	if w := got[0].where(5); !reflect.DeepEqual(w, []string{"redis:7", "redis:8"}) {
		t.Errorf("where = %q, want both tags", w)
	}
}

// A copy goes with the step of a split upgrade its own fixes put it in, as the finding it repeats
// does, and with the step within the policy where there is no other.
func TestAPolicySplitSendsEachCopyWithItsStep(t *testing.T) {
	at := func(f finding, loc string) finding { f.location = loc; return f }
	major := upgradeFinding("CVE-1", "P1", "web", "minor", "npm", "jquery", "1.8.3", "3.5.0")
	minor := upgradeFinding("CVE-3", "P3", "web", "minor", "npm", "jquery", "1.8.3", "1.9.0")
	got, _ := groupActions([]finding{major, minor}, nil,
		at(major, "static/js/jquery.min.js"), at(minor, "admin/js/jquery.min.js"))
	if len(got) != 2 {
		t.Fatalf("want the step within the policy and the step past it, got %d", len(got))
	}
	within, beyond := got[0], got[1]
	if w := within.where(5); !reflect.DeepEqual(w, []string{"package-lock.json:12", "admin/js/jquery.min.js vendored"}) {
		t.Errorf("within: where = %q", w)
	}
	if w := beyond.where(5); !reflect.DeepEqual(w, []string{"package-lock.json:12", "static/js/jquery.min.js vendored"}) {
		t.Errorf("beyond: where = %q", w)
	}

	// Every finding fits the policy, and a scanner naming a later fix for its copy does not make a
	// second step for it.
	got, _ = groupActions([]finding{minor}, nil, at(major, "static/js/jquery.min.js"))
	if len(got) != 1 {
		t.Fatalf("want one step, got %d", len(got))
	}
	if w := got[0].where(5); !reflect.DeepEqual(w, []string{"package-lock.json:12", "static/js/jquery.min.js vendored"}) {
		t.Errorf("where = %q, want the copy's file on the one step", w)
	}
}
