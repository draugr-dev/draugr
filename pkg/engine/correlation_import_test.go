package engine

import (
	"reflect"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// codeAt is a code finding at app.py, reported by tool under rule at line, in repo. scanner is the
// Draugr scanner whose job read it: semgrep for a native run, sarif-import for a file.
func codeAt(scanner, tool, rule string, line int, component, repo string, level sarif.Level) sarif.Result {
	return sarif.Result{
		Tool: tool, Scanner: scanner, RuleID: rule, Level: level,
		Component: component, Repository: repo,
		Location: sarif.Location{URI: "app.py", StartLine: line},
	}
}

// native and imported are one Semgrep finding as Draugr's own run reports it, in its repository,
// and as an imported file reports it, with no repository and the rules directory still on its id.
func native(rule string, line int, component, repo string, level sarif.Level) sarif.Result {
	return codeAt("semgrep", "Semgrep OSS", rule, line, component, repo, level)
}

func imported(rule string, line int, component string, level sarif.Level) sarif.Result {
	return codeAt(plugin.ImportScanner, "Semgrep OSS", rule, line, component, "", level)
}

// sastWith files results under sast, beside an sca control holding others, so a component's home is
// read from every control rather than the one being correlated.
func sastWith(sast []sarif.Result, sca ...sarif.Result) map[string]plugin.ControlResult {
	ctrls := controlsWith(sca...)
	ctrls["sast"] = plugin.ControlResult{Control: "sast", Report: sarif.Report{Tool: "t", Results: sast}}
	return ctrls
}

// An imported Semgrep finding is the native finding of the same rule at the same line: counted once,
// under the stronger copy, which names the other as the imported file's. The imported id still
// carries the directory its rules came from, which the native scanner removed.
func TestAnImportedCodeFindingJoinsTheNativeFindingAtItsLine(t *testing.T) {
	ctrls := sastWith([]sarif.Result{
		native("no-os-system", 9, "api", "repo-api", sarif.LevelWarning),
		imported("rules.no-os-system", 9, "api", sarif.LevelError),
	})
	if groups, _ := applyCorrelation(ctrls); groups != 1 {
		t.Fatalf("groups = %d, want 1", groups)
	}
	results := ctrls["sast"].Report.Results
	if !results[0].Correlated() || results[0].Correlation.CountedUnder != "imported Semgrep OSS" {
		t.Errorf("native copy correlation = %+v, want counted under the imported file's stronger copy", results[0].Correlation)
	}
	also := results[1].Correlation.AlsoFoundBy
	if results[1].Correlated() || len(also) != 1 || also[0].Tool != "Semgrep OSS" || also[0].RuleID != "no-os-system" {
		t.Errorf("imported copy alsoFoundBy = %+v, want the native run under its own id", also)
	}
	if note := sarif.AgreementNote(also, results[1].Severity(""), results[1].Reporter()); note != "also found by Semgrep OSS (medium)" {
		t.Errorf("agreement note = %q", note)
	}
}

// Over two components in two repositories, each import joins its own component's native finding.
func TestImportedCodeFindingsJoinWithinTheirOwnComponent(t *testing.T) {
	ctrls := sastWith([]sarif.Result{
		native("no-os-system", 9, "api", "repo-api", sarif.LevelError),
		native("no-os-system", 9, "web", "repo-web", sarif.LevelError),
		imported("rules.no-os-system", 9, "web", sarif.LevelWarning),
		imported("rules.no-os-system", 9, "api", sarif.LevelWarning),
	})
	if groups, _ := applyCorrelation(ctrls); groups != 2 {
		t.Fatalf("groups = %d, want one per component", groups)
	}
	want := map[string][]string{"api": {"Semgrep OSS no-os-system"}, "web": {"Semgrep OSS no-os-system"}}
	if got := counted(ctrls["sast"].Report.Results); !reflect.DeepEqual(got, want) {
		t.Errorf("counted = %v, want %v", got, want)
	}
}

// What is not the same rule at the same line stays its own finding: the rule at another line,
// another rule at the line, Bandit's rule about the same call, a native finding beside another
// native one, and two copies of the rule at one line, which cannot be paired copy to copy.
func TestCodeFindingsThatAreNotOneRuleAtOneLineStayApart(t *testing.T) {
	bandit := codeAt(plugin.ImportScanner, "Bandit", "B605", 9, "api", "", sarif.LevelError)
	gosec := codeAt("gosec", "gosec", "no-os-system", 9, "api", "repo-api", sarif.LevelError)
	for name, sast := range map[string][]sarif.Result{
		"another line": {native("no-os-system", 9, "api", "repo-api", sarif.LevelError), imported("rules.no-os-system", 10, "api", sarif.LevelError)},
		"another rule": {native("no-os-popen", 9, "api", "repo-api", sarif.LevelError), imported("rules.no-os-system", 9, "api", sarif.LevelError)},
		"bandit":       {native("no-os-system", 9, "api", "repo-api", sarif.LevelError), bandit},
		"two natives":  {native("no-os-system", 9, "api", "repo-api", sarif.LevelError), gosec},
		"twice at the line": {
			native("no-os-system", 9, "api", "repo-api", sarif.LevelError),
			native("no-os-system", 9, "api", "repo-api", sarif.LevelWarning),
			imported("rules.no-os-system", 9, "api", sarif.LevelError),
		},
		"claimed twice": {
			native("no-os-system", 9, "api", "repo-api", sarif.LevelError),
			imported("rules.no-os-system", 9, "api", sarif.LevelError),
			imported("no-os-system", 9, "api", sarif.LevelWarning),
		},
		"another component": {native("no-os-system", 9, "api", "repo-api", sarif.LevelError), imported("rules.no-os-system", 9, "web", sarif.LevelError)},
	} {
		ctrls := sastWith(sast, native("other", 1, "web", "repo-web", sarif.LevelNote))
		if groups, _ := applyCorrelation(ctrls); groups != 0 {
			t.Errorf("%s: groups = %d, want none", name, groups)
		}
	}
}

// The suffix is read only for Semgrep, the tool that puts a directory on a local rule's id. Another
// tool's ids are compared whole, and a Semgrep id that is its own at the line is preferred to one
// the imported id merely ends in.
func TestOnlySemgrepIdsAreReadPastTheirDirectory(t *testing.T) {
	ctrls := sastWith([]sarif.Result{
		codeAt("gosec", "gosec", "G204", 9, "api", "repo-api", sarif.LevelError),
		codeAt(plugin.ImportScanner, "gosec", "x.G204", 9, "api", "", sarif.LevelError),
	})
	if groups, _ := applyCorrelation(ctrls); groups != 0 {
		t.Errorf("gosec: groups = %d, want none", groups)
	}
	ctrls = sastWith([]sarif.Result{
		native("no-os-system", 9, "api", "repo-api", sarif.LevelError),
		native("rules.no-os-system", 9, "api", "repo-api", sarif.LevelError),
		imported("rules.no-os-system", 9, "api", sarif.LevelError),
	})
	if groups, _ := applyCorrelation(ctrls); groups != 1 {
		t.Fatalf("groups = %d, want 1", groups)
	}
	if r := ctrls["sast"].Report.Results[0]; r.Correlated() {
		t.Errorf("the id the imported one only ends in was joined: %+v", r.Correlation)
	}
}

// A component whose findings name two repositories gives an imported finding no home: the file's
// path does not say which repository it is in, and the finding stays counted apart rather than
// joining whichever repository came first.
func TestAnImportIsNotPlacedInAComponentOfTwoRepositories(t *testing.T) {
	ctrls := sastWith([]sarif.Result{
		native("no-os-system", 9, "api", "repo-api", sarif.LevelError),
		native("no-os-system", 9, "api", "repo-tools", sarif.LevelError),
		imported("rules.no-os-system", 9, "api", sarif.LevelError),
	})
	if groups, _ := applyCorrelation(ctrls); groups != 0 {
		t.Errorf("groups = %d, want none", groups)
	}
	// A second repository the component's sca findings name is enough.
	ctrls = sastWith([]sarif.Result{
		native("no-os-system", 9, "api", "repo-api", sarif.LevelError),
		imported("rules.no-os-system", 9, "api", sarif.LevelError),
	}, native("other", 1, "api", "repo-tools", sarif.LevelNote))
	if groups, _ := applyCorrelation(ctrls); groups != 0 {
		t.Errorf("with a second repository in sca: groups = %d, want none", groups)
	}
}

// textDep is golang.org/x/text v0.3.5 under CVE-2021-38561, as trivy-fs reports it from a go.mod,
// with the package URL, and as Trivy's own SARIF states it, by name and version alone.
func textDep(scanner, tool, component, repo string, score float64) sarif.Result {
	r := sarif.Result{
		Tool: tool, Scanner: scanner, RuleID: "CVE-2021-38561", Level: sarif.LevelError, Score: score, HasScore: true,
		Component: component, Repository: repo, Location: sarif.Location{URI: "go.mod"},
		Package: &sarif.Package{Name: "golang.org/x/text", Version: "v0.3.5", Ecosystem: "gomod"},
	}
	if scanner != plugin.ImportScanner {
		r.Package.PURL = "pkg:golang/golang.org/x/text@v0.3.5"
	}
	return r
}

// Trivy's file imported into sca is a second account of what trivy-fs found, though both are Trivy
// and one may spell the tool as the other does: the import is its own reporter. The copy with the
// higher score is counted, naming the other.
func TestAnImportedDependencyFindingJoinsTheNativeOneOfTheSameTool(t *testing.T) {
	for _, tool := range []string{"Trivy", "trivy"} {
		ctrls := controlsWith(
			textDep("trivy-fs", "trivy", "api", "repo-api", 7.5),
			textDep(plugin.ImportScanner, tool, "api", "", 8.1),
		)
		if groups, _ := applyCorrelation(ctrls); groups != 1 {
			t.Fatalf("%s: groups = %d, want 1", tool, groups)
		}
		results := ctrls["sca"].Report.Results
		if !results[0].Correlated() || results[0].Correlation.CountedUnder != "imported "+tool {
			t.Errorf("%s: native copy = %+v, want counted under the import's higher score", tool, results[0].Correlation)
		}
		if also := results[1].Correlation.AlsoFoundBy; len(also) != 1 || also[0].Tool != "trivy" {
			t.Errorf("%s: alsoFoundBy = %+v, want trivy", tool, also)
		}
	}
}

// The same advisory in another package, or in another component, is another flaw.
func TestAnImportedDependencyFindingStaysApartFromAnotherPackage(t *testing.T) {
	other := textDep(plugin.ImportScanner, "Trivy", "api", "", 7.5)
	other.Package.Name = "golang.org/x/net"
	ctrls := controlsWith(textDep("trivy-fs", "trivy", "api", "repo-api", 7.5), other,
		textDep(plugin.ImportScanner, "Trivy", "web", "", 7.5))
	if groups, _ := applyCorrelation(ctrls); groups != 0 {
		t.Errorf("groups = %d, want none", groups)
	}
}

// Placement is for an import only. A native finding with no repository was read from an image or a
// host, and an imported one read from an image keeps none.
func TestPlacedRepository(t *testing.T) {
	homes := map[string]string{"api": "repo-api"}
	for _, c := range []struct {
		res  sarif.Result
		want string
	}{
		{sarif.Result{Component: "api", Scanner: plugin.ImportScanner}, "repo-api"},
		{sarif.Result{Component: "api", Scanner: plugin.ImportScanner, Repository: "repo-x"}, "repo-x"},
		{sarif.Result{Component: "api", Scanner: plugin.ImportScanner, Image: "img"}, ""},
		{sarif.Result{Component: "api", Scanner: "trivy"}, ""},
		{sarif.Result{Component: "web", Scanner: plugin.ImportScanner}, ""},
	} {
		if got := placedRepository(c.res, homes); got != c.want {
			t.Errorf("placedRepository(%+v) = %q, want %q", c.res, got, c.want)
		}
	}
}

// A code finding is keyed only where it names a rule, a file, a line and a tool, and is not about a
// package or a benchmark check.
func TestCodeKeyOf(t *testing.T) {
	ok := native("r", 3, "api", "repo-api", sarif.LevelError)
	check := sarif.Rule{Taxa: []sarif.Taxon{{Taxonomy: "CIS-Kubernetes", ID: "5.1.1", Version: "1.9"}}}
	for name, c := range map[string]struct {
		edit  func(*sarif.Result)
		rules map[string]sarif.Rule
	}{
		"package":   {edit: func(r *sarif.Result) { r.Package = &sarif.Package{Name: "p"} }},
		"no rule":   {edit: func(r *sarif.Result) { r.RuleID = "" }},
		"no file":   {edit: func(r *sarif.Result) { r.Location.URI = "" }},
		"no line":   {edit: func(r *sarif.Result) { r.Location.StartLine = 0 }},
		"no tool":   {edit: func(r *sarif.Result) { r.Tool = " " }},
		"benchmark": {edit: func(*sarif.Result) {}, rules: map[string]sarif.Rule{"r": check}},
	} {
		r := ok
		c.edit(&r)
		if _, keyed := codeKeyOf(r, c.rules, nil); keyed {
			t.Errorf("%s: keyed", name)
		}
	}
	if k, keyed := codeKeyOf(ok, nil, nil); !keyed || k.product != "semgrep" || k.line != 3 {
		t.Errorf("codeKeyOf = %+v, %v", k, keyed)
	}
}
