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
		Tool: tool, Scanner: scanner, RuleID: rule, Level: level, Message: "os.system runs its argument through a shell",
		Component: component, Repository: repo,
		Location: sarif.Location{URI: "app.py", StartLine: line},
	}
}

// native is one Semgrep finding as Draugr's own run reports it, in its repository.
func native(rule string, line int, component, repo string, level sarif.Level) sarif.Result {
	return codeAt("semgrep", "Semgrep OSS", rule, line, component, repo, level)
}

// imported is the same finding as an imported file reports it: no repository of its own, the rules
// directory still on its id, and placed by the import in the component's repository, repo-<component>.
func imported(rule string, line int, component string, level sarif.Level) sarif.Result {
	return importedIn(rule, line, component, "repo-"+component, level)
}

// importedIn is an imported finding the import placed in repo, or in none where repo is empty.
func importedIn(rule string, line int, component, repo string, level sarif.Level) sarif.Result {
	r := codeAt(plugin.ImportScanner, "Semgrep OSS", rule, line, component, "", level)
	r.ImportedRepository = repo
	return r
}

// sastWith files results under sast.
func sastWith(sast ...sarif.Result) map[string]plugin.ControlResult {
	return map[string]plugin.ControlResult{"sast": {Control: "sast", Report: sarif.Report{Tool: "t", Results: sast}}}
}

// An imported Semgrep finding is the native finding of the same rule at the same line: counted once,
// under the stronger copy, which names the other as the imported file's. The imported id still
// carries the directory its rules came from, which the native scanner removed.
func TestAnImportedCodeFindingJoinsTheNativeFindingAtItsLine(t *testing.T) {
	ctrls := sastWith(
		native("no-os-system", 9, "api", "repo-api", sarif.LevelWarning),
		imported("rules.no-os-system", 9, "api", sarif.LevelError),
	)
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
	ctrls := sastWith(
		native("no-os-system", 9, "api", "repo-api", sarif.LevelError),
		native("no-os-system", 9, "web", "repo-web", sarif.LevelError),
		imported("rules.no-os-system", 9, "web", sarif.LevelWarning),
		imported("rules.no-os-system", 9, "api", sarif.LevelWarning),
	)
	if groups, _ := applyCorrelation(ctrls); groups != 2 {
		t.Fatalf("groups = %d, want one per component", groups)
	}
	want := map[string][]string{"api": {"Semgrep OSS no-os-system"}, "web": {"Semgrep OSS no-os-system"}}
	if got := counted(ctrls["sast"].Report.Results); !reflect.DeepEqual(got, want) {
		t.Errorf("counted = %v, want %v", got, want)
	}
}

// What is not the same rule at the same line in the same repository stays its own finding: the rule
// at another line, another rule at the line, Bandit's rule about the same call, a native finding
// beside another native one, two copies of the rule at one line, which cannot be paired copy to copy,
// an import placed in another repository or in none, and a Semgrep id that ends in the native one
// but says something else.
func TestCodeFindingsThatAreNotOneRuleAtOneLineStayApart(t *testing.T) {
	bandit := codeAt(plugin.ImportScanner, "Bandit", "B605", 9, "api", "", sarif.LevelError)
	bandit.ImportedRepository = "repo-api"
	gosec := codeAt("gosec", "gosec", "no-os-system", 9, "api", "repo-api", sarif.LevelError)
	saysOther := imported("rules.no-os-system", 9, "api", sarif.LevelError)
	saysOther.Message = "a different rule that happens to share the name"
	at := native("no-os-system", 9, "api", "repo-api", sarif.LevelError)
	for name, sast := range map[string][]sarif.Result{
		"another line":       {at, imported("rules.no-os-system", 10, "api", sarif.LevelError)},
		"another rule":       {native("no-os-popen", 9, "api", "repo-api", sarif.LevelError), imported("rules.no-os-system", 9, "api", sarif.LevelError)},
		"bandit":             {at, bandit},
		"two natives":        {at, gosec},
		"another repo":       {at, importedIn("rules.no-os-system", 9, "api", "repo-tools", sarif.LevelError)},
		"placed nowhere":     {at, importedIn("rules.no-os-system", 9, "api", "", sarif.LevelError)},
		"says another thing": {at, saysOther},
		"twice at the line": {
			at, native("no-os-system", 9, "api", "repo-api", sarif.LevelWarning),
			imported("rules.no-os-system", 9, "api", sarif.LevelError),
		},
		"claimed twice": {
			at, imported("rules.no-os-system", 9, "api", sarif.LevelError),
			imported("no-os-system", 9, "api", sarif.LevelWarning),
		},
		"another component": {at, imported("rules.no-os-system", 9, "web", sarif.LevelError)},
	} {
		if groups, _ := applyCorrelation(sastWith(sast...)); groups != 0 {
			t.Errorf("%s: groups = %d, want none", name, groups)
		}
	}
	// An import placed nowhere does not meet a native finding that names no repository either.
	repoless := native("no-os-system", 9, "api", "", sarif.LevelError)
	if groups, _ := applyCorrelation(sastWith(repoless, importedIn("no-os-system", 9, "api", "", sarif.LevelError))); groups != 0 {
		t.Errorf("an unplaced import joined a finding with no repository: groups = %d", groups)
	}
	// The same id needs no matching message.
	if groups, _ := applyCorrelation(sastWith(at, func() sarif.Result {
		r := imported("no-os-system", 9, "api", sarif.LevelError)
		r.Message = "worded differently"
		return r
	}())); groups != 1 {
		t.Errorf("the same id worded differently: groups = %d, want 1", groups)
	}
}

// The suffix is read only for Semgrep, the tool that puts a directory on a local rule's id. Another
// tool's ids are compared whole, and a Semgrep id that is its own at the line is preferred to one
// the imported id merely ends in.
func TestOnlySemgrepIdsAreReadPastTheirDirectory(t *testing.T) {
	importedGosec := codeAt(plugin.ImportScanner, "gosec", "x.G204", 9, "api", "", sarif.LevelError)
	importedGosec.ImportedRepository = "repo-api"
	ctrls := sastWith(codeAt("gosec", "gosec", "G204", 9, "api", "repo-api", sarif.LevelError), importedGosec)
	if groups, _ := applyCorrelation(ctrls); groups != 0 {
		t.Errorf("gosec: groups = %d, want none", groups)
	}
	ctrls = sastWith(
		native("no-os-system", 9, "api", "repo-api", sarif.LevelError),
		native("rules.no-os-system", 9, "api", "repo-api", sarif.LevelError),
		imported("rules.no-os-system", 9, "api", sarif.LevelError),
	)
	if groups, _ := applyCorrelation(ctrls); groups != 1 {
		t.Fatalf("groups = %d, want 1", groups)
	}
	if r := ctrls["sast"].Report.Results[0]; r.Correlated() {
		t.Errorf("the id the imported one only ends in was joined: %+v", r.Correlation)
	}
}

// textDep is golang.org/x/text v0.3.5 under CVE-2021-38561, as trivy-fs reports it from a go.mod,
// with the package URL, and as Trivy's own SARIF states it, by name and version alone, placed by the
// import in repo.
func textDep(scanner, tool, component, repo string, score float64) sarif.Result {
	r := sarif.Result{
		Tool: tool, Scanner: scanner, RuleID: "CVE-2021-38561", Level: sarif.LevelError, Score: score, HasScore: true,
		Component: component, Repository: repo, Location: sarif.Location{URI: "go.mod"},
		Package: &sarif.Package{Name: "golang.org/x/text", Version: "v0.3.5", Ecosystem: "gomod"},
	}
	if scanner == plugin.ImportScanner {
		r.Repository, r.ImportedRepository = "", repo
	} else {
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
			textDep(plugin.ImportScanner, tool, "api", "repo-api", 8.1),
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

// The same advisory in another package, another component, another repository or in no repository
// the import could establish is another flaw.
func TestAnImportedDependencyFindingStaysApartFromAnotherPackage(t *testing.T) {
	other := textDep(plugin.ImportScanner, "Trivy", "api", "repo-api", 7.5)
	other.Package.Name = "golang.org/x/net"
	ctrls := controlsWith(textDep("trivy-fs", "trivy", "api", "repo-api", 7.5), other,
		textDep(plugin.ImportScanner, "Trivy", "web", "repo-web", 7.5),
		textDep(plugin.ImportScanner, "Trivy", "api", "repo-tools", 7.5),
		textDep(plugin.ImportScanner, "Trivy", "api", "", 7.5))
	if groups, _ := applyCorrelation(ctrls); groups != 0 {
		t.Errorf("groups = %d, want none", groups)
	}
}

// A native finding keeps its own repository. An imported one, which names none, is in the one the
// import established, or in none a scanner reports.
func TestPlacedRepository(t *testing.T) {
	for _, c := range []struct {
		res  sarif.Result
		want string
	}{
		{sarif.Result{Scanner: plugin.ImportScanner, ImportedRepository: "repo-api"}, "repo-api"},
		{sarif.Result{Scanner: plugin.ImportScanner, Repository: "repo-x", ImportedRepository: "repo-api"}, "repo-x"},
		{sarif.Result{Scanner: plugin.ImportScanner}, unplaced},
		{sarif.Result{Scanner: "trivy"}, ""},
		{sarif.Result{Scanner: "trivy", Repository: "repo-api"}, "repo-api"},
	} {
		if got := placedRepository(c.res); got != c.want {
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
		if _, keyed := codeKeyOf(r, c.rules); keyed {
			t.Errorf("%s: keyed", name)
		}
	}
	if k, keyed := codeKeyOf(ok, nil); !keyed || k.product != "semgrep" || k.line != 3 {
		t.Errorf("codeKeyOf = %+v, %v", k, keyed)
	}
}
