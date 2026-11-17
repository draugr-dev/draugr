package scanners

import (
	"cmp"
	"context"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/controllers"
	"github.com/draugr-dev/draugr/internal/git"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// The files under testdata/sarif-import that these tests import beside a native run are each what a
// tool wrote, unedited, about one project at /src/app:
//
//   - semgrep-code.sarif and semgrep-code.json, Semgrep 1.182.1 run with --config
//     /src/app/rules/app-rules.yaml over an app.py (semgrepApp) that calls os.popen at line 5 and
//     os.system at line 9. Semgrep put `rules.` on each rule's id, the rules directory relative to
//     where it ran.
//   - trivy-fs-gomod.json, Trivy 0.76.1's `trivy fs --format json --list-all-pkgs` over a go.mod that
//     requires golang.org/x/text v0.3.5, the command line trivy-fs runs: the same four advisories
//     trivy-deps.sarif reports in that go.mod.
//
// Each is imported into the control whose own scanner is the same tool, into two components in two
// repositories, and each flaw is expected once per component.

// semgrepApp is the app.py Semgrep read for semgrep-code.sarif.
const semgrepApp = `import os


def listing(name):
    return os.popen("ls " + name).read()


def remove(name):
    os.system("rm " + name)
`

// importTestdata reads one file under testdata/sarif-import.
func importTestdata(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "sarif-import", name)) // #nosec G304 -- under testdata
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// importComponent is one component as runBesideImport declares it: its repositories by name, each
// a directory of its own, those that hold semgrepApp, and the file it imports.
type importComponent struct {
	repos, withApp []string
	file           string
}

// twoComponents is api and web, each in a repository of its own holding semgrepApp, each importing
// file from testdata/sarif-import.
func twoComponents(file string) map[string]importComponent {
	path := filepath.Join("testdata", "sarif-import", file)
	return map[string]importComponent{
		"api": {repos: []string{"api"}, withApp: []string{"api"}, file: path},
		"web": {repos: []string{"web"}, withApp: []string{"web"}, file: path},
	}
}

// runBesideImport runs comps under control, with scanner as the control's native scanner, and
// returns the result and each repository's directory by name.
func runBesideImport(t *testing.T, control plugin.Controller, scanner plugin.Scanner, settings saga.ControllerSettings,
	comps map[string]importComponent) (engine.Result, map[string]string) {
	t.Helper()
	reg := engine.NewRegistry()
	reg.RegisterController(control)
	reg.RegisterScanner(scanner)
	reg.RegisterScanner(NewSARIFImport())
	name := control.Info().Name
	model := saga.Model{Config: saga.Config{Controls: map[string]saga.ControllerSettings{name: settings}}}
	root := t.TempDir()
	dirs := map[string]string{}
	names := slices.Sorted(maps.Keys(comps))
	for _, comp := range names {
		c := comps[comp]
		var repos []saga.Repository
		for _, repo := range c.repos {
			dir := filepath.Join(root, repo)
			if err := os.MkdirAll(dir, 0o750); err != nil {
				t.Fatal(err)
			}
			if slices.Contains(c.withApp, repo) {
				if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte(semgrepApp), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			dirs[repo] = dir
			repos = append(repos, saga.Repository{URL: dir})
		}
		model.Components = append(model.Components, saga.Component{
			Name: comp, Repositories: repos, Imports: []saga.Import{{Control: name, File: c.file}},
		})
	}
	res, err := engine.New(reg).Run(context.Background(), model)
	if err != nil {
		t.Fatal(err)
	}
	return res, dirs
}

// checkoutAt reads a repository's URL as the directory it is in.
func checkoutAt(_ context.Context, url, _ string, _ git.Scope) (git.Tree, func(), error) {
	return git.Tree{Dir: url}, func() {}, nil
}

// replayingSemgrep is the semgrep scanner replaying semgrep-code.sarif over a checkout holding
// semgrepApp, as it reports a rules file at config, and reporting nothing over any other checkout.
func replayingSemgrep(t *testing.T) (plugin.Scanner, string) {
	t.Helper()
	rules := filepath.Join(t.TempDir(), "rules")
	if err := os.MkdirAll(rules, 0o750); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(rules, "app-rules.yaml")
	if err := os.WriteFile(config, []byte("rules: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// What Semgrep writes for the rules file at config: its absolute directory on each id, which the
	// native scanner then removes.
	prefixed := func(doc []byte) []byte {
		return []byte(strings.ReplaceAll(string(doc), `"rules.`, `"`+dottedPrefix(rules)))
	}
	semgrep := NewSemgrep().(repoScanner)
	semgrep.checkout, semgrep.cacheVersion, semgrep.preflight, semgrep.dataState = checkoutAt, nil, nil, nil
	semgrep.run = func(_ context.Context, dir string, _ []string) ([]byte, error) {
		if _, err := os.Stat(filepath.Join(dir, "app.py")); err != nil {
			return semgrepReportsOf(t, []byte(noSemgrepSARIF), []byte(noSemgrepResults)), nil
		}
		return semgrepReportsOf(t, prefixed(importTestdata(t, "semgrep-code.sarif")),
			prefixed(importTestdata(t, "semgrep-code.json"))), nil
	}
	return semgrep, config
}

// noSemgrepSARIF is a Semgrep run that found nothing.
const noSemgrepSARIF = `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Semgrep OSS","rules":[]}},"results":[]}]}`

// flaw is one counted finding as a test reads it: the rule, and who else reported it.
type flaw struct {
	rule string
	also []string
}

// countedFlaws is each component's counted findings in the control, sorted by rule.
func countedFlaws(t *testing.T, res engine.Result, control string) map[string][]flaw {
	t.Helper()
	out := map[string][]flaw{}
	for _, r := range res.Controls[control].Report.Results {
		if r.Correlated() {
			continue
		}
		f := flaw{rule: r.RuleID}
		if r.Correlation != nil {
			for _, o := range r.Correlation.AlsoFoundBy {
				f.also = append(f.also, o.Tool)
			}
		}
		out[r.Component] = append(out[r.Component], f)
	}
	for comp := range out {
		slices.SortFunc(out[comp], func(a, b flaw) int { return strings.Compare(a.rule, b.rule) })
	}
	return out
}

// Semgrep's own file imported into sast, which runs Semgrep: each of the two findings is counted
// once in each component, under one copy that names the other, though the native run reports each
// rule without the directory the imported file's ids carry.
func TestAnImportedSemgrepFileBesideSemgrepCountsEachFindingOnce(t *testing.T) {
	semgrep, config := replayingSemgrep(t)
	res, _ := runBesideImport(t, controllers.NewSAST(), semgrep,
		saga.ControllerSettings{"enabled": true, "semgrep": map[string]any{"config": config}}, twoComponents("semgrep-code.sarif"))
	if len(res.ScanErrors) > 0 {
		t.Fatalf("errors: %v", res.ScanErrors)
	}

	results := res.Controls["sast"].Report.Results
	if len(results) != 8 {
		t.Fatalf("%d results, want 2 rules × 2 copies × 2 components", len(results))
	}
	// The pairs differ by the directory: the native run reports the id the rules file declares.
	ids := map[string]bool{}
	for _, r := range results {
		ids[r.Reporter()+" "+r.RuleID] = true
	}
	for _, want := range []string{"Semgrep OSS no-os-system", "imported Semgrep OSS rules.no-os-system"} {
		if !ids[want] {
			t.Fatalf("no %q among %v", want, ids)
		}
	}
	got := countedFlaws(t, res, "sast")
	for _, comp := range []string{"api", "web"} {
		flaws := got[comp]
		if len(flaws) != 2 {
			t.Fatalf("%s: counted %+v, want each of the two findings once", comp, flaws)
		}
		for _, f := range flaws {
			if len(f.also) != 1 || (f.also[0] != "Semgrep OSS" && f.also[0] != "imported Semgrep OSS") {
				t.Errorf("%s %s: also found by %v, want the other Semgrep copy", comp, f.rule, f.also)
			}
		}
	}
	// Each counted copy is the stronger of its pair: Semgrep's own run rates os.system from the rule's
	// impact and likelihood, high, where the imported file gives the SARIF level alone.
	for _, r := range results {
		if r.Correlated() {
			continue
		}
		for _, o := range r.Correlation.AlsoFoundBy {
			if o.Severity.Rank() > r.Severity("").Rank() {
				t.Errorf("%s %s counted at %s under %s, below %s's %s", r.Component, r.RuleID, r.Severity(""), r.Reporter(), o.Tool, o.Severity)
			}
		}
	}
}

// Trivy's own SARIF imported into sca, which runs trivy-fs over the same go.mod: each of the four
// advisories in golang.org/x/text is counted once per component, naming both scanners, and the
// lodash advisories only the file reports are counted as they were.
func TestAnImportedTrivyFileBesideTrivyFSCountsEachAdvisoryOnce(t *testing.T) {
	trivy := NewTrivyFS().(repoScanner)
	trivy.checkout, trivy.prewarm, trivy.cacheVersion, trivy.dataState = checkoutAt, nil, nil, nil
	trivy.runLogged = trivyFSRun(func(context.Context, string, []string) ([]byte, []byte, error) {
		return importTestdata(t, "trivy-fs-gomod.json"), nil, nil
	})
	res, _ := runBesideImport(t, controllers.NewSCA(), trivy, saga.ControllerSettings{"enabled": true}, twoComponents("trivy-deps.sarif"))
	if len(res.ScanErrors) > 0 {
		t.Fatalf("errors: %v", res.ScanErrors)
	}

	advisories := []string{"CVE-2021-38561", "CVE-2022-32149", "CVE-2026-56851", "CVE-2026-56852"}
	got := countedFlaws(t, res, "sca")
	for _, comp := range []string{"api", "web"} {
		var text []flaw
		for _, f := range got[comp] {
			if slices.Contains(advisories, f.rule) {
				text = append(text, f)
			}
		}
		if len(text) != len(advisories) {
			t.Fatalf("%s: counted %+v, want each golang.org/x/text advisory once", comp, text)
		}
		for _, f := range text {
			if len(f.also) != 1 || (f.also[0] != "trivy" && f.also[0] != "imported Trivy") {
				t.Errorf("%s %s: also found by %v, want the other Trivy copy", comp, f.rule, f.also)
			}
		}
		if len(got[comp]) == len(text) {
			t.Errorf("%s: no lodash advisory counted; the file's own findings were lost", comp)
		}
	}
}

// withProvenance writes semgrep-code.sarif with a versionControlProvenance entry naming repository,
// as a file states the repository its run scanned, and returns its path. The entry names no revision,
// so the import does not hold the file to a commit.
func withProvenance(t *testing.T, repository string) string {
	t.Helper()
	var log map[string]any
	if err := json.Unmarshal(importTestdata(t, "semgrep-code.sarif"), &log); err != nil {
		t.Fatal(err)
	}
	log["runs"].([]any)[0].(map[string]any)["versionControlProvenance"] = []any{map[string]any{"repositoryUri": repository}}
	data, err := json.Marshal(log)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "semgrep.sarif")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// sastCopies is each sast finding as "<reporter> <repository directory name> <rule>", the imported
// ones named by the repository they were placed in, and whether it is counted.
func sastCopies(res engine.Result) map[string]bool {
	out := map[string]bool{}
	for _, r := range res.Controls["sast"].Report.Results {
		repo := filepath.Base(cmp.Or(r.Repository, r.ImportedRepository, "none"))
		out[r.Reporter()+" "+repo+" "+r.RuleID] = !r.Correlated()
	}
	return out
}

// A component that declares two repositories, with Semgrep's findings in only one, imports a file
// that does not say which repository it scanned. The file could be about either, so its findings are
// placed in neither and merge with nothing: each of the four is counted.
func TestAnImportIntoAComponentOfTwoRepositoriesIsNotPlacedByItsFindings(t *testing.T) {
	semgrep, config := replayingSemgrep(t)
	res, _ := runBesideImport(t, controllers.NewSAST(), semgrep,
		saga.ControllerSettings{"enabled": true, "semgrep": map[string]any{"config": config}},
		map[string]importComponent{"api": {
			repos: []string{"service", "tools"}, withApp: []string{"service"},
			file: filepath.Join("testdata", "sarif-import", "semgrep-code.sarif"),
		}})
	if len(res.ScanErrors) > 0 {
		t.Fatalf("errors: %v", res.ScanErrors)
	}
	want := map[string]bool{
		"Semgrep OSS service no-os-popen": true, "Semgrep OSS service no-os-system": true,
		"imported Semgrep OSS none rules.no-os-popen": true, "imported Semgrep OSS none rules.no-os-system": true,
	}
	if got := sastCopies(res); !reflect.DeepEqual(got, want) {
		t.Errorf("copies = %v, want %v", got, want)
	}
}

// The same component, importing a file whose provenance names one of its two repositories: the file's
// findings are that repository's, and merge with Semgrep's findings there and not with the other's.
func TestAnImportIsPlacedInTheRepositoryItsProvenanceNames(t *testing.T) {
	semgrep, config := replayingSemgrep(t)
	res, _ := runBesideImport(t, controllers.NewSAST(), semgrep,
		saga.ControllerSettings{"enabled": true, "semgrep": map[string]any{"config": config}},
		map[string]importComponent{"api": {
			repos: []string{"service", "tools"}, withApp: []string{"service", "tools"},
			file: withProvenance(t, "https://example.com/acme/tools.git"),
		}})
	if len(res.ScanErrors) > 0 {
		t.Fatalf("errors: %v", res.ScanErrors)
	}
	counted := map[string]bool{}
	for copyOf, isCounted := range sastCopies(res) {
		if isCounted {
			counted[copyOf] = true
		}
	}
	if len(counted) != 4 {
		t.Errorf("counted %v, want each rule once per repository", counted)
	}
	for copyOf := range sastCopies(res) {
		if strings.Contains(copyOf, "imported") && !strings.Contains(copyOf, " tools ") {
			t.Errorf("%s: placed outside the repository the file names", copyOf)
		}
	}
	for _, r := range res.Controls["sast"].Report.Results {
		if r.Correlation == nil {
			if filepath.Base(r.Repository) != "service" {
				t.Errorf("%s %s in %s merged with nothing", r.Reporter(), r.RuleID, cmp.Or(r.Repository, r.ImportedRepository))
			}
			continue
		}
		if filepath.Base(cmp.Or(r.Repository, r.ImportedRepository)) != "tools" {
			t.Errorf("%s %s in %s was merged", r.Reporter(), r.RuleID, r.Repository)
		}
	}
}

// placeImported reads each run's provenance for that run's findings alone: the component's only
// repository whatever a run names, the one of several a run names, and none where a run names none
// of several, two, or one the component does not declare.
func TestPlaceImportedReadsEachRunsProvenance(t *testing.T) {
	var meta importLog
	doc := `{"runs":[
	 {"versionControlProvenance":[{"repositoryUri":"https://example.com/acme/tools.git"}],"results":[{},{}]},
	 {"results":[{}]},
	 {"versionControlProvenance":[{"repositoryUri":"https://example.com/acme/tools.git"},{"repositoryUri":"https://example.com/acme/service.git"}],"results":[{}]},
	 {"versionControlProvenance":[{"repositoryUri":"https://example.com/acme/other.git"}],"results":[{}]}
	]}`
	if err := json.Unmarshal([]byte(doc), &meta); err != nil {
		t.Fatal(err)
	}
	two := []plugin.RepositoryTarget{{URL: "/src/service"}, {URL: "/src/tools"}}
	results := make([]sarif.Result, 5)
	placeImported(results, meta, two)
	var got []string
	for _, r := range results {
		got = append(got, r.ImportedRepository)
	}
	tools := two[1].Source()
	if want := []string{tools, tools, "", "", ""}; !slices.Equal(got, want) {
		t.Errorf("placed %q, want %q", got, want)
	}

	one := []plugin.RepositoryTarget{{URL: "/src/service", Paths: []string{"a"}}, {URL: "/src/service", Paths: []string{"b"}}}
	results = make([]sarif.Result, 5)
	placeImported(results, meta, one)
	for i, r := range results {
		if r.ImportedRepository != one[0].Source() {
			t.Errorf("result %d with one repository: placed %q", i, r.ImportedRepository)
		}
	}

	// No repository declared places nothing, and fewer results than the runs count stop short.
	short := make([]sarif.Result, 1)
	placeImported(short, meta, nil)
	if short[0].ImportedRepository != "" {
		t.Errorf("no repository declared: placed %q", short[0].ImportedRepository)
	}
	placeImported(short, meta, two)
	if short[0].ImportedRepository != tools {
		t.Errorf("short results: placed %q", short[0].ImportedRepository)
	}
}
