package scanners

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/controllers"
	"github.com/draugr-dev/draugr/internal/git"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
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

// runBesideImport runs two components, api and web, each in a repository of its own, under control,
// with scanner as the control's native scanner and file imported into the control for each.
func runBesideImport(t *testing.T, control plugin.Controller, scanner plugin.Scanner, settings saga.ControllerSettings, file string) engine.Result {
	t.Helper()
	reg := engine.NewRegistry()
	reg.RegisterController(control)
	reg.RegisterScanner(scanner)
	reg.RegisterScanner(NewSARIFImport())
	name := control.Info().Name
	model := saga.Model{Config: saga.Config{Controls: map[string]saga.ControllerSettings{name: settings}}}
	for _, comp := range []string{"api", "web"} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte(semgrepApp), 0o600); err != nil {
			t.Fatal(err)
		}
		model.Components = append(model.Components, saga.Component{
			Name:         comp,
			Repositories: []saga.Repository{{URL: dir}},
			Imports:      []saga.Import{{Control: name, File: filepath.Join("testdata", "sarif-import", file)}},
		})
	}
	res, err := engine.New(reg).Run(context.Background(), model)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// checkoutAt reads a repository's URL as the directory it is in.
func checkoutAt(_ context.Context, url, _ string, _ git.Scope) (git.Tree, func(), error) {
	return git.Tree{Dir: url}, func() {}, nil
}

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
	semgrep.run = func(context.Context, string, []string) ([]byte, error) {
		return semgrepReportsOf(t, prefixed(importTestdata(t, "semgrep-code.sarif")),
			prefixed(importTestdata(t, "semgrep-code.json"))), nil
	}
	res := runBesideImport(t, controllers.NewSAST(), semgrep,
		saga.ControllerSettings{"enabled": true, "semgrep": map[string]any{"config": config}}, "semgrep-code.sarif")
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
	res := runBesideImport(t, controllers.NewSCA(), trivy, saga.ControllerSettings{"enabled": true}, "trivy-deps.sarif")
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
