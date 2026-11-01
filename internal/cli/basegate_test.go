package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/skald"
)

// The repositories two components read, one each.
const (
	apiRepo = "https://example.com/api.git"
	webRepo = "https://example.com/web.git"
)

// repoController plans one job per repository a component declares, as a dependency control does.
type repoController struct{}

func (repoController) Info() plugin.ControllerInfo {
	return plugin.ControllerInfo{Name: "sca", Scope: plugin.ScopeComponent}
}

func (repoController) Plan(_ saga.Model, comp *saga.Component) ([]plugin.ScanJob, error) {
	if comp == nil {
		return nil, nil
	}
	var jobs []plugin.ScanJob
	for _, r := range comp.Repositories {
		jobs = append(jobs, plugin.ScanJob{Scanner: "staged", Target: plugin.RepositoryTarget{URL: r.URL}})
	}
	return jobs, nil
}

func (repoController) Aggregate(reports []sarif.Report) (plugin.ControlResult, error) {
	m := sarif.Merge(reports...)
	c := m.Counts()
	return plugin.ControlResult{Control: "sca", Report: m,
		Summary: plugin.Summary{Errors: c.Error, Warnings: c.Warning, Notes: c.Note}}, nil
}

// stagedScanner reports what the test has put on each repository, and the revision it read, as a
// repository scanner records them. The test changes both between a base scan and a head scan.
type stagedScanner struct {
	findings  map[string][]sarif.Result
	revisions map[string]string
}

func (*stagedScanner) Info() plugin.ScannerInfo { return plugin.ScannerInfo{Name: "staged"} }

func (s *stagedScanner) Scan(_ context.Context, target plugin.Target, _ plugin.Config) (sarif.Report, error) {
	url := target.(plugin.RepositoryTarget).URL
	out := make([]sarif.Result, 0, len(s.findings[url]))
	for _, f := range s.findings[url] {
		f.Repository = url
		out = append(out, f)
	}
	return sarif.Report{Tool: "staged", Results: out, Provenance: []sarif.Provenance{{
		Tool:   "staged",
		Fields: []sarif.Field{{Key: "repository", Value: url}, {Key: "revision", Value: s.revisions[url]}},
	}}}, nil
}

// twoComponentSaga declares two components on two repositories, with the gate on new findings set
// to failOnNew where it is not empty.
func twoComponentSaga(t *testing.T, failOnNew string) string {
	t.Helper()
	gate := ""
	if failOnNew != "" {
		gate = "\n  gate:\n    failOnNew: " + failOnNew
	}
	return writeSaga(t, `
project: shop
release:
  version: "1.0"
config:
  controls:
    sca:
      enabled: true`+gate+`
components:
  - name: api
    repositories:
      - url: `+apiRepo+`
  - name: web
    repositories:
      - url: `+webRepo+`
`)
}

// finding is one result at a path, with a message naming it, at a level.
func finding(rule, uri string, level sarif.Level) sarif.Result {
	return sarif.Result{Tool: "staged", RuleID: rule, Level: level, Message: rule + " in " + uri,
		Location: sarif.Location{URI: uri, StartLine: 1}}
}

// stagedPair is a scanner holding the base, at a level the default gate does not fail on: one
// finding in each repository, the same rule in the same file, and one more in web.
func stagedPair() (*stagedScanner, *engine.Registry) {
	s := &stagedScanner{
		findings: map[string][]sarif.Result{
			apiRepo: {finding("CVE-OLD", "go.mod", sarif.LevelNote)},
			webRepo: {finding("CVE-OLD", "go.mod", sarif.LevelNote), finding("CVE-WEB", "go.mod", sarif.LevelNote)},
		},
		revisions: map[string]string{apiRepo: "aaaa1111", webRepo: "bbbb2222"},
	}
	reg := engine.NewRegistry()
	reg.RegisterController(repoController{})
	reg.RegisterScanner(s)
	return s, reg
}

// introduce moves the scanner to the head: api gains a warning, and a note that is web's CVE-WEB in
// every field but its component and repository. web is unchanged.
//
// The second is the finding a comparison keyed on less than the component and the repository would
// match to web's and report as nothing new.
func introduce(s *stagedScanner) {
	s.findings[apiRepo] = append(s.findings[apiRepo],
		finding("CVE-NEW", "go.mod", sarif.LevelWarning),
		finding("CVE-WEB", "go.mod", sarif.LevelNote))
	s.revisions[apiRepo] = "cccc3333"
}

// gateOf reads the gate block of the report.json written into dir.
func gateOf(t *testing.T, dir string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "report.json")) // #nosec G304 -- this test's own temp file
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Gate map[string]any `json:"gate"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Gate
}

// scanBase runs the base scan into a directory of its own and returns its results.sarif.
func scanBase(t *testing.T, path string, reg *engine.Registry) string {
	t.Helper()
	dir := t.TempDir()
	if err := runScan(context.Background(), path, scanOptions{outputDir: dir, noPublish: true}, reg, &bytes.Buffer{}); err != nil {
		t.Fatalf("base scan: %v", err)
	}
	return filepath.Join(dir, "results.sarif")
}

// A scan given a base gates on what it introduced, in the component and repository it introduced
// it in. Both new findings are in api's repository, one of them a rule and file web already had,
// and web's own findings are the same findings they were.
func TestAScanGatesOnTheFindingsItIntroduces(t *testing.T) {
	path := twoComponentSaga(t, "")
	s, reg := stagedPair()
	base := scanBase(t, path, reg)
	introduce(s)

	out := t.TempDir()
	err := runScan(context.Background(), path,
		scanOptions{outputDir: out, noPublish: true, base: base, failOnNew: "P3"}, reg, &bytes.Buffer{})
	if err == nil {
		t.Fatal("two new findings at or above P3 passed the gate on new findings")
	}
	// Both of the base's revisions, because it read two repositories and neither is the base alone.
	if want := "fails on P3: 2 new findings since aaaa111, bbbb222"; err.Error() != want {
		t.Errorf("error = %q, want %q", err, want)
	}

	gate := gateOf(t, out)
	if gate["failOnNew"] != "P3" {
		t.Errorf("failOnNew = %v, want P3", gate["failOnNew"])
	}
	n, ok := gate["new"].(map[string]any)
	if !ok {
		t.Fatalf("new = %v, want the comparison", gate["new"])
	}
	if n["verdict"] != "fail" {
		t.Errorf("verdict = %v, want fail", n["verdict"])
	}
	introduced, _ := n["introduced"].(map[string]any)
	if total := introduced["p1"].(float64) + introduced["p2"].(float64) + introduced["p3"].(float64) + introduced["p4"].(float64); total != 2 {
		t.Errorf("introduced = %v, want the two api findings and nothing from web", introduced)
	}
	baseBlock, _ := n["base"].(map[string]any)
	if _, named := baseBlock["commit"]; named {
		t.Errorf("base.commit = %v, for a base that read two repositories at two revisions", baseBlock["commit"])
	}
	repos, _ := baseBlock["repositories"].([]any)
	if len(repos) != 2 {
		t.Fatalf("base.repositories = %v, want api and web", baseBlock["repositories"])
	}
	// The base's revision, not the head's: api moved to cccc3333 and the base read aaaa1111.
	if first, _ := repos[0].(map[string]any); first["url"] != apiRepo || first["revision"] != "aaaa1111" {
		t.Errorf("base.repositories[0] = %v, want api at the base's revision", repos[0])
	}
}

// The descriptor's gate on new findings applies where no flag is typed, and a band the new findings
// do not reach passes. --no-gate exits 0 on a gate that fails, with the outcome still stated.
func TestTheDescriptorSetsTheGateOnNewFindings(t *testing.T) {
	path := twoComponentSaga(t, "P1")
	s, reg := stagedPair()
	base := scanBase(t, path, reg)
	introduce(s)

	out := t.TempDir()
	if err := runScan(context.Background(), path,
		scanOptions{outputDir: out, noPublish: true, base: base}, reg, &bytes.Buffer{}); err != nil {
		t.Fatalf("no new finding reaches P1, so the run should pass: %v", err)
	}
	gate := gateOf(t, out)
	if gate["failOnNew"] != "P1" {
		t.Errorf("failOnNew = %v, want the descriptor's P1", gate["failOnNew"])
	}
	if n, _ := gate["new"].(map[string]any); n["verdict"] != "pass" {
		t.Errorf("new = %v, want a pass", gate["new"])
	}

	released := t.TempDir()
	if err := runScan(context.Background(), path,
		scanOptions{outputDir: released, noPublish: true, base: base, failOnNew: "low", noGate: true}, reg, &bytes.Buffer{}); err != nil {
		t.Fatalf("--no-gate should exit 0 on a failing gate on new findings: %v", err)
	}
	gate = gateOf(t, released)
	if n, _ := gate["new"].(map[string]any); n["verdict"] != "fail" {
		t.Errorf("new = %v, want the fail stated under --no-gate", gate["new"])
	}
	if gate["disabled"] != true {
		t.Errorf("disabled = %v, want true under --no-gate", gate["disabled"])
	}
}

// A run given a base and a gate on new findings is judged on its change alone: the verdict on the
// screen, the verdict in report.json and the exit status all come from the gate on new findings,
// whatever the whole run's own gate says, and report.json keeps the whole run's outcome beside it.
// The head adds two findings to api and none to web, so the change is in one of two components and
// one of two repositories.
func TestABaseRunIsJudgedOnItsChange(t *testing.T) {
	for _, tc := range []struct {
		name              string
		failOn, failOnNew string
		// err is the whole exit message, empty for a run that exits 0.
		err               string
		verdict, wholeRun string
		header            string
	}{
		{
			name: "the whole run passes and the change fails", failOnNew: "P3",
			err:     "fails on P3: 2 new findings since aaaa111, bbbb222",
			verdict: "fail", wholeRun: "pass",
			header: "DRAUGR  FAIL  shop 1.0  change since aaaa111, bbbb222 · 2 new · fails on P3",
		},
		{
			name: "the whole run fails and the change passes", failOn: "low", failOnNew: "P1",
			verdict: "pass", wholeRun: "fail",
			header: "DRAUGR  PASS  shop 1.0  change since aaaa111, bbbb222 · 2 new · fails on P1",
		},
		{
			name: "both pass", failOnNew: "P1",
			verdict: "pass", wholeRun: "pass",
			header: "DRAUGR  PASS  shop 1.0  change since aaaa111, bbbb222 · 2 new · fails on P1",
		},
		{
			// The whole run's failure decides nothing, so the message names the change alone.
			name: "both fail", failOn: "low", failOnNew: "low",
			err:     "fails on low severity: 2 new findings since aaaa111, bbbb222",
			verdict: "fail", wholeRun: "fail",
			header: "DRAUGR  FAIL  shop 1.0  change since aaaa111, bbbb222 · 2 new · fails on low severity",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := twoComponentSaga(t, "")
			s, reg := stagedPair()
			base := scanBase(t, path, reg)
			introduce(s)

			out := t.TempDir()
			var console bytes.Buffer
			err := runScan(context.Background(), path, scanOptions{
				outputDir: out, noPublish: true, noTips: true, base: base, failOn: tc.failOn, failOnNew: tc.failOnNew,
			}, reg, &console)
			switch {
			case tc.err == "" && err != nil:
				t.Fatalf("exit = %v, want 0", err)
			case tc.err != "" && (err == nil || err.Error() != tc.err):
				t.Fatalf("exit = %v, want %q", err, tc.err)
			}
			if first, _, _ := strings.Cut(console.String(), "\n"); !strings.HasPrefix(first, tc.header) {
				t.Errorf("verdict line = %q, want it to open %q", first, tc.header)
			}
			if verdict := reportVerdict(t, out); verdict != tc.verdict {
				t.Errorf("report.json verdict = %q, want %q, the verdict the exit status came from", verdict, tc.verdict)
			}
			gate := gateOf(t, out)
			if gate["wholeRun"] != tc.wholeRun {
				t.Errorf("gate.wholeRun = %v, want %q", gate["wholeRun"], tc.wholeRun)
			}
			if n, _ := gate["new"].(map[string]any); n["verdict"] != tc.verdict {
				t.Errorf("gate.new = %v, want verdict %q", gate["new"], tc.verdict)
			}
		})
	}
}

// A base with no gate on new findings decides nothing, so the run is judged on the whole of it and
// prints the scan's own report, as it does without a base.
func TestABaseWithNoGateOnNewFindingsJudgesTheWholeRun(t *testing.T) {
	path := twoComponentSaga(t, "")
	s, reg := stagedPair()
	base := scanBase(t, path, reg)
	introduce(s)

	out := t.TempDir()
	var console bytes.Buffer
	err := runScan(context.Background(), path,
		scanOptions{outputDir: out, noPublish: true, noTips: true, base: base, failOn: "low"}, reg, &console)
	if err == nil || err.Error() != "policy verdict: fail" {
		t.Fatalf("exit = %v, want the whole run's policy verdict", err)
	}
	if strings.Contains(console.String(), "change since") || !strings.Contains(console.String(), "CONTROLS") {
		t.Errorf("a run with no gate on new findings printed the change:\n%s", console.String())
	}
	if verdict := reportVerdict(t, out); verdict != "fail" {
		t.Errorf("report.json verdict = %q, want fail", verdict)
	}
	if _, ok := gateOf(t, out)["wholeRun"]; ok {
		t.Error("gate.wholeRun is written on a run the whole run judged")
	}
}

// A judged run names the organization's policy first where it failed too, and a run nothing on
// its change failed exits on the policy alone.
func TestAJudgedRunNamesThePolicyBesideTheChange(t *testing.T) {
	g := baseGate{band: "P2", basePath: "main/results.sarif"}
	c := comparison{findings: &skald.NewFindings{}, tripped: 1}
	for _, tc := range []struct {
		gate         baseGate
		c            comparison
		policyFailed bool
		want         string
	}{
		{g, c, true, "policy verdict: fail, and fails on P2: 1 new finding since main/results.sarif"},
		{g, c, false, "fails on P2: 1 new finding since main/results.sarif"},
		{g, comparison{findings: &skald.NewFindings{}}, true, "policy verdict: fail"},
		{baseGate{}, comparison{}, false, "policy verdict: fail"},
	} {
		if got := tc.gate.failure(tc.c, tc.policyFailed).Error(); got != tc.want {
			t.Errorf("failure = %q, want %q", got, tc.want)
		}
	}
}

// reportVerdict reads the top-level verdict of the report.json written into dir.
func reportVerdict(t *testing.T, dir string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "report.json")) // #nosec G304 -- this test's own temp file
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Verdict string `json:"verdict"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Verdict
}

// A gate on new findings with no base is stated and not applied, with no comparison in the report,
// and the run is judged by its verdict alone.
func TestAGateOnNewFindingsWithNoBaseIsStated(t *testing.T) {
	path := twoComponentSaga(t, "P2")
	_, reg := stagedPair()
	out := t.TempDir()
	if err := runScan(context.Background(), path,
		scanOptions{outputDir: out, noPublish: true}, reg, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	gate := gateOf(t, out)
	if gate["failOnNew"] != "P2" {
		t.Errorf("failOnNew = %v, want P2", gate["failOnNew"])
	}
	if _, ran := gate["new"]; ran {
		t.Errorf("new = %v with no --base", gate["new"])
	}

	var note bytes.Buffer
	baseGate{band: "P2", from: "config.gate.failOnNew"}.noteUnapplied(&note)
	if want := "config.gate.failOnNew is P2 and no --base"; !strings.Contains(note.String(), want) {
		t.Errorf("note = %q, want it to say %q", note.String(), want)
	}
	note.Reset()
	baseGate{band: "P2", from: "--fail-on-new", basePath: "main/results.sarif"}.noteUnapplied(&note)
	baseGate{}.noteUnapplied(&note)
	if note.Len() != 0 {
		t.Errorf("note = %q, for a gate with a base and for no gate at all", note.String())
	}
}

// What is wrong with the gate or the base is said before anything is scanned.
func TestTheBaseAndTheGateAreCheckedBeforeTheScan(t *testing.T) {
	path := twoComponentSaga(t, "")
	_, reg := stagedPair()
	base := scanBase(t, path, reg)

	for name, c := range map[string]struct {
		opts scanOptions
		want string
	}{
		"a threshold in neither vocabulary": {scanOptions{base: base, failOnNew: "urgent"}, "--fail-on-new"},
		"a base that names no file":         {scanOptions{base: filepath.Join(t.TempDir(), "none.sarif")}, "--base"},
		"a base that is not SARIF":          {scanOptions{base: writeFile(t, "report.json", `{"draugr":{},"verdict":"pass"}`)}, "--base"},
		// The base covered both components; a run of one would read every web finding as fixed and
		// compare nothing about web.
		"a base of another scope": {scanOptions{base: base, components: []string{"api"}}, "do not describe the same scan"},
	} {
		t.Run(name, func(t *testing.T) {
			c.opts.noPublish = true
			scanned := false
			counting := engine.NewRegistry()
			counting.RegisterController(repoController{})
			counting.RegisterScanner(&countingScanner{scanned: &scanned})
			err := runScan(context.Background(), path, c.opts, counting, &bytes.Buffer{})
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("err = %v, want it to mention %q", err, c.want)
			}
			if scanned {
				t.Error("the scanners ran before the mistake was reported")
			}
		})
	}
}

// gateSaga is a descriptor whose only gate setting is failOnNew.
func gateSaga(failOnNew string) string {
	return `project: shop
config:
  gate:
    failOnNew: ` + failOnNew + `
components:
  - name: api
    repositories:
      - url: ` + apiRepo + "\n"
}

// diffIn runs `draugr diff` with args from dir, with a configuration file of its own so nothing on
// this machine is read, and returns what it printed and its error.
func diffIn(t *testing.T, dir string, args ...string) (string, error) {
	t.Helper()
	cfg := filepath.Join(t.TempDir(), "draugr.config.yaml")
	if err := os.WriteFile(cfg, []byte("output: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DRAUGR_CONFIG", cfg)
	t.Chdir(dir)
	var out bytes.Buffer
	cmd := newDiffCommand()
	cmd.SetArgs(args)
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	err := cmd.Execute()
	return out.String(), err
}

// putSaga writes a descriptor named name into dir.
func putSaga(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// `draugr diff` applies the descriptor's gate on new findings where no flag names one: the
// descriptor in the working directory, or the one --saga names. A flag replaces it for one run.
func TestDiffReadsTheGateOnNewFindingsFromTheDescriptor(t *testing.T) {
	empty := writeFile(t, "base.sarif", `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Draugr"}},"results":[]}]}`)
	head := writeFile(t, "head.sarif", sarifDoc("CVE-2", "error", "img", "P1"))

	here := t.TempDir()
	putSaga(t, here, "draugr.saga.yaml", gateSaga("P1"))
	if _, err := diffIn(t, here, empty, head); err == nil || !strings.Contains(err.Error(), "differential gate: 1 new finding") {
		t.Errorf("err = %v, want the descriptor's P1 gate tripped", err)
	}
	// The flag asks another question for this run: the new finding is high, not critical.
	if out, err := diffIn(t, here, empty, head, "--fail-on-new", "critical"); err != nil {
		t.Errorf("--fail-on-new critical should replace the descriptor's P1: %v\n%s", err, out)
	}

	elsewhere := t.TempDir()
	named := putSaga(t, t.TempDir(), "shop.saga.yaml", gateSaga("P1"))
	if _, err := diffIn(t, elsewhere, empty, head, "--saga", named); err == nil || !strings.Contains(err.Error(), "differential gate") {
		t.Errorf("err = %v, want the gate of the descriptor --saga names", err)
	}
	// A working directory with no descriptor is a diff that gates nothing, as it always was.
	if out, err := diffIn(t, elsewhere, empty, head); err != nil {
		t.Errorf("no descriptor and no flag should gate nothing: %v\n%s", err, out)
	}
}

// A descriptor somebody named and that is not there, or one that is there and cannot be read, is
// an error. Several in the working directory are read as none, and the diff says so.
func TestDiffSaysWhichDescriptorItCouldNotRead(t *testing.T) {
	empty := writeFile(t, "base.sarif", `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Draugr"}},"results":[]}]}`)
	head := writeFile(t, "head.sarif", sarifDoc("CVE-2", "error", "img", "P1"))

	if _, err := diffIn(t, t.TempDir(), empty, head, "--saga", t.TempDir()); err == nil || !strings.Contains(err.Error(), "--saga: no *.saga.yaml") {
		t.Errorf("err = %v, want a --saga naming nothing refused", err)
	}
	broken := t.TempDir()
	putSaga(t, broken, "draugr.saga.yaml", gateSaga("urgent"))
	if _, err := diffIn(t, broken, empty, head); err == nil || !strings.Contains(err.Error(), "failOnNew") {
		t.Errorf("err = %v, want the unreadable descriptor named rather than skipped", err)
	}

	two := t.TempDir()
	putSaga(t, two, "api.saga.yaml", gateSaga("P1"))
	putSaga(t, two, "web.saga.yaml", gateSaga("P1"))
	out, err := diffIn(t, two, empty, head)
	if err != nil {
		t.Errorf("two descriptors and no flag should gate nothing: %v", err)
	}
	if want := "config.gate.failOnNew not read: the working directory holds 2 descriptors (api.saga.yaml, web.saga.yaml)"; !strings.Contains(out, want) {
		t.Errorf("output does not say %q:\n%s", want, out)
	}
}

// countingScanner records that it was asked to scan.
type countingScanner struct{ scanned *bool }

func (*countingScanner) Info() plugin.ScannerInfo { return plugin.ScannerInfo{Name: "staged"} }

func (c *countingScanner) Scan(context.Context, plugin.Target, plugin.Config) (sarif.Report, error) {
	*c.scanned = true
	return sarif.Report{Tool: "staged"}, nil
}
