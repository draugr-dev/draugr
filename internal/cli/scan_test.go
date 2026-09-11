package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/draugr-dev/draugr/internal/feeds"
	"github.com/draugr-dev/draugr/pkg/config"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/report"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/sbom"
)

// --- fakes ---

type fakeScanner struct{ level sarif.Level }

func (fakeScanner) Info() plugin.ScannerInfo { return plugin.ScannerInfo{Name: "fake"} }
func (f fakeScanner) Scan(_ context.Context, target plugin.Target, _ plugin.Config) (sarif.Report, error) {
	return sarif.Report{Tool: "fake", Results: []sarif.Result{
		{RuleID: "R", Level: f.level, Location: sarif.Location{URI: target.Identity()}},
	}}, nil
}

type fakeController struct{}

func (fakeController) Info() plugin.ControllerInfo {
	return plugin.ControllerInfo{Name: "images", Scope: plugin.ScopeComponent}
}
func (fakeController) Plan(_ saga.Model, comp *saga.Component) ([]plugin.ScanJob, error) {
	if comp == nil {
		return nil, nil
	}
	return []plugin.ScanJob{{Scanner: "fake", Target: plugin.ImageTarget{Ref: comp.Name}}}, nil
}
func (fakeController) Aggregate(reports []sarif.Report) (plugin.ControlResult, error) {
	m := sarif.Merge(reports...)
	c := m.Counts()
	return plugin.ControlResult{Control: "images", Report: m,
		Summary: plugin.Summary{Errors: c.Error, Warnings: c.Warning, Notes: c.Note}}, nil
}

func fakeRegistry(level sarif.Level) *engine.Registry {
	reg := engine.NewRegistry()
	reg.RegisterController(fakeController{})
	reg.RegisterScanner(fakeScanner{level: level})
	return reg
}

type failScanner struct{}

func (failScanner) Info() plugin.ScannerInfo { return plugin.ScannerInfo{Name: "fake"} }
func (failScanner) Scan(context.Context, plugin.Target, plugin.Config) (sarif.Report, error) {
	return sarif.Report{}, errors.New("scan boom")
}

func failingRegistry() *engine.Registry {
	reg := engine.NewRegistry()
	reg.RegisterController(fakeController{})
	reg.RegisterScanner(failScanner{})
	return reg
}

const sagaWithImage = `
project: app
release:
  version: "1.0"
config:
  controllers:
    images:
      enabled: true
components:
  - name: c
    images:
      - image: repo/x:1
`

func writeSaga(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "draugr.saga.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// --- tests ---

func TestValidatePriority(t *testing.T) {
	for _, v := range []string{"", "P1", "p2", "P4"} {
		if _, err := validatePriority("--min-priority", v); err != nil {
			t.Errorf("%q should be valid: %v", v, err)
		}
	}
	if got, _ := validatePriority("--min-priority", "p2"); got != "P2" {
		t.Errorf("validate should upper-case, got %q", got)
	}
	if _, err := validatePriority("--fail-on-priority", "P9"); err == nil {
		t.Error("P9 should be rejected")
	}
}

func TestRunScanMinPriorityListsFindings(t *testing.T) {
	var buf bytes.Buffer
	path := writeSaga(t, sagaWithImage)
	// Unclassified component → treated as public/critical (C1); a note-level finding → P3.
	err := runScan(context.Background(), path,
		scanOptions{failOn: "error", minPriority: "P3", format: "json"}, fakeRegistry(sarif.LevelNote), &buf)
	if err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "\"priorities\"") || !strings.Contains(out, "\"findings\"") {
		t.Errorf("expected priorities + findings with --min-priority:\n%s", out)
	}
	if !strings.Contains(out, "\"P3\"") {
		t.Errorf("expected a P3 finding:\n%s", out)
	}
}

func TestRunScanPublishesConfiguredReports(t *testing.T) {
	dir := t.TempDir()
	saga := `
project: app
release:
  version: "1.0"
config:
  controllers:
    images:
      enabled: true
  reports:
    - format: sarif
    - format: markdown
  publishers:
    - kind: file
      dir: ` + dir + `
components:
  - name: c
    images:
      - image: repo/x:1
`
	path := writeSaga(t, saga)
	err := runScan(context.Background(), path,
		scanOptions{failOn: "error", format: "console"}, fakeRegistry(sarif.LevelNote), &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"results.sarif", "report.md"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("expected publisher to write %s: %v", f, err)
		}
	}
}

func TestRunScanNoPublishSkipsPublishers(t *testing.T) {
	dir := t.TempDir()
	saga := `
project: app
release:
  version: "1.0"
config:
  controllers:
    images:
      enabled: true
  reports:
    - format: sarif
  publishers:
    - kind: file
      dir: ` + dir + `
components:
  - name: c
    images:
      - image: repo/x:1
`
	path := writeSaga(t, saga)
	err := runScan(context.Background(), path,
		scanOptions{failOn: "error", format: "console", noPublish: true}, fakeRegistry(sarif.LevelNote), &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "results.sarif")); !os.IsNotExist(err) {
		t.Errorf("--no-publish should skip publishers; got file (err=%v)", err)
	}
}

func TestRunScanTemplateFormat(t *testing.T) {
	var buf bytes.Buffer
	err := runScan(context.Background(), writeSaga(t, sagaWithImage),
		scanOptions{failOn: "error", format: "template", template: "verdict={{.Verdict}}"},
		fakeRegistry(sarif.LevelNote), &buf)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "verdict=") {
		t.Errorf("expected template output, got %q", buf.String())
	}
}

func TestRunScanTemplateMissingSource(t *testing.T) {
	err := runScan(context.Background(), writeSaga(t, sagaWithImage),
		scanOptions{failOn: "error", format: "template"}, fakeRegistry(sarif.LevelNote), &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "template report requires") {
		t.Fatalf("expected template-source error, got %v", err)
	}
}

func TestRunScanUnknownPublisherErrors(t *testing.T) {
	saga := `
project: app
release:
  version: "1.0"
config:
  controllers:
    images:
      enabled: true
  reports:
    - format: sarif
  publishers:
    - kind: bogus
components:
  - name: c
    images:
      - image: repo/x:1
`
	err := runScan(context.Background(), writeSaga(t, saga),
		scanOptions{failOn: "error", format: "console"}, fakeRegistry(sarif.LevelNote), &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "unknown publisher kind") {
		t.Fatalf("expected unknown publisher error, got %v", err)
	}
}

// A controller for one of the controls zero-config enables, so the synthesized Saga actually
// plans work. fakeRegistry serves `images`, which zero-config does not enable, with only that
// registered, this test was scanning nothing and calling it a pass.
type fakeRepoController struct{}

func (fakeRepoController) Info() plugin.ControllerInfo {
	return plugin.ControllerInfo{Name: "sca", Scope: plugin.ScopeComponent}
}
func (fakeRepoController) Plan(_ saga.Model, comp *saga.Component) ([]plugin.ScanJob, error) {
	if comp == nil {
		return nil, nil
	}
	return []plugin.ScanJob{{Scanner: "fake", Target: plugin.RepositoryTarget{URL: comp.Name}}}, nil
}
func (fakeRepoController) Aggregate(reports []sarif.Report) (plugin.ControlResult, error) {
	m := sarif.Merge(reports...)
	c := m.Counts()
	return plugin.ControlResult{Control: "sca", Report: m,
		Summary: plugin.Summary{Errors: c.Error, Warnings: c.Warning, Notes: c.Note}}, nil
}

func TestRunScanZeroConfigDirectory(t *testing.T) {
	// Pointing scan at a directory synthesizes a default Saga (no file needed) and scans it.
	dir := t.TempDir()
	reg := fakeRegistry(sarif.LevelNote)
	reg.RegisterController(fakeRepoController{})
	var buf bytes.Buffer
	err := runScan(context.Background(), dir, scanOptions{failOn: "error", format: "json"}, reg, &buf)
	if err != nil {
		t.Fatalf("zero-config scan: %v", err)
	}
	if !strings.Contains(buf.String(), "\"verdict\"") {
		t.Errorf("expected a JSON verdict, got:\n%s", buf.String())
	}
}

func TestScanModelSynthesizesForDir(t *testing.T) {
	dir := t.TempDir()
	m, synth, err := scanModel(dir)
	if err != nil || !synth {
		t.Fatalf("dir should synthesize: synth=%v err=%v", synth, err)
	}
	for _, c := range []string{"sca", "secrets", "sast", "iac"} {
		if _, ok := m.Config.Controls[c]; !ok {
			t.Errorf("synthesized Saga missing control %q", c)
		}
	}
	if len(m.Components) != 1 || len(m.Components[0].Repositories) != 1 {
		t.Fatalf("expected one component with one repository: %+v", m.Components)
	}
	if err := m.Validate(); err != nil {
		t.Errorf("synthesized Saga should be valid: %v", err)
	}
}

func TestScanModelLoadsFile(t *testing.T) {
	path := writeSaga(t, sagaWithImage)
	m, synth, err := scanModel(path)
	if err != nil || synth {
		t.Fatalf("file should load (not synthesize): synth=%v err=%v", synth, err)
	}
	if m.Project != "app" {
		t.Errorf("loaded wrong saga: project=%q release=%+v", m.Project, m.Release)
	}
}

func TestRunScanInvalidMinPriority(t *testing.T) {
	err := runScan(context.Background(), writeSaga(t, sagaWithImage),
		scanOptions{failOn: "error", minPriority: "bogus"}, fakeRegistry(sarif.LevelNote), &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "invalid --min-priority") {
		t.Fatalf("expected invalid min-priority error, got %v", err)
	}
}

func TestRunScanNegativeJobs(t *testing.T) {
	err := runScan(context.Background(), writeSaga(t, sagaWithImage),
		scanOptions{failOn: "error", jobs: -3}, fakeRegistry(sarif.LevelNote), &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "--jobs must be >= 0") {
		t.Fatalf("expected --jobs validation error, got %v", err)
	}
}

func TestRunScanJobsSetsConcurrency(t *testing.T) {
	var buf bytes.Buffer
	err := runScan(context.Background(), writeSaga(t, sagaWithImage),
		scanOptions{failOn: "error", jobs: 2, format: "json"}, fakeRegistry(sarif.LevelNote), &buf)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "\"concurrency\": 2") {
		t.Errorf("expected stats.concurrency=2 in output:\n%s", buf.String())
	}
}

func TestRunScanRefusesAThresholdInNeitherVocabulary(t *testing.T) {
	err := runScan(context.Background(), writeSaga(t, sagaWithImage),
		scanOptions{failOn: "bogus"}, fakeRegistry(sarif.LevelNote), &bytes.Buffer{})
	if err == nil {
		t.Fatal("a word that is neither a band nor a severity was accepted")
	}
	// Both vocabularies named. Somebody who wrote a word in neither cannot tell, from a message
	// about one of them, whether they misspelled a band or reached for a severity.
	for _, want := range []string{"P1", "critical"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("message does not offer %q: %v", want, err)
		}
	}
}

// TestTheOlderSpellingStillResolves: --fail-on-priority is deprecated, not removed. A pipeline that
// predates the merge keeps working, because the moving tag on the action means our release is what
// would break it rather than their upgrade.
func TestTheOlderSpellingStillResolves(t *testing.T) {
	path := writeSaga(t, sagaWithImage)
	// A warning is P2 on an unclassified component, so the older flag still decides the verdict.
	if err := runScan(context.Background(), path, scanOptions{failOnPriority: "P2"},
		fakeRegistry(sarif.LevelWarning), &bytes.Buffer{}); err == nil {
		t.Error("--fail-on-priority P2 no longer gates")
	}
	// And the same band written the new way gives the same answer.
	if err := runScan(context.Background(), path, scanOptions{failOn: "P2"},
		fakeRegistry(sarif.LevelWarning), &bytes.Buffer{}); err == nil {
		t.Error("--fail-on P2 does not gate on a band")
	}
}

func TestRunScanFailsWhenAControlCouldNotRun(t *testing.T) {
	// A control that couldn't run didn't find nothing. It found out nothing. Reporting that as a
	// pass makes the gate a false negative precisely where it matters, so it fails by default.
	var buf bytes.Buffer
	err := runScan(context.Background(), writeSaga(t, sagaWithImage),
		scanOptions{failOn: "error"}, failingRegistry(), &buf)
	if err == nil {
		t.Fatal("a scan that could not run should not pass the gate")
	}
	if !strings.Contains(err.Error(), "scan incomplete") {
		t.Errorf("the error should say the scan was incomplete, not that a policy failed: %v", err)
	}
	// And it must say how to opt out, or the only way past it is guesswork.
	if !strings.Contains(err.Error(), "--allow-scan-errors") {
		t.Errorf("the error should name the opt-out: %v", err)
	}
	if !strings.Contains(buf.String(), "ERROR") {
		t.Errorf("the report should name the control that failed:\n%s", buf.String())
	}
}

func TestRunScanAllowsIncompleteScansOnRequest(t *testing.T) {
	// Best-effort scanning stays available. But the report still says a control errored, so the
	// opt-out buys a passing exit code, not silence.
	var buf bytes.Buffer
	err := runScan(context.Background(), writeSaga(t, sagaWithImage),
		scanOptions{failOn: "error", allowScanErrors: true}, failingRegistry(), &buf)
	if err != nil {
		t.Fatalf("--allow-scan-errors should not fail the gate, got %v", err)
	}
	if !strings.Contains(buf.String(), "Draugr · PASS") {
		t.Errorf("expected pass verdict:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "ERROR") {
		t.Errorf("the errored control should still be named:\n%s", buf.String())
	}
}

func TestWriteArtifactsMkdirError(t *testing.T) {
	// Point the output dir under a regular file so MkdirAll fails.
	f := filepath.Join(t.TempDir(), "afile")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := runScan(context.Background(), writeSaga(t, sagaWithImage),
		scanOptions{failOn: "error", outputDir: filepath.Join(f, "sub")}, fakeRegistry(sarif.LevelNote), &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected an error creating the output directory under a file")
	}
}

func TestRunScanFailOnPriority(t *testing.T) {
	path := writeSaga(t, sagaWithImage)
	// A warning finding is below a severity gate set to error, and on an unclassified component it
	// ranks P2. Each gate is asked on its own, because a run only ever asks one.
	severity := scanOptions{failOn: "error"}
	if err := runScan(context.Background(), path, severity, fakeRegistry(sarif.LevelWarning), &bytes.Buffer{}); err != nil {
		t.Fatalf("a warning should pass a gate set to error: %v", err)
	}
	priority := scanOptions{failOnPriority: "P2"}
	if err := runScan(context.Background(), path, priority, fakeRegistry(sarif.LevelWarning), &bytes.Buffer{}); err == nil {
		t.Fatal("expected fail: a P2 finding should trip --fail-on-priority P2")
	}
}

// TestTheDefaultGateIsTheBandRatherThanTheSeverity is the behavior change stated where somebody
// running the command would meet it.
func TestTheDefaultGateIsTheBandRatherThanTheSeverity(t *testing.T) {
	path := writeSaga(t, sagaWithImage)
	// Nothing named. An unclassified component ranks at the most exposed tier, where an error-level
	// finding is P1, so the default gate catches it — the same answer `--fail-on high` used to
	// give, arrived at by asking the other question.
	err := runScan(context.Background(), path, scanOptions{}, fakeRegistry(sarif.LevelError), &bytes.Buffer{})
	if err == nil {
		t.Error("the default gate let an unclassified error-level finding through")
	}
	// And a warning on the same component is P2, which the default does not catch.
	if err := runScan(context.Background(), path, scanOptions{},
		fakeRegistry(sarif.LevelWarning), &bytes.Buffer{}); err != nil {
		t.Errorf("the default gate failed on a P2: %v", err)
	}
}

// TestBothGatesTogetherIsRefused holds the flags to the rule the descriptor is held to. Silently
// letting one win would leave somebody who passed both with no way to tell which did nothing.
func TestBothGatesTogetherIsRefused(t *testing.T) {
	both := scanOptions{failOn: "high", failOnPriority: "P1"}
	err := runScan(context.Background(), writeSaga(t, sagaWithImage), both,
		fakeRegistry(sarif.LevelNote), &bytes.Buffer{})
	if err == nil {
		t.Fatal("both gates were accepted")
	}
	for _, want := range []string{"--fail-on", "--fail-on-priority", "one"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("message does not mention %q: %v", want, err)
		}
	}
}

func TestLoadExploitSource(t *testing.T) {
	if src, _, err := loadExploitSource(context.Background(), exploitability{}); err != nil || src != nil {
		t.Fatalf("no files should yield nil source, got %v %v", src, err)
	}
	kev := filepath.Join(t.TempDir(), "kev.json")
	if err := os.WriteFile(kev, []byte(`{"vulnerabilities":[{"cveID":"CVE-2021-44228"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	src, _, err := loadExploitSource(context.Background(), exploitability{kev: kev, threshold: 0.5, maxAge: feeds.DefaultMaxAge})
	if err != nil || src == nil || src.Empty() {
		t.Fatalf("kev file should yield a non-empty source, got %v %v", src, err)
	}
	if _, _, err := loadExploitSource(context.Background(), exploitability{kev: filepath.Join(t.TempDir(), "nope.json"), maxAge: feeds.DefaultMaxAge}); err == nil {
		t.Error("missing --kev file should error")
	}
	if _, _, err := loadExploitSource(context.Background(), exploitability{epss: filepath.Join(t.TempDir(), "nope.csv"), maxAge: feeds.DefaultMaxAge}); err == nil {
		t.Error("missing --epss file should error")
	}
}

func TestRunScanBadKEVFileErrors(t *testing.T) {
	err := runScan(context.Background(), writeSaga(t, sagaWithImage),
		scanOptions{failOn: "error", kevFile: "/nonexistent/kev.json"}, fakeRegistry(sarif.LevelNote), &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "--kev") {
		t.Fatalf("expected --kev open error, got %v", err)
	}
}

func TestRunScanFail(t *testing.T) {
	var buf bytes.Buffer
	path := writeSaga(t, sagaWithImage)
	err := runScan(context.Background(), path, scanOptions{failOn: "error"}, fakeRegistry(sarif.LevelError), &buf)
	if err == nil {
		t.Fatal("expected fail verdict to return an error")
	}
	if !strings.Contains(buf.String(), "Draugr · FAIL") {
		t.Errorf("report should show fail verdict:\n%s", buf.String())
	}
}

func TestRunScanPass(t *testing.T) {
	var buf bytes.Buffer
	path := writeSaga(t, sagaWithImage)
	// Findings at note level, threshold error → pass.
	err := runScan(context.Background(), path, scanOptions{failOn: "error"}, fakeRegistry(sarif.LevelNote), &buf)
	if err != nil {
		t.Fatalf("expected pass, got %v", err)
	}
	if !strings.Contains(buf.String(), "Draugr · PASS") {
		t.Errorf("report should show pass:\n%s", buf.String())
	}
}

func TestRunScanWritesArtifacts(t *testing.T) {
	dir := t.TempDir()
	path := writeSaga(t, sagaWithImage)
	err := runScan(context.Background(), path,
		scanOptions{failOn: "error", outputDir: dir}, fakeRegistry(sarif.LevelNote), &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"report.json", "results.sarif"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("expected artifact %s: %v", f, err)
		}
	}
}

func TestRunScanWithCache(t *testing.T) {
	dir := t.TempDir()
	path := writeSaga(t, sagaWithImage)
	opts := scanOptions{failOn: "error", cacheDir: filepath.Join(dir, "cache")}
	if err := runScan(context.Background(), path, opts, fakeRegistry(sarif.LevelNote), &bytes.Buffer{}); err != nil {
		t.Fatalf("run with cache: %v", err)
	}
	// Cache directory should have been created and populated.
	entries, err := os.ReadDir(filepath.Join(dir, "cache"))
	if err != nil || len(entries) == 0 {
		t.Fatalf("expected cache entries, err=%v entries=%d", err, len(entries))
	}
}

func TestRunScanLoadError(t *testing.T) {
	err := runScan(context.Background(), "/no/such/saga.yaml", scanOptions{failOn: "error"},
		fakeRegistry(sarif.LevelNote), &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected load error")
	}
}

func TestScanCommandViaCobra(t *testing.T) {
	// No components → no jobs → nothing was checked, which must not read as a pass. A descriptor
	// that scans nothing is far more often unfinished than genuinely empty, and a clean verdict
	// renders the two identically.
	path := writeSaga(t, "project: app\nrelease:\n  version: \"1.0\"\n")
	cmd := newRootCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"scan", path})
	if err := cmd.Execute(); err == nil {
		t.Fatalf("a scan that checked nothing must not succeed:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "no controls ran") {
		t.Errorf("the output should say nothing was checked:\n%s", out.String())
	}
}

func TestWriteArtifactsWritesSBOMs(t *testing.T) {
	// -o is the path most CI jobs use; an SBOM reachable only through a configured publisher
	// would be missing from exactly the evidence bundle people archive.
	dir := t.TempDir()
	run := engine.Result{SBOMs: []sbom.Document{
		{Component: "web", Target: "https://git/web", Format: saga.SBOMSPDXJSON, Bytes: []byte(`{"spdxVersion":"SPDX-2.3"}`)},
		{Component: "api", Target: "api:1", Format: saga.SBOMCycloneDXJSON, Bytes: []byte(`{"bomFormat":"CycloneDX"}`)},
	}}
	if err := writeArtifacts(dir, nil, report.Data{}, saga.Release{Version: "1"}, run, norn.Result{Verdict: norn.Pass}, "", ""); err != nil {
		t.Fatalf("writeArtifacts: %v", err)
	}
	for name, want := range map[string]string{
		"sbom-web-https-git-web.spdx.json": `"spdxVersion"`,
		"sbom-api-api-1.cdx.json":          `"bomFormat"`,
	} {
		b, err := os.ReadFile(filepath.Join(dir, name)) //nolint:gosec // test-controlled path under t.TempDir
		if err != nil {
			t.Errorf("expected %s: %v", name, err)
			continue
		}
		if !strings.Contains(string(b), want) {
			t.Errorf("%s does not contain %s: %s", name, want, b)
		}
	}
	// The usual artifacts still land alongside them.
	for _, f := range []string{"report.json", "results.sarif"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("expected %s: %v", f, err)
		}
	}
}

// A directory holding a descriptor is not a directory to scan zero-config. Ignoring it discarded
// the controls chosen, the components declared, and the exposure and criticality that drive
// prioritization, silently, and while telling the reader to create the file they already had.
func TestScanUsesTheDescriptorInTheDirectory(t *testing.T) {
	dir := t.TempDir()
	saga := "project: real\nrelease:\n  version: \"2.0\"\nconfig:\n  controllers:\n    images: {enabled: true}\n" +
		"components:\n  - name: web\n    images: [{image: \"nginx:1\"}]\n"
	if err := os.WriteFile(filepath.Join(dir, "draugr.saga.yaml"), []byte(saga), 0o600); err != nil {
		t.Fatal(err)
	}

	m, synthesized, err := scanModel(dir)
	if err != nil {
		t.Fatal(err)
	}
	if synthesized {
		t.Fatal("a directory with a descriptor must not be scanned zero-config")
	}
	if m.Project != "real" {
		t.Errorf("project = %q, want the descriptor's", m.Project)
	}
	// The controls it declares, not the zero-config four.
	if !m.Config.ControllerEnabled("images") || m.Config.ControllerEnabled("sca") {
		t.Errorf("controls came from the wrong place: %+v", m.Config.Controls)
	}
}

// The reason a descriptor was skipped has to be reported. Falling back to zero-config would
// reproduce the bug with an extra step: a broken descriptor and a green scan.
func TestABrokenDescriptorFailsRatherThanFallingBack(t *testing.T) {
	dir := t.TempDir()
	// The typo that surfaced this: a misspelled component key.
	broken := "project: app\nrelease:\n  version: \"1.0\"\ncomponents:\n  - namfe: web\n"
	if err := os.WriteFile(filepath.Join(dir, "draugr.saga.yaml"), []byte(broken), 0o600); err != nil {
		t.Fatal(err)
	}

	_, synthesized, err := scanModel(dir)
	if err == nil {
		t.Fatal("a descriptor that cannot be read must fail the scan")
	}
	if synthesized {
		t.Error("falling back to zero-config would hide the reason it was skipped")
	}
	if !strings.Contains(err.Error(), "namfe") {
		t.Errorf("the error should name the problem, got: %v", err)
	}
}

// Zero-config still applies where there is nothing to honor. That is what it is for.
func TestScanStaysZeroConfigWithoutADescriptor(t *testing.T) {
	dir := t.TempDir()
	m, synthesized, err := scanModel(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !synthesized {
		t.Fatal("a bare directory should still be scanned zero-config")
	}
	if !m.Config.ControllerEnabled("sca") {
		t.Errorf("zero-config controls missing: %+v", m.Config.Controls)
	}
}

// A directory named the same as the descriptor is not a descriptor.
func TestADirectoryNamedLikeTheDescriptorIsIgnored(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "draugr.saga.yaml"), 0o750); err != nil {
		t.Fatal(err)
	}
	if _, synthesized, err := scanModel(dir); err != nil || !synthesized {
		t.Errorf("want zero-config, got synthesized=%v err=%v", synthesized, err)
	}
}

func TestRunScanReportsTheVerdictAheadOfAPublisherFailure(t *testing.T) {
	// A run that both failed its gate and could not publish is two facts, and only one can be the
	// exit message. Naming the publisher sends a reader to fix a token when what actually happened
	// is that the build should not ship, so the verdict leads and the publisher follows it, rather
	// than replacing it.
	saga := `
project: app
release:
  version: "1.0"
config:
  controllers:
    images:
      enabled: true
  reports:
    - format: sarif
  publishers:
    - kind: bogus
components:
  - name: c
    images:
      - image: repo/x:1
`
	err := runScan(context.Background(), writeSaga(t, saga),
		scanOptions{failOn: "error", format: "console"}, fakeRegistry(sarif.LevelError), &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected an error: the gate failed and the publisher failed")
	}
	if !strings.Contains(err.Error(), "policy verdict: fail") {
		t.Errorf("the verdict must lead the message, got %v", err)
	}
	if !strings.Contains(err.Error(), "unknown publisher kind") {
		t.Errorf("the publishing failure must survive in the message, got %v", err)
	}
}

func TestAlsoPublishKeepsTheOutcomeAloneWhenPublishingWorked(t *testing.T) {
	outcome := errors.New("policy verdict: fail")
	if got := alsoPublish(outcome, nil); got != outcome {
		t.Errorf("got %v, want the outcome unchanged", got)
	}
}

func TestAlsoPublishWrapsBothSoEitherCanBeMatched(t *testing.T) {
	outcome, pub := errors.New("scan incomplete"), errors.New("no token")
	err := alsoPublish(outcome, pub)
	if !errors.Is(err, outcome) || !errors.Is(err, pub) {
		t.Errorf("both causes should be reachable with errors.Is: %v", err)
	}
}

func TestRunScanAllowScanErrorsCannotPassAScanThatDidNothing(t *testing.T) {
	// The hole #439 closed, reopened by the flag the error message itself recommended: a
	// descriptor enabling no control produced (planning) "no controls ran", and
	// --allow-scan-errors turned that into a green PASS over a scan that checked nothing.
	saga := `
project: app
release:
  version: "1.0"
components:
  - name: c
    repositories:
      - url: https://github.com/acme/x.git
`
	path := writeSaga(t, saga)
	for _, allow := range []bool{false, true} {
		err := runScan(context.Background(), path,
			scanOptions{failOn: "error", format: "console", allowScanErrors: allow},
			fakeRegistry(sarif.LevelNote), &bytes.Buffer{})
		if err == nil {
			t.Fatalf("allowScanErrors=%v: a scan that ran no control must not pass", allow)
		}
		if !strings.Contains(err.Error(), "scan incomplete") {
			t.Errorf("allowScanErrors=%v: got %v", allow, err)
		}
	}
}

func TestRunScanStillOffersTheFlagForARealScannerFailure(t *testing.T) {
	// The flag has to keep working for what it is actually for, and keep being suggested there.
	saga := `
project: app
release:
  version: "1.0"
config:
  controllers:
    images:
      enabled: true
components:
  - name: c
    images:
      - image: repo/x:1
`
	path := writeSaga(t, saga)
	reg := failingRegistry()
	err := runScan(context.Background(), path,
		scanOptions{failOn: "error", format: "console"}, reg, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "--allow-scan-errors to accept partial") {
		t.Fatalf("a failed scanner should still point at the flag, got %v", err)
	}
	if err := runScan(context.Background(), path,
		scanOptions{failOn: "error", format: "console", allowScanErrors: true},
		reg, &bytes.Buffer{}); err != nil {
		t.Errorf("the flag should still accept a failed scanner, got %v", err)
	}
}

func TestSplitScanErrorsKeepsSBOMWaivable(t *testing.T) {
	// A missing SBOM is missing evidence, not a missing check: the controls ran and their
	// verdict still means something, so the flag continues to accept it.
	unwaived, waived := splitScanErrors(map[string][]string{
		"(planning)": {"no controls ran"},
		"(sbom)":     {"syft failed"},
		"sca":        {"trivy failed"},
	})
	if !slices.Equal(unwaived, []string{"(planning)"}) {
		t.Errorf("unwaived = %v, want only (planning)", unwaived)
	}
	if !slices.Equal(waived, []string{"(sbom)", "sca"}) {
		t.Errorf("waived = %v, want (sbom) and sca", waived)
	}
}

func TestComponentVerdictsJudgeEachComponentByTheSamePolicy(t *testing.T) {
	// Not a second implementation of the gate. Reproducing "what counts as failing" in the reporter
	// is how the parts come to disagree with the whole, a component reading PASS under a headline
	// that says FAIL.
	policy := norn.Policy{FailOn: sarif.SeverityHigh}
	model := &saga.Model{Components: []saga.Component{{Name: "payments"}, {Name: "internal-tool"}}}
	reports := map[string]sarif.Report{
		"sca": {Tool: "trivy", Results: []sarif.Result{
			{RuleID: "CVE-1", Level: sarif.LevelError, Component: "payments", Priority: "P1"},
			{RuleID: "CVE-2", Level: sarif.LevelNote, Component: "internal-tool", Priority: "P4"},
		}},
		"infrastructure": {Tool: "draugr-k8s-policies", Results: []sarif.Result{
			{RuleID: "cis/5.1.1", Level: sarif.LevelWarning}, // project-scoped: no component
		}},
	}
	got, unattributed := componentVerdicts(policy, model, reports, engine.Scope{}, nil)
	if len(got) != 2 {
		t.Fatalf("want a row per declared component, got %d", len(got))
	}
	if got[0].Name != "payments" || got[0].Verdict != norn.Fail {
		t.Errorf("the failing component should lead: %+v", got[0])
	}
	if got[0].Priorities[0] != 1 || !slices.Equal(got[0].Controls, []string{"sca"}) {
		t.Errorf("payments: %+v", got[0])
	}
	if got[1].Name != "internal-tool" || got[1].Verdict != norn.Pass {
		t.Errorf("a component below the threshold passes: %+v", got[1])
	}
	if unattributed != 1 {
		t.Errorf("unattributed = %d, want the project-scoped finding counted", unattributed)
	}
}

func TestComponentVerdictsIncludeAComponentWithNoFindings(t *testing.T) {
	// Building the list from the findings drops exactly the component a reader most wants to see.
	// The clean one they can take back to their team.
	policy := norn.Policy{FailOn: sarif.SeverityHigh}
	model := &saga.Model{Components: []saga.Component{{Name: "a"}, {Name: "quiet"}}}
	reports := map[string]sarif.Report{"sca": {Results: []sarif.Result{
		{RuleID: "x", Level: sarif.LevelError, Component: "a"},
	}}}
	got, _ := componentVerdicts(policy, model, reports, engine.Scope{}, nil)
	if len(got) != 2 {
		t.Fatalf("got %d rows, want both components", len(got))
	}
	quiet := got[1]
	if quiet.Name != "quiet" || quiet.Verdict != norn.Pass || quiet.Findings != 0 {
		t.Errorf("the clean component should be present and passing: %+v", quiet)
	}
}

func TestComponentVerdictsSkipSuppressedFindings(t *testing.T) {
	// The counts skip these, so the breakdown must too, or the parts and the whole disagree.
	policy := norn.Policy{FailOn: sarif.SeverityHigh}
	model := &saga.Model{Components: []saga.Component{{Name: "a"}, {Name: "b"}}}
	reports := map[string]sarif.Report{"sca": {Results: []sarif.Result{
		{RuleID: "x", Level: sarif.LevelError, Component: "a",
			Suppression: &sarif.Suppression{Kind: "external", Justification: "accepted"}},
	}}}
	got, _ := componentVerdicts(policy, model, reports, engine.Scope{}, nil)
	if got[0].Findings != 0 || got[0].Verdict != norn.Pass {
		t.Errorf("a suppressed finding must not fail its component: %+v", got[0])
	}
}

func TestComponentVerdictsAreAbsentForOneComponent(t *testing.T) {
	policy := norn.Policy{FailOn: sarif.SeverityHigh}
	model := &saga.Model{Components: []saga.Component{{Name: "only"}}}
	if got, _ := componentVerdicts(policy, model, nil, engine.Scope{}, nil); got != nil {
		t.Errorf("nothing to tell apart: %+v", got)
	}
}

func TestFormatRejectsDocumentFormats(t *testing.T) {
	// The complaint this fixes: `--format html` dumped four thousand lines of styled document
	// into a terminal. It is not a printable format, so it is not one --format offers.
	for _, f := range []string{"html", "junit"} {
		err := report.StreamFormat(f)
		if err == nil {
			t.Errorf("--format %s was accepted", f)
			continue
		}
		// The error has to say where the format *did* go, or it reads as a capability removed.
		if !strings.Contains(err.Error(), "--report "+f) {
			t.Errorf("%s: error does not point at --report: %v", f, err)
		}
	}
}

func TestFormatAcceptsWhatAPersonMightRead(t *testing.T) {
	for _, f := range []string{"console", "markdown", "json", "sarif", "template"} {
		if err := report.StreamFormat(f); err != nil {
			t.Errorf("--format %s should be allowed: %v", f, err)
		}
	}
	if err := report.StreamFormat("nonsense"); err == nil {
		t.Error("an unknown format was accepted")
	}
}

func TestWriteArtifactsHonorsReportFormats(t *testing.T) {
	dir := t.TempDir()
	data := report.Data{Release: saga.Release{Version: "1"}}
	err := writeArtifacts(dir, []string{"html", "markdown"}, data,
		saga.Release{Version: "1"}, engine.Result{}, norn.Result{Verdict: norn.Pass}, "", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"report.html", "report.md"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s not written: %v", name, err)
		}
	}
	// Only what was asked for. Writing json and sarif anyway would make --report advisory.
	if _, err := os.Stat(filepath.Join(dir, "report.json")); err == nil {
		t.Error("report.json written despite --report naming other formats")
	}
}

func TestWriteArtifactsDefaultsToWhatPipelinesExpect(t *testing.T) {
	dir := t.TempDir()
	err := writeArtifacts(dir, nil, report.Data{}, saga.Release{Version: "1"},
		engine.Result{}, norn.Result{Verdict: norn.Pass}, "", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"report.json", "results.sarif"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("-o alone should still write %s: %v", name, err)
		}
	}
}

func TestDigestPinnedOnly(t *testing.T) {
	// A tag is a name, not content: rebuild and re-push and the key is unchanged while the image
	// is not. Everything else Draugr scans is content-addressed already.
	if digestPinnedOnly(plugin.ImageTarget{Ref: "acme/api:latest"}) {
		t.Error("a tag-only image was allowed into the cache")
	}
	if !digestPinnedOnly(plugin.ImageTarget{Ref: "acme/api:latest", Digest: "sha256:abc"}) {
		t.Error("a digest-pinned image was refused")
	}
	// Repositories and hosts are not mutable behind our back in the same way.
	if !digestPinnedOnly(plugin.RepositoryTarget{URL: "https://git/x"}) {
		t.Error("a repository was refused")
	}
}

func TestToolBuildsUsesTheRegistryNotTheDriverName(t *testing.T) {
	// A finding's Tool is the SARIF driver name the tool gives itself, "Trivy" for trivy-fs, so
	// deriving the list from findings finds nothing. It comes from Result.Scanners, which are the
	// names Draugr selected.
	got := toolBuilds(t.Context(), engine.Result{Scanners: []string{"trivy-fs", "gitleaks"}})
	names := map[string]bool{}
	for _, b := range got {
		names[b.Name] = true
	}
	if !names["trivy"] || !names["gitleaks"] {
		t.Errorf("expected the executables behind those scanners, got %+v", got)
	}
	// Every entry says something either way: verified, or why not.
	for _, b := range got {
		if b.Level != "pinned" && b.Level != "signed" && b.Reason == "" {
			t.Errorf("%s is unverified without a reason", b.Name)
		}
	}
}

func TestToolBuildsSkipsNativeScanners(t *testing.T) {
	// Their rules ship in this binary, so "which build" is answered by Draugr's own version,
	// which the report already stamps. Listing them would pad the evidence with nothing.
	if got := toolBuilds(t.Context(), engine.Result{Scanners: []string{"draugr-headers", "draugr-tls"}}); got != nil {
		t.Errorf("native scanners were listed as external tools: %+v", got)
	}
	if got := toolBuilds(t.Context(), engine.Result{}); got != nil {
		t.Errorf("a run that used nothing listed something: %+v", got)
	}
}

func TestToolBuildsIgnoresUnknownScanners(t *testing.T) {
	// A name no scanner answers to cannot have an executable behind it.
	if got := toolBuilds(t.Context(), engine.Result{Scanners: []string{"not-a-scanner"}}); got != nil {
		t.Errorf("got %+v", got)
	}
}

func TestWriteArtifactsUsesTheSameNamesAPublisherWould(t *testing.T) {
	// -o and a publisher have to write a format under one name. When they disagree, a CI step
	// globbing for the file finds nothing, and the common ones warn rather than fail, so the run
	// stays green with no results in it.
	dir := t.TempDir()
	formats := []string{"json", "sarif", "html", "markdown", "junit"}
	err := writeArtifacts(dir, formats, report.Data{Release: saga.Release{Version: "1"}},
		saga.Release{Version: "1"}, engine.Result{}, norn.Result{Verdict: norn.Pass}, "", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range formats {
		if _, err := os.Stat(filepath.Join(dir, report.Filename(f))); err != nil {
			t.Errorf("%s: %s not written: %v", f, report.Filename(f), err)
		}
	}
}

// TestWriteArtifactsRecordsTheGateInReportJSON holds the -o path to the same policy the reporters
// use. It writes report.json through skald directly rather than through the reporter, so it is the
// one path that can silently omit a block every other path carries.
func TestWriteArtifactsRecordsTheGateInReportJSON(t *testing.T) {
	dir := t.TempDir()
	data := report.Data{
		Release: saga.Release{Version: "1"},
		// One question, so one field. A severity gate here, and the band absent rather than empty.
		Gate: report.GateSettings{Threshold: sarif.SeverityCritical},
	}
	err := writeArtifacts(dir, []string{"json"}, data, saga.Release{Version: "1"},
		engine.Result{}, norn.Result{Verdict: norn.Pass}, "", "")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, report.Filename("json"))) //#nosec G304 -- under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Gate struct {
			Threshold      string `json:"threshold"`
			FailOnPriority string `json:"failOnPriority"`
		} `json:"gate"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Gate.Threshold != "critical" || doc.Gate.FailOnPriority != "" {
		t.Errorf("gate = %+v, want the policy -o was given", doc.Gate)
	}
}

func TestNoGateSuppressesTheVerdictButNotAFailedScan(t *testing.T) {
	// The flag exists for the two scans either side of a `draugr diff`: their job is to produce
	// reports, and the diff is the gate. `|| true` in a pipeline would do it, but it also swallows
	// a scan that never ran. And then the diff fails on a file that was never written, which reads
	// as a diff problem rather than a scan one.
	if !strings.Contains(newScanCommand().Flags().Lookup("no-gate").Usage, "diff") {
		t.Error("the flag's help should say what it is for")
	}
}

func TestWorkingTreeRefusesARemoteRatherThanScanningSomethingElse(t *testing.T) {
	// A remote has no working tree. Falling back to the committed revision would produce a report
	// that looks like the one asked for and describes something else, and the reason to ask is
	// precisely that you want to see work that is not committed yet.
	model := &saga.Model{Components: []saga.Component{{
		Name:         "web",
		Repositories: []saga.Repository{{URL: "https://example.test/web.git"}},
	}}}
	err := checkWorkingTree(true, model)
	if err == nil {
		t.Fatal("a remote was accepted")
	}
	if !strings.Contains(err.Error(), "example.test") {
		t.Errorf("the error should name the repository: %v", err)
	}

	// A local path is fine, and so is not passing the flag at all.
	local := &saga.Model{Components: []saga.Component{{
		Name: "web", Repositories: []saga.Repository{{URL: "."}},
	}}}
	if err := checkWorkingTree(true, local); err != nil {
		t.Errorf("a local checkout was refused: %v", err)
	}
	if err := checkWorkingTree(false, model); err != nil {
		t.Errorf("the check fired without the flag: %v", err)
	}
	if err := checkWorkingTree(true, nil); err != nil {
		t.Errorf("no descriptor is not an error here: %v", err)
	}
}

func TestCacheSettingsComeFromConfigUnlessTyped(t *testing.T) {
	cfg := config.CacheSettings{
		Dir: "/from/config", TTL: 2 * time.Hour, ReadOnly: true, RequireDigest: true,
	}

	// Nothing typed: the config decides.
	opts := scanOptions{cacheTTL: 24 * time.Hour, setFlags: map[string]bool{}}
	cacheOptionsFrom(&opts, cfg)
	if opts.cacheDir != "/from/config" || opts.cacheTTL != 2*time.Hour ||
		!opts.cacheReadOnly || !opts.cacheRequireDigest {
		t.Errorf("config was not applied: %+v", opts)
	}

	// Typed: the flag wins, including when what was typed is a zero value. `--cache-ttl 0` means
	// no expiry, deliberately, and must not read as absent and be overridden.
	opts = scanOptions{
		cacheDir: "/from/flag", cacheTTL: 0,
		setFlags: map[string]bool{"cache-dir": true, "cache-ttl": true},
	}
	cacheOptionsFrom(&opts, cfg)
	if opts.cacheDir != "/from/flag" {
		t.Errorf("cacheDir = %q, want the typed flag", opts.cacheDir)
	}
	if opts.cacheTTL != 0 {
		t.Errorf("an explicit --cache-ttl 0 was overridden with %v", opts.cacheTTL)
	}

	// An explicit --cache-read-only=false is honored over a config that says true, because it
	// was typed. Booleans otherwise only ever turn on.
	opts = scanOptions{setFlags: map[string]bool{"cache-read-only": true}}
	cacheOptionsFrom(&opts, cfg)
	if opts.cacheReadOnly {
		t.Error("an explicit --cache-read-only=false was overridden by the config")
	}
}

// A tool Draugr installed is identified from its install record; one the operator brought has no
// record, so it had no version. And that is the case this whole section exists for. Without it
// the report says only that Draugr did not install the tool, which is a fact about Draugr rather
// than about the run, and nothing can be reproduced from it.
func TestAnExternalToolStillNamesItsBuild(t *testing.T) {
	// `go` is on PATH wherever these tests run and reports a version, which makes it a stand-in
	// for any tool the operator brought: Draugr has no install record for it either.
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no go on PATH")
	}
	if got := probeVersion(t.Context(), "go"); got != "" {
		t.Logf("probed go version: %q", got)
	}
	// A binary Draugr has never heard of has nothing to ask, and must not error or hang.
	if got := probeVersion(t.Context(), "definitely-not-a-tool"); got != "" {
		t.Errorf("probeVersion for an unknown binary = %q, want empty", got)
	}
}

// The two priority knobs do different things, and the difference is the whole design.
//
// --min-priority trims what is printed and leaves every file complete, because a file that
// silently omits findings is read by the next tool as a scan that did not find them. `draugr
// diff` would call each one fixed. A band declared on the report, or asked for explicitly, is a
// decision somebody recorded, and the artifact then states it.
func TestArtifactsAreCompleteUnlessNarrowingWasDeclared(t *testing.T) {
	run := engine.Result{Controls: map[string]plugin.ControlResult{
		"sca": {Report: sarif.Report{Results: []sarif.Result{
			{RuleID: "URGENT", Level: sarif.LevelError, Priority: "P1", Message: "act now"},
			{RuleID: "LATER", Level: sarif.LevelWarning, Priority: "P3", Message: "backlog"},
		}}},
	}}
	verdict := norn.Result{Verdict: norn.Fail}
	data := report.Data{Run: run, Verdict: verdict}

	count := func(t *testing.T, dir string) (int, string) {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(dir, "results.sarif")) //#nosec G304 -- under t.TempDir()
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Runs []struct {
				Results    []struct{} `json:"results"`
				Properties struct {
					Provenance []struct {
						Tool   string            `json:"tool"`
						Fields map[string]string `json:"fields"`
					} `json:"draugr/provenance"`
				} `json:"properties"`
			} `json:"runs"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		n, band := 0, ""
		for _, r := range doc.Runs {
			n += len(r.Results)
			for _, p := range r.Properties.Provenance {
				if p.Tool == "draugr/min-priority" {
					band = p.Fields["band"]
				}
			}
		}
		return n, band
	}

	// --min-priority alone: the file keeps everything and claims no narrowing.
	whole := t.TempDir()
	if err := writeArtifacts(whole, []string{"sarif"}, data, saga.Release{}, run, verdict, "P1", ""); err != nil {
		t.Fatal(err)
	}
	if n, band := count(t, whole); n != 2 || band != "" {
		t.Errorf("--min-priority alone wrote %d result(s) and declared %q; want 2 and no declaration", n, band)
	}

	// A declared band: narrowed, and the file says which band it was narrowed to.
	narrowed := t.TempDir()
	if err := writeArtifacts(narrowed, []string{"sarif"}, data, saga.Release{}, run, verdict, "", "P1"); err != nil {
		t.Fatal(err)
	}
	if n, band := count(t, narrowed); n != 1 || band != "P1" {
		t.Errorf("a declared band wrote %d result(s) and declared %q; want 1 and P1", n, band)
	}
}

// The flag overrides the descriptor, so a workflow can narrow what it uploads without editing a
// file it may not own.
func TestDeclaredBandPrefersTheFlag(t *testing.T) {
	model := &saga.Model{Config: saga.Config{Reports: []saga.ReportConfig{
		{Format: "sarif", MinPriority: "P3"},
	}}}
	if got := declaredBand(scanOptions{artifactMinPriority: "P1"}, model); got != "P1" {
		t.Errorf("flag should win: got %q", got)
	}
	if got := declaredBand(scanOptions{}, model); got != "P3" {
		t.Errorf("descriptor should apply when no flag: got %q", got)
	}
	// Only a sarif report's band reaches the written sarif; another format's must not.
	other := &saga.Model{Config: saga.Config{Reports: []saga.ReportConfig{
		{Format: "markdown", MinPriority: "P1"},
	}}}
	if got := declaredBand(scanOptions{}, other); got != "" {
		t.Errorf("a markdown report's band must not narrow the sarif: got %q", got)
	}
}

// The --report help lists what the registry actually holds.
//
// A format can ship, work, and still be undiscoverable: --report listed its formats as a hand-
// written string, so a new one appeared nowhere a user looks. Nothing failed, `--report
// gitlab-codequality` worked the whole time. Which is why the drift survived a release.
func TestReportFlagListsEveryFormat(t *testing.T) {
	cmd := newRootCommand()
	scan, _, err := cmd.Find([]string{"scan"})
	if err != nil {
		t.Fatal(err)
	}
	usage := scan.Flags().Lookup("report").Usage
	for _, f := range report.Formats() {
		if !strings.Contains(usage, f) {
			t.Errorf("--report help does not mention %q, so nobody finds it: %s", f, usage)
		}
	}
}

// TestComponentVerdictsAttributeUnscannedTargets covers the attribution the report depends on: a
// failure recorded only against a control cannot tell a reader which component went unexamined,
// and a component with nothing examined must not be describable as passing.
func TestComponentVerdictsAttributeUnscannedTargets(t *testing.T) {
	model := &saga.Model{Components: []saga.Component{{Name: "api"}, {Name: "mesh"}}}
	unscanned := []engine.Unscanned{
		{Control: "images", Component: "mesh", Kind: "image", Target: "r/a:1"},
		{Control: "images", Component: "mesh", Kind: "image", Target: "r/b:1"},
		{Control: "images", Component: "api", Kind: "image", Target: "r/c:1"},
		{Control: "infrastructure", Component: "", Kind: "infra", Target: "kubernetes/x"},
	}

	got, _ := componentVerdicts(norn.Policy{}, model, nil, engine.Scope{}, unscanned)
	byName := map[string][]engine.Unscanned{}
	for _, cv := range got {
		byName[cv.Name] = cv.Unscanned
	}
	if len(byName["mesh"]) != 2 {
		t.Errorf("mesh should carry both of its unscanned images, got %d", len(byName["mesh"]))
	}
	if len(byName["api"]) != 1 {
		t.Errorf("api should carry its own, got %d", len(byName["api"]))
	}
	// A project-wide failure belongs to no component, and attaching it to one would blame a team
	// for a gap that is not theirs.
	for name, us := range byName {
		for _, u := range us {
			if u.Component != name {
				t.Errorf("%s was given %s's unscanned target", name, u.Component)
			}
		}
	}
}

// TestAGateThatCannotFireIsRefused: the default gate is a band, so a descriptor that classifies
// every component below where that band is reachable has no gate at all rather than a weak one.
// Every scan passes, including one carrying an actively exploited critical vulnerability.
func TestAGateThatCannotFireIsRefused(t *testing.T) {
	saga := `project: p
release: {version: "1"}
config:
  controllers: {images: {enabled: true}}
components:
  - name: api
    exposure: restricted
    criticality: important
    images: [{image: alpine:3}]
`
	err := runScan(context.Background(), writeSaga(t, saga), scanOptions{},
		fakeRegistry(sarif.LevelError), &bytes.Buffer{})
	if err == nil {
		t.Fatal("a gate that cannot fire was accepted")
	}
	// The classification, the tier it produces, and what to do. A reader told only that something
	// is wrong has to work out all three for themselves.
	for _, want := range []string{"cannot fire", "restricted", "C4", "P2", "classify"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("message does not mention %q: %v", want, err)
		}
	}
}

// TestSomeComponentsOutOfReachIsSaidAndNotRefused: a restricted internal tool beside a public API
// is an ordinary descriptor, and the run is still meaningful for the rest of it.
func TestSomeComponentsOutOfReachIsSaidAndNotRefused(t *testing.T) {
	saga := `project: p
release: {version: "1"}
config:
  controllers: {images: {enabled: true}}
components:
  - name: public-api
    exposure: public
    criticality: critical
    images: [{image: alpine:3}]
  - name: internal-tool
    exposure: restricted
    criticality: supporting
    images: [{image: alpine:3}]
`
	var out bytes.Buffer
	err := runScan(context.Background(), writeSaga(t, saga), scanOptions{},
		fakeRegistry(sarif.LevelNote), &out)
	if err != nil {
		t.Fatalf("the run should continue: %v", err)
	}
	// Only the warning block, because every component is named again further down in the results
	// the scan produced, where naming them is the point.
	warning := gateWarning(out.String())
	if !strings.Contains(warning, "internal-tool") {
		t.Errorf("the component out of reach was not named:\n%s", out.String())
	}
	if strings.Contains(warning, "public-api") {
		t.Errorf("a component the gate does judge was named as out of reach:\n%s", warning)
	}
}

// gateWarning is the block reportUnreachableGate wrote, from the line that opens it to the advice
// that closes it.
func gateWarning(output string) string {
	lines := strings.Split(output, "\n")
	for i, line := range lines {
		if !strings.Contains(line, "cannot produce") {
			continue
		}
		for j := i; j < len(lines); j++ {
			if strings.HasPrefix(lines[j], "Gate on a band") {
				return strings.Join(lines[i:j+1], "\n")
			}
		}
	}
	return ""
}

// TestASeverityGateIsNeverOutOfReach: a severity threshold does not read a classification, so no
// classification can put it beyond one.
func TestASeverityGateIsNeverOutOfReach(t *testing.T) {
	saga := `project: p
release: {version: "1"}
config:
  gate: {failOn: critical}
  controllers: {images: {enabled: true}}
components:
  - name: api
    exposure: restricted
    criticality: supporting
    images: [{image: alpine:3}]
`
	var out bytes.Buffer
	if err := runScan(context.Background(), writeSaga(t, saga), scanOptions{},
		fakeRegistry(sarif.LevelNote), &out); err != nil {
		t.Fatalf("a severity gate was reported unreachable: %v", err)
	}
	if strings.Contains(out.String(), "cannot produce") {
		t.Errorf("a severity gate was checked against a band:\n%s", out.String())
	}
}

// TestNoGateSkipsTheUnreachableCheck: refusing a run because its gate cannot fire, on the one flag
// that exists to stop the gate deciding anything, is the check arguing with the person who has
// already answered it.
func TestNoGateSkipsTheUnreachableCheck(t *testing.T) {
	saga := `project: p
release: {version: "1"}
config:
  controllers: {images: {enabled: true}}
components:
  - name: api
    exposure: restricted
    criticality: important
    images: [{image: alpine:3}]
`
	var out bytes.Buffer
	err := runScan(context.Background(), writeSaga(t, saga), scanOptions{noGate: true},
		fakeRegistry(sarif.LevelError), &out)
	if err != nil {
		t.Fatalf("--no-gate was refused for a gate it had already switched off: %v", err)
	}
	if strings.Contains(out.String(), "cannot fire") {
		t.Errorf("--no-gate was told its gate cannot fire:\n%s", out.String())
	}
}
