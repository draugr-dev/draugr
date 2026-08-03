package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/feeds"
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
release:
  name: app
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
release:
  name: app
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
release:
  name: app
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
release:
  name: app
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
// plans work. fakeRegistry serves `images`, which zero-config does not enable — with only that
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
		if _, ok := m.Config.Controllers[c]; !ok {
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
	if m.Release.Name != "app" {
		t.Errorf("loaded wrong saga: %+v", m.Release)
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

func TestRunScanInvalidFailOnPriority(t *testing.T) {
	err := runScan(context.Background(), writeSaga(t, sagaWithImage),
		scanOptions{failOn: "error", failOnPriority: "bogus"}, fakeRegistry(sarif.LevelNote), &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "invalid --fail-on-priority") {
		t.Fatalf("expected invalid fail-on-priority error, got %v", err)
	}
}

func TestRunScanFailsWhenAControlCouldNotRun(t *testing.T) {
	// A control that couldn't run didn't find nothing — it found out nothing. Reporting that as
	// a pass makes the gate a false negative precisely where it matters, so it fails by default.
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
	// Best-effort scanning stays available — but the report still says a control errored, so
	// the opt-out buys a passing exit code, not silence.
	var buf bytes.Buffer
	err := runScan(context.Background(), writeSaga(t, sagaWithImage),
		scanOptions{failOn: "error", allowScanErrors: true}, failingRegistry(), &buf)
	if err != nil {
		t.Fatalf("--allow-scan-errors should not fail the gate, got %v", err)
	}
	if !strings.Contains(buf.String(), "Draugr — PASS") {
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
	// A warning finding passes the fail-on-error level gate; on an unclassified component it
	// resolves to P2, so --fail-on-priority P2 must flip the verdict to fail.
	base := scanOptions{failOn: "error"}
	if err := runScan(context.Background(), path, base, fakeRegistry(sarif.LevelWarning), &bytes.Buffer{}); err != nil {
		t.Fatalf("without priority gate, warning should pass fail-on-error: %v", err)
	}
	withGate := scanOptions{failOn: "error", failOnPriority: "P2"}
	if err := runScan(context.Background(), path, withGate, fakeRegistry(sarif.LevelWarning), &bytes.Buffer{}); err == nil {
		t.Fatal("expected fail: a P2 finding should trip --fail-on-priority P2")
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
	if !strings.Contains(buf.String(), "Draugr — FAIL") {
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
	if !strings.Contains(buf.String(), "Draugr — PASS") {
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
	// that scans nothing is far more often unfinished than genuinely empty, and the output for
	// the two used to be identical.
	path := writeSaga(t, "release:\n  name: app\n  version: \"1.0\"\n")
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
	if err := writeArtifacts(dir, nil, report.Data{}, saga.Release{Name: "app", Version: "1"}, run, norn.Result{Verdict: norn.Pass}, ""); err != nil {
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

func TestPerControlThresholds(t *testing.T) {
	if got := perControlThresholds(nil); got != nil {
		t.Errorf("no gate block should leave every control on --fail-on, got %v", got)
	}
	if got := perControlThresholds(&saga.GateConfig{}); got != nil {
		t.Errorf("an empty gate block is the same as none, got %v", got)
	}
	got := perControlThresholds(&saga.GateConfig{Controls: map[string]string{"licenses": "error", "sast": "note"}})
	if len(got) != 2 || got["licenses"] != sarif.LevelError || got["sast"] != sarif.LevelNote {
		t.Errorf("perControlThresholds = %v", got)
	}
}

// A directory holding a descriptor is not a directory to scan zero-config. Ignoring it discarded
// the controls chosen, the components declared, and the exposure and criticality that drive
// prioritization — silently, and while telling the reader to create the file they already had.
func TestScanUsesTheDescriptorInTheDirectory(t *testing.T) {
	dir := t.TempDir()
	saga := "release:\n  name: real\n  version: \"2.0\"\nconfig:\n  controllers:\n    images: {enabled: true}\n" +
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
	if m.Release.Name != "real" {
		t.Errorf("release = %q, want the descriptor's", m.Release.Name)
	}
	// The controls it declares, not the zero-config four.
	if !m.Config.ControllerEnabled("images") || m.Config.ControllerEnabled("sca") {
		t.Errorf("controls came from the wrong place: %+v", m.Config.Controllers)
	}
}

// The reason a descriptor was skipped has to be reported. Falling back to zero-config would
// reproduce the bug with an extra step: a broken descriptor and a green scan.
func TestABrokenDescriptorFailsRatherThanFallingBack(t *testing.T) {
	dir := t.TempDir()
	// The typo that surfaced this: a misspelled component key.
	broken := "release:\n  name: app\n  version: \"1.0\"\ncomponents:\n  - namfe: web\n"
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

// Zero-config still applies where there is nothing to honour — that is what it is for.
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
		t.Errorf("zero-config controls missing: %+v", m.Config.Controllers)
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
	// A run that both failed its gate and could not publish is two facts, and only one can be
	// the exit message. Naming the publisher sends a reader to fix a token when what actually
	// happened is that the build should not ship — so the verdict leads and the publisher
	// follows it, rather than replacing it.
	saga := `
release:
  name: app
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
release:
  name: app
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
release:
  name: app
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
	// Not a second implementation of the gate. Reproducing "what counts as failing" in the
	// reporter is how the parts come to disagree with the whole — a component reading PASS
	// under a headline that says FAIL.
	policy := norn.Policy{FailOn: sarif.LevelError}
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
	got, unattributed := componentVerdicts(policy, model, reports)
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
	// Building the list from the findings drops exactly the component a reader most wants to
	// see — the clean one they can take back to their team.
	policy := norn.Policy{FailOn: sarif.LevelError}
	model := &saga.Model{Components: []saga.Component{{Name: "a"}, {Name: "quiet"}}}
	reports := map[string]sarif.Report{"sca": {Results: []sarif.Result{
		{RuleID: "x", Level: sarif.LevelError, Component: "a"},
	}}}
	got, _ := componentVerdicts(policy, model, reports)
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
	policy := norn.Policy{FailOn: sarif.LevelError}
	model := &saga.Model{Components: []saga.Component{{Name: "a"}, {Name: "b"}}}
	reports := map[string]sarif.Report{"sca": {Results: []sarif.Result{
		{RuleID: "x", Level: sarif.LevelError, Component: "a",
			Suppression: &sarif.Suppression{Kind: "external", Justification: "accepted"}},
	}}}
	got, _ := componentVerdicts(policy, model, reports)
	if got[0].Findings != 0 || got[0].Verdict != norn.Pass {
		t.Errorf("a suppressed finding must not fail its component: %+v", got[0])
	}
}

func TestComponentVerdictsAreAbsentForOneComponent(t *testing.T) {
	policy := norn.Policy{FailOn: sarif.LevelError}
	model := &saga.Model{Components: []saga.Component{{Name: "only"}}}
	if got, _ := componentVerdicts(policy, model, nil); got != nil {
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

func TestWriteArtifactsHonoursReportFormats(t *testing.T) {
	dir := t.TempDir()
	data := report.Data{Release: saga.Release{Name: "app", Version: "1"}}
	err := writeArtifacts(dir, []string{"html", "markdown"}, data,
		saga.Release{Name: "app", Version: "1"}, engine.Result{}, norn.Result{Verdict: norn.Pass}, "")
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
	err := writeArtifacts(dir, nil, report.Data{}, saga.Release{Name: "app", Version: "1"},
		engine.Result{}, norn.Result{Verdict: norn.Pass}, "")
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
	// A finding's Tool is the SARIF driver name the tool gives itself — "Trivy" for trivy-fs —
	// so deriving the list from findings finds nothing. It comes from Result.Scanners, which are
	// the names Draugr selected.
	got := toolBuilds(engine.Result{Scanners: []string{"trivy-fs", "gitleaks"}})
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
	if got := toolBuilds(engine.Result{Scanners: []string{"draugr-headers", "draugr-tls"}}); got != nil {
		t.Errorf("native scanners were listed as external tools: %+v", got)
	}
	if got := toolBuilds(engine.Result{}); got != nil {
		t.Errorf("a run that used nothing listed something: %+v", got)
	}
}

func TestToolBuildsIgnoresUnknownScanners(t *testing.T) {
	// A name no scanner answers to cannot have an executable behind it.
	if got := toolBuilds(engine.Result{Scanners: []string{"not-a-scanner"}}); got != nil {
		t.Errorf("got %+v", got)
	}
}

func TestWriteArtifactsUsesTheSameNamesAPublisherWould(t *testing.T) {
	// -o and a publisher have to write a format under one name. When they disagree, a CI step
	// globbing for the file finds nothing — and the common ones warn rather than fail, so the run
	// stays green with no results in it.
	dir := t.TempDir()
	formats := []string{"json", "sarif", "html", "markdown", "junit"}
	err := writeArtifacts(dir, formats, report.Data{Release: saga.Release{Name: "app", Version: "1"}},
		saga.Release{Name: "app", Version: "1"}, engine.Result{}, norn.Result{Verdict: norn.Pass}, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range formats {
		if _, err := os.Stat(filepath.Join(dir, report.Filename(f))); err != nil {
			t.Errorf("%s: %s not written: %v", f, report.Filename(f), err)
		}
	}
}
