package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
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

func TestRunScanZeroConfigDirectory(t *testing.T) {
	// Pointing scan at a directory synthesizes a default Saga (no file needed) and scans it.
	dir := t.TempDir()
	var buf bytes.Buffer
	err := runScan(context.Background(), dir, scanOptions{failOn: "error", format: "json"}, fakeRegistry(sarif.LevelNote), &buf)
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

func TestRunScanWarnsOnScanError(t *testing.T) {
	// A scanner error is surfaced (logged) but does not by itself fail the gate: no findings
	// means the verdict passes.
	var buf bytes.Buffer
	err := runScan(context.Background(), writeSaga(t, sagaWithImage),
		scanOptions{failOn: "error"}, failingRegistry(), &buf)
	if err != nil {
		t.Fatalf("scan errors should not fail the gate, got %v", err)
	}
	if !strings.Contains(buf.String(), "Draugr — PASS") {
		t.Errorf("expected pass verdict:\n%s", buf.String())
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
	if src, err := loadExploitSource(scanOptions{}); err != nil || src != nil {
		t.Fatalf("no files should yield nil source, got %v %v", src, err)
	}
	kev := filepath.Join(t.TempDir(), "kev.json")
	if err := os.WriteFile(kev, []byte(`{"vulnerabilities":[{"cveID":"CVE-2021-44228"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	src, err := loadExploitSource(scanOptions{kevFile: kev, epssThreshold: 0.5})
	if err != nil || src == nil || src.Empty() {
		t.Fatalf("kev file should yield a non-empty source, got %v %v", src, err)
	}
	if _, err := loadExploitSource(scanOptions{kevFile: filepath.Join(t.TempDir(), "nope.json")}); err == nil {
		t.Error("missing --kev file should error")
	}
	if _, err := loadExploitSource(scanOptions{epssFile: filepath.Join(t.TempDir(), "nope.csv")}); err == nil {
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
	// No components → no jobs → pass, using the real built-in registry (no external tools run).
	path := writeSaga(t, "release:\n  name: app\n  version: \"1.0\"\n")
	cmd := newRootCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"scan", path})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("scan should pass with no components: %v", err)
	}
	if !strings.Contains(out.String(), "Draugr — PASS") {
		t.Errorf("expected pass verdict (console default):\n%s", out.String())
	}
}
