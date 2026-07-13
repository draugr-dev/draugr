package cli

import (
	"bytes"
	"context"
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

func TestNormalizeMinPriority(t *testing.T) {
	for _, v := range []string{"", "P1", "p2", "P4"} {
		if _, err := normalizeMinPriority(v); err != nil {
			t.Errorf("%q should be valid: %v", v, err)
		}
	}
	if got, _ := normalizeMinPriority("p2"); got != "P2" {
		t.Errorf("normalize should upper-case, got %q", got)
	}
	if _, err := normalizeMinPriority("P9"); err == nil {
		t.Error("P9 should be rejected")
	}
}

func TestRunScanMinPriorityListsFindings(t *testing.T) {
	var buf bytes.Buffer
	path := writeSaga(t, sagaWithImage)
	// Unclassified component → treated as re1/bc1 (C1); a note-level finding → P3.
	err := runScan(context.Background(), path,
		scanOptions{failOn: "error", minPriority: "P3"}, fakeRegistry(sarif.LevelNote), &buf)
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

func TestRunScanInvalidMinPriority(t *testing.T) {
	err := runScan(context.Background(), writeSaga(t, sagaWithImage),
		scanOptions{failOn: "error", minPriority: "bogus"}, fakeRegistry(sarif.LevelNote), &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "invalid --min-priority") {
		t.Fatalf("expected invalid min-priority error, got %v", err)
	}
}

func TestRunScanFail(t *testing.T) {
	var buf bytes.Buffer
	path := writeSaga(t, sagaWithImage)
	err := runScan(context.Background(), path, scanOptions{failOn: "error"}, fakeRegistry(sarif.LevelError), &buf)
	if err == nil {
		t.Fatal("expected fail verdict to return an error")
	}
	if !strings.Contains(buf.String(), "\"verdict\": \"fail\"") {
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
	if !strings.Contains(buf.String(), "\"verdict\": \"pass\"") {
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
	if !strings.Contains(out.String(), "\"verdict\": \"pass\"") {
		t.Errorf("expected pass verdict:\n%s", out.String())
	}
}
