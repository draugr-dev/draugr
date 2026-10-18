package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// enabling is the test model with these controls enabled, on two components.
func enabling(controls ...string) saga.Model {
	m := model()
	m.Config.Controls = map[string]saga.ControllerSettings{}
	for _, c := range controls {
		m.Config.Controls[c] = saga.ControllerSettings{"enabled": true}
	}
	return m
}

// uninstalledScanner runs a tool that is not on the machine, the way toolexec reports one.
type uninstalledScanner struct{ name, tool string }

func (s uninstalledScanner) Info() plugin.ScannerInfo {
	return plugin.ScannerInfo{Name: s.name, Binary: s.tool}
}

func (s uninstalledScanner) notFound() error {
	return fmt.Errorf("run %s: %w. Run `draugr tools install %s`", s.name,
		&exec.Error{Name: s.tool, Err: exec.ErrNotFound}, s.tool)
}

func (s uninstalledScanner) Scan(context.Context, plugin.Target, plugin.Config) (sarif.Report, error) {
	return sarif.Report{}, s.notFound()
}

func (s uninstalledScanner) Prewarm(context.Context) error { return s.notFound() }

// failingScanner fails for a reason that is not a missing tool.
type failingScanner struct{ name string }

func (s failingScanner) Info() plugin.ScannerInfo { return plugin.ScannerInfo{Name: s.name} }
func (s failingScanner) Scan(context.Context, plugin.Target, plugin.Config) (sarif.Report, error) {
	return sarif.Report{}, errors.New("run " + s.name + ": database download failed")
}

// Two controls missing one tool and a third missing another: each control and tool is recorded once,
// sorted, against the exact message the run reported, and a failure of another kind is not.
func TestARunRecordsEachMissingToolAgainstItsMessage(t *testing.T) {
	reg := NewRegistry()
	for ctl, sc := range map[string]plugin.Scanner{
		"iac":  uninstalledScanner{"trivy-config", "trivy"},
		"sca":  uninstalledScanner{"trivy-fs", "trivy"},
		"sast": uninstalledScanner{"semgrep", "semgrep"},
		"dast": failingScanner{"nuclei"},
	} {
		reg.RegisterController(fakeController{name: ctl, scope: plugin.ScopeComponent, scanner: sc.Info().Name})
		reg.RegisterScanner(sc)
	}
	// The run reports the failures as its error too; the result is what is under test.
	res, err := New(reg).Run(context.Background(), enabling("iac", "sca", "sast", "dast"))
	if err == nil {
		t.Fatal("a run whose scanners all failed returned no error")
	}
	var got []string
	for _, m := range res.MissingTools {
		got = append(got, m.Control+"/"+m.Tool)
		if !m.Provisionable {
			t.Errorf("%s: %s reported as not provisionable", m.Control, m.Tool)
		}
		found := false
		for _, msg := range res.ScanErrors[m.Control] {
			found = found || msg == m.Message
		}
		if !found {
			t.Errorf("%s: message %q is not one the run reported: %v", m.Control, m.Message, res.ScanErrors[m.Control])
		}
	}
	if want := "iac/trivy sast/semgrep sca/trivy"; strings.Join(got, " ") != want {
		t.Errorf("MissingTools = %s, want %s", strings.Join(got, " "), want)
	}
	// Once per component: the model has two, which is what proves the entries above collapse.
	if len(res.ScanErrors["dast"]) != 2 {
		t.Errorf("the other failure was not reported: %v", res.ScanErrors)
	}
}

// A tool that is not installed is said by the control that needed it, so the warm-up records it at
// debug, while any other warm-up failure is still a warning.
func TestAMissingToolDoesNotWarnDuringTheWarmUp(t *testing.T) {
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(old) })

	reg := NewRegistry()
	reg.RegisterController(fakeController{name: "sca", scope: plugin.ScopeComponent, scanner: "trivy-fs"})
	reg.RegisterScanner(uninstalledScanner{"trivy-fs", "trivy"})
	reg.RegisterController(fakeController{name: "images", scope: plugin.ScopeComponent, scanner: "s"})
	reg.RegisterScanner(refreshingScanner{name: "s", data: []plugin.DataSource{{Name: "db"}}, err: errors.New("mirror unreachable")})
	_, _ = New(reg).Run(context.Background(), enabling("sca", "images"))
	var missing, other string
	for _, line := range strings.Split(buf.String(), "\n") {
		if !strings.Contains(line, "scanner prewarm failed") {
			continue
		}
		if strings.Contains(line, "scanner=trivy-fs") {
			missing = line
		}
		if strings.Contains(line, "scanner=s ") {
			other = line
		}
	}
	if !strings.Contains(missing, "level=DEBUG") {
		t.Errorf("missing tool logged as %q, want debug", missing)
	}
	if !strings.Contains(other, "level=WARN") {
		t.Errorf("another warm-up failure logged as %q, want a warning", other)
	}
}

func TestMissingToolReadsOnlyANotFoundExecError(t *testing.T) {
	for err, want := range map[error]string{
		fmt.Errorf("run x: %w", &exec.Error{Name: "/usr/local/bin/trivy", Err: exec.ErrNotFound}): "trivy",
		fmt.Errorf("run x: %w", &exec.Error{Name: "trivy", Err: errors.New("permission denied")}): "",
		errors.New("exit status 1"): "",
	} {
		if got := missingTool(err); got != want {
			t.Errorf("missingTool(%v) = %q, want %q", err, got, want)
		}
	}
}
