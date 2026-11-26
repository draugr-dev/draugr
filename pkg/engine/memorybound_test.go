package engine

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/toolexec"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// namedController plans one job of its scanner per component, under a control of its own name.
type namedController struct{ name, scanner string }

func (c namedController) Info() plugin.ControllerInfo {
	return plugin.ControllerInfo{Name: c.name, Scope: plugin.ScopeComponent}
}

func (c namedController) Plan(_ saga.Model, comp *saga.Component) ([]plugin.ScanJob, error) {
	return []plugin.ScanJob{{Scanner: c.scanner, Target: plugin.ImageTarget{Ref: comp.Name}}}, nil
}

func (c namedController) Aggregate(reports []sarif.Report) (plugin.ControlResult, error) {
	return plugin.ControlResult{Control: c.name, Report: sarif.Merge(reports...)}, nil
}

// hogScanner runs a tool whose process group holds about 200 MiB until it is stopped.
type hogScanner struct{}

func (hogScanner) Info() plugin.ScannerInfo { return plugin.ScannerInfo{Name: "hog", Version: "1"} }

func (hogScanner) Scan(ctx context.Context, _ plugin.Target, _ plugin.Config) (sarif.Report, error) {
	_, err := toolexec.Run(ctx, "", []string{"sh", "-c", "{ head -c 209715200 /dev/zero; sleep 30; } | tail > /dev/null"})
	if err != nil {
		return sarif.Report{}, fmt.Errorf("run hog: %w", err)
	}
	return sarif.Report{Tool: "hog"}, nil
}

// findingScanner reports one finding for each target.
type findingScanner struct{}

func (findingScanner) Info() plugin.ScannerInfo {
	return plugin.ScannerInfo{Name: "finder", Version: "1"}
}

func (findingScanner) Scan(_ context.Context, t plugin.Target, _ plugin.Config) (sarif.Report, error) {
	ref := t.(plugin.ImageTarget).Ref
	return sarif.Report{Tool: "finder", Results: []sarif.Result{{RuleID: "R1", Component: ref, Location: sarif.Location{URI: ref + "/main.go"}}}}, nil
}

// A tool that passes the run's memory bound fails its own control, whose error names the tool, the
// bound and what to change, and the other control's findings, on both components, are reported.
func TestAToolPastTheMemoryBoundFailsOnlyItsControl(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the bound is enforced on Linux")
	}
	reg := NewRegistry()
	reg.RegisterController(namedController{name: "hungry", scanner: "hog"})
	reg.RegisterController(namedController{name: "steady", scanner: "finder"})
	reg.RegisterScanner(hogScanner{})
	reg.RegisterScanner(findingScanner{})
	model := saga.Model{
		Release: saga.Release{Version: "1"},
		Config: saga.Config{Controls: map[string]saga.ControllerSettings{
			"hungry": {"enabled": true}, "steady": {"enabled": true},
		}},
		Components: []saga.Component{{Name: "web"}, {Name: "api"}},
	}
	ctx := toolexec.WithMemoryBound(context.Background(), toolexec.MemoryBound{Bytes: 64 << 20, Text: "64MiB"})

	run, err := New(reg, WithConcurrency(4)).Run(ctx, model)
	if err == nil {
		t.Fatal("a run whose tool was stopped returned no error")
	}
	steady := run.Controls["steady"]
	if got := len(steady.Report.Results); got != 2 {
		t.Errorf("the other control reported %d findings, want one per component: %+v", got, steady)
	}
	failures := run.ScanErrors["hungry"]
	if len(failures) != 2 {
		t.Fatalf("the hungry control's errors = %q, want one per component", failures)
	}
	for _, f := range failures {
		for _, want := range []string{"run hog", "64MiB", "--tool-memory", boundAdvice, boundLimitAdvice} {
			if !strings.Contains(f, want) {
				t.Errorf("the failure %q does not say %q", f, want)
			}
		}
	}
	if len(run.ScanErrors["steady"]) != 0 {
		t.Errorf("the other control failed too: %q", run.ScanErrors["steady"])
	}
}

// A tool stopped at the bound in a run that already limits its tools' threads is told only to
// raise the bound, and stays a kill and a stop to errors.Is.
func TestAStopUnderTheThreadLimitAdvisesTheBoundAlone(t *testing.T) {
	t.Parallel()
	stop := fmt.Errorf("run fake: %w", toolexec.ErrOverMemoryBound)
	err := adviseOnKill(toolexec.WithThreadLimit(context.Background()), stop)
	if msg := err.Error(); !strings.HasSuffix(msg, boundAdvice) || strings.Contains(msg, "--limit-tool-threads") {
		t.Errorf("advice %q, want the bound's alone", msg)
	}
	if !errors.Is(err, toolexec.ErrOverMemoryBound) {
		t.Errorf("the advised stop %v is no longer ErrOverMemoryBound", err)
	}
}
