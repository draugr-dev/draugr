package engine

import (
	"context"
	"errors"
	"testing"

	"github.com/draugr-dev/draugr/internal/toolexec"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// toolScanner runs a real process through toolexec for each job, as a scanner's tool runs, and
// fails its job when fail is set, after the tool has run.
type toolScanner struct {
	name string
	fail bool
}

func (s toolScanner) Info() plugin.ScannerInfo { return plugin.ScannerInfo{Name: s.name} }

func (s toolScanner) Scan(ctx context.Context, target plugin.Target, _ plugin.Config) (sarif.Report, error) {
	if _, err := toolexec.Run(ctx, "", []string{"sh", "-c", "true"}); err != nil {
		return sarif.Report{}, err
	}
	if s.fail {
		return sarif.Report{}, errors.New("the tool ran out of memory")
	}
	return sarif.Report{Tool: s.name, Results: []sarif.Result{
		{RuleID: "R", Level: sarif.LevelWarning, Location: sarif.Location{URI: target.Identity()}},
	}}, nil
}

// Each job that ran a tool records its largest tool process, a failed job too, one entry per job
// in a stable order, and a job that ran no tool records none. The run records Draugr's own peak
// beside the tools'.
func TestRunRecordsEachJobsToolMemoryAndItsOwn(t *testing.T) {
	origOwn := peakOwnMemory
	t.Cleanup(func() { peakOwnMemory = origOwn })
	peakOwnMemory = func() (uint64, bool) { return 3 << 30, true }

	reg := NewRegistry()
	reg.RegisterController(fakeController{name: "images", scope: plugin.ScopeComponent, scanner: "tool"})
	reg.RegisterController(fakeController{name: "infra", scope: plugin.ScopeComponent, scanner: "notool"})
	reg.RegisterScanner(toolScanner{name: "tool"})
	reg.RegisterScanner(&fakeScanner{name: "notool"})
	res, err := New(reg).Run(context.Background(), model())
	if err != nil {
		t.Fatal(err)
	}
	if res.Stats.PeakOwnMemory != 3<<30 {
		t.Errorf("PeakOwnMemory = %d, want %d", res.Stats.PeakOwnMemory, uint64(3<<30))
	}
	if len(res.Stats.JobMemory) != 2 {
		t.Fatalf("JobMemory = %+v, want one entry for each of the two components' tool jobs", res.Stats.JobMemory)
	}
	for i, want := range []string{"a", "b"} {
		m := res.Stats.JobMemory[i]
		if m.Scanner != "tool" || m.Control != "images" || m.Kind != "image" || m.Target != want || m.PeakBytes == 0 {
			t.Errorf("JobMemory[%d] = %+v, want the tool job on %s with a peak", i, m, want)
		}
	}

	failing := NewRegistry()
	failing.RegisterController(fakeController{name: "images", scope: plugin.ScopeComponent, scanner: "tool"})
	failing.RegisterScanner(toolScanner{name: "tool", fail: true})
	res, _ = New(failing).Run(context.Background(), saga.Model{
		Release:    saga.Release{Version: "1"},
		Config:     saga.Config{Controls: map[string]saga.ControllerSettings{"images": {"enabled": true}}},
		Components: []saga.Component{{Name: "a"}},
	})
	if len(res.Stats.JobMemory) != 1 || res.Stats.JobMemory[0].PeakBytes == 0 {
		t.Errorf("a failed job's tool memory = %+v, want it recorded", res.Stats.JobMemory)
	}
}
