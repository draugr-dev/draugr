package engine

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"

	"github.com/draugr-dev/draugr/pkg/cache"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// partialScanner reads part of every target and fails on the rest.
type partialScanner struct {
	mu   sync.Mutex
	call int
}

func (*partialScanner) Info() plugin.ScannerInfo {
	return plugin.ScannerInfo{Name: "s", Version: "1.0"}
}

func (p *partialScanner) Scan(_ context.Context, target plugin.Target, _ plugin.Config) (sarif.Report, error) {
	p.mu.Lock()
	p.call++
	p.mu.Unlock()
	rep := sarif.Report{Tool: "s", Results: []sarif.Result{
		{RuleID: "R", Level: sarif.LevelWarning, Location: sarif.Location{URI: target.Identity()}},
	}}
	return rep, &plugin.PartialScanError{Report: rep, Err: errors.New("run s over tools/go.mod: exit status 1")}
}

func (p *partialScanner) calls() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.call
}

// A scan that read part of its target puts the control in error as any failed scan does, and what
// it read stays in the control's report, for each of two components. The target counts as reached,
// and the report is never cached, so the next run scans again.
func TestAPartialScanKeepsWhatItReadBesideItsError(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterController(fakeController{name: "images", scope: plugin.ScopeComponent, scanner: "s"})
	sc := &partialScanner{}
	reg.RegisterScanner(sc)
	e := New(reg, WithCache(cache.NewMemory()))

	for run := 1; run <= 2; run++ {
		res, err := e.Run(context.Background(), model())
		if err == nil {
			t.Fatalf("run %d: a partial scan returned no error", run)
		}
		if !res.Incomplete("images") {
			t.Fatalf("run %d: images is not in error", run)
		}
		if errs := res.ScanErrors["images"]; len(errs) != 2 || errs[0] != "run s over tools/go.mod: exit status 1" {
			t.Errorf("run %d: errors %q, want the scan's error once per component", run, errs)
		}
		if got := res.Controls["images"].Summary.Warnings; got != 2 {
			t.Errorf("run %d: %d findings, want what each component's scan read", run, got)
		}
		if len(res.FailedScans) != 2 || res.FailedScans[0].Version != "1.0" {
			t.Errorf("run %d: failed scans %+v, want one per component, with the version", run, res.FailedScans)
		}
		if !slices.Equal(res.Reported["images"], []string{"s"}) {
			t.Errorf("run %d: reported %v, want [s]", run, res.Reported["images"])
		}
		if len(res.Stats.Unscanned) != 0 || len(res.Stats.Failures) != 0 {
			t.Errorf("run %d: unscanned %+v, failures %+v, want none", run, res.Stats.Unscanned, res.Stats.Failures)
		}
		if len(res.Targets) != 2 {
			t.Errorf("run %d: targets %+v, want one per component", run, res.Targets)
		}
		for _, tgt := range res.Targets {
			if tgt.Status != "reached" {
				t.Errorf("run %d: target %+v, want reached", run, tgt)
			}
		}
		if res.Stats.CacheHits != 0 {
			t.Errorf("run %d: %d cache hits, want a partial report never cached", run, res.Stats.CacheHits)
		}
		var described bool
		for _, p := range res.Controls["images"].Report.Provenance {
			described = described || p.Tool == "s"
		}
		if !described {
			t.Errorf("run %d: the report does not say which scanner produced it", run)
		}
	}
	if sc.calls() != 4 {
		t.Errorf("scanner called %d times over two runs, want 4", sc.calls())
	}
}
