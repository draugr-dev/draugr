package engine

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// refreshingScanner declares data and takes a set time to refresh it.
type refreshingScanner struct {
	name string
	data []plugin.DataSource
	took time.Duration
	err  error
}

func (s refreshingScanner) Info() plugin.ScannerInfo {
	return plugin.ScannerInfo{Name: s.name, Data: s.data}
}

func (s refreshingScanner) Scan(context.Context, plugin.Target, plugin.Config) (sarif.Report, error) {
	return sarif.Report{Tool: s.name}, nil
}

func (s refreshingScanner) Prewarm(context.Context) error {
	time.Sleep(s.took)
	return s.err
}

func runRefreshing(t *testing.T, sc refreshingScanner) (Stats, []string) {
	t.Helper()
	old := refreshShownAfter
	refreshShownAfter = 20 * time.Millisecond
	t.Cleanup(func() { refreshShownAfter = old })

	reg := NewRegistry()
	reg.RegisterController(fakeController{name: "images", scope: plugin.ScopeComponent, scanner: sc.name})
	reg.RegisterScanner(sc)
	var (
		mu         sync.Mutex
		refreshing []string
	)
	progress := func(ev ProgressEvent) {
		mu.Lock()
		defer mu.Unlock()
		if ev.Refreshing != "" {
			refreshing = append(refreshing, ev.Refreshing)
		}
	}
	res, err := New(reg, WithProgress(progress)).Run(context.Background(), model())
	if err != nil {
		t.Fatal(err)
	}
	return res.Stats, refreshing
}

// A refresh is timed and named by the data the scanner declares, so a report can say which data a
// slow run was waiting on.
func TestARefreshIsTimedAndNamedByItsData(t *testing.T) {
	db := []plugin.DataSource{{Name: "vulnerability database"}, {Name: "vulnerability database"}}
	stats, refreshing := runRefreshing(t, refreshingScanner{name: "s", data: db, took: 60 * time.Millisecond})
	if len(stats.DataRefresh) != 1 {
		t.Fatalf("DataRefresh = %+v, want one entry", stats.DataRefresh)
	}
	r := stats.DataRefresh[0]
	if r.Scanner != "s" || !slices.Equal(r.Data, []string{"vulnerability database"}) || r.Took < 60*time.Millisecond || r.Failed {
		t.Errorf("DataRefresh[0] = %+v", r)
	}
	if !slices.Equal(refreshing, []string{"s vulnerability database"}) {
		t.Errorf("progress named %q, want the refresh once it ran past the threshold", refreshing)
	}
}

// A refresh that returns at once is not named on the progress display. Most find their data current,
// and a line per scanner would say nothing about the wait.
func TestAQuickRefreshIsNotNamedWhileTheRunWaits(t *testing.T) {
	stats, refreshing := runRefreshing(t, refreshingScanner{name: "s"})
	if len(refreshing) != 0 {
		t.Errorf("progress named %q for a refresh that returned at once", refreshing)
	}
	if len(stats.DataRefresh) != 1 {
		t.Errorf("DataRefresh = %+v; a quick refresh is still recorded", stats.DataRefresh)
	}
}

func TestAFailedRefreshIsRecordedAsFailed(t *testing.T) {
	stats, _ := runRefreshing(t, refreshingScanner{name: "s", err: errors.New("offline")})
	if len(stats.DataRefresh) != 1 || !stats.DataRefresh[0].Failed {
		t.Errorf("DataRefresh = %+v, want the failure recorded", stats.DataRefresh)
	}
}

func TestRefreshLabel(t *testing.T) {
	if got := refreshLabel("trivy", []string{"vulnerability database"}); got != "trivy vulnerability database" {
		t.Errorf("refreshLabel = %q", got)
	}
	if got := refreshLabel("gitleaks", nil); got != "gitleaks data" {
		t.Errorf("refreshLabel with no data = %q", got)
	}
}
