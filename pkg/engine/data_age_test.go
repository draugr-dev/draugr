package engine

import (
	"context"
	"testing"
	"time"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// datedScanner reports the state of its data.
type datedScanner struct {
	name, binary string
	states       []plugin.DataState
	asked        *int
}

func (s datedScanner) Info() plugin.ScannerInfo {
	return plugin.ScannerInfo{Name: s.name, Binary: s.binary}
}

func (s datedScanner) Scan(context.Context, plugin.Target, plugin.Config) (sarif.Report, error) {
	return sarif.Report{Tool: s.name}, nil
}

func (s datedScanner) DataState(context.Context) []plugin.DataState {
	if s.asked != nil {
		*s.asked++
	}
	return s.states
}

var trivyDB = plugin.DataState{Name: "vulnerability database", Version: "schema 2",
	Published: time.Date(2026, 10, 10, 18, 59, 50, 0, time.UTC), Downloaded: time.Date(2026, 10, 11, 0, 2, 0, 0, time.UTC)}

// A run records the data its scanners read, asking each scanner once however many jobs it ran.
func TestARunRecordsTheDataItsScannersRead(t *testing.T) {
	asked := 0
	sc := datedScanner{name: "trivy", binary: "trivy", states: []plugin.DataState{trivyDB}, asked: &asked}
	reg := NewRegistry()
	reg.RegisterController(fakeController{name: "images", scope: plugin.ScopeComponent, scanner: sc.name})
	reg.RegisterScanner(sc)
	res, err := New(reg).Run(context.Background(), model())
	if err != nil {
		t.Fatal(err)
	}
	if res.Stats.Jobs < 2 {
		t.Fatalf("the fixture plans %d jobs; asking once needs more than one to mean anything", res.Stats.Jobs)
	}
	if asked != 1 {
		t.Errorf("the scanner was asked %d times, want once", asked)
	}
	want := []ScannerData{{Tool: "trivy", DataState: trivyDB}}
	if len(res.Stats.Data) != 1 || res.Stats.Data[0] != want[0] {
		t.Errorf("Stats.Data = %+v, want %+v", res.Stats.Data, want)
	}
}

// One tool's data appears once, whichever of its scanners reported it. A scanner with no binary is
// named for itself, and one that reports nothing adds nothing.
func TestDataStatesKeepsOneEntryPerToolAndSource(t *testing.T) {
	checks := plugin.DataState{Name: "checks bundle", Downloaded: trivyDB.Downloaded}
	got := DataStates(context.Background(), []plugin.Scanner{
		datedScanner{name: "trivy", binary: "trivy", states: []plugin.DataState{trivyDB}},
		datedScanner{name: "trivy-fs", binary: "trivy", states: []plugin.DataState{trivyDB}},
		datedScanner{name: "trivy-config", binary: "trivy", states: []plugin.DataState{checks}},
		datedScanner{name: "grype", binary: "grype", states: []plugin.DataState{trivyDB}},
		datedScanner{name: "osv", states: []plugin.DataState{{Name: "advisories", Downloaded: trivyDB.Downloaded}}},
		datedScanner{name: "quiet", binary: "quiet"},
		refreshingScanner{name: "no-state"},
	})
	want := []ScannerData{
		{Tool: "trivy", DataState: trivyDB},
		{Tool: "trivy", DataState: checks},
		{Tool: "grype", DataState: trivyDB},
		{Tool: "osv", DataState: plugin.DataState{Name: "advisories", Downloaded: trivyDB.Downloaded}},
	}
	if len(got) != len(want) {
		t.Fatalf("DataStates = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d = %+v, want %+v", i, got[i], want[i])
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := DataStates(ctx, []plugin.Scanner{datedScanner{name: "trivy", states: []plugin.DataState{trivyDB}}}); got != nil {
		t.Errorf("a canceled run asked anyway: %+v", got)
	}
}
