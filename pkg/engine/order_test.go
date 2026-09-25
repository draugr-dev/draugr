package engine

import (
	"bytes"
	"context"
	"sync"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// orderedScanner finishes its jobs in an order the test chooses: the job for component first
// returns at once, and every other job waits until the engine has recorded a finished job.
//
// Each component describes the same rule id in its own words, the shape a license policy takes
// when one component denies a license another only flags. Whichever description the report
// carries has to be decided by the inputs, never by which job happened to finish first.
type orderedScanner struct {
	first   string
	release chan struct{}
}

func (s *orderedScanner) Info() plugin.ScannerInfo { return plugin.ScannerInfo{Name: "ordered"} }

func (s *orderedScanner) Scan(ctx context.Context, target plugin.Target, _ plugin.Config) (sarif.Report, error) {
	comp := target.(plugin.ImageTarget).Ref
	if comp != s.first {
		select {
		case <-s.release:
		case <-ctx.Done():
			return sarif.Report{}, ctx.Err()
		}
	}
	return sarif.Report{
		Tool: "ordered",
		Results: []sarif.Result{{
			RuleID:   "license/ISC/inherits",
			Level:    sarif.LevelWarning,
			Message:  "inherits is ISC, as component " + comp + " sees it.",
			Location: sarif.Location{URI: "package-lock.json", StartLine: 3},
		}},
		Rules: map[string]sarif.Rule{
			"license/ISC/inherits": {
				ShortDescription: "inherits is licensed ISC",
				FullDescription:  "Described by component " + comp + ".",
			},
		},
	}, nil
}

// runFinishingFirst scans two components, a and b, with first's job finishing before the other's,
// and returns the control's report as SARIF.
func runFinishingFirst(t *testing.T, first string) []byte {
	t.Helper()
	scanner := &orderedScanner{first: first, release: make(chan struct{})}
	var once sync.Once
	reg := NewRegistry()
	reg.RegisterController(fakeController{name: "images", scope: plugin.ScopeComponent, scanner: "ordered"})
	reg.RegisterScanner(scanner)
	m := saga.Model{
		Release:    saga.Release{Version: "1"},
		Config:     saga.Config{Controls: map[string]saga.ControllerSettings{"images": {"enabled": true}}},
		Components: []saga.Component{{Name: "a"}, {Name: "b"}},
	}
	// A progress event counting a finished job is sent after that job's report is recorded, so
	// releasing the other job here fixes the order the two are recorded in.
	progress := func(ev ProgressEvent) {
		if ev.Complete >= 1 {
			once.Do(func() { close(scanner.release) })
		}
	}
	res, err := New(reg, WithConcurrency(2), WithoutPrewarm(), WithProgress(progress)).
		Run(context.Background(), m)
	if err != nil {
		t.Fatal(err)
	}
	out, err := res.Controls["images"].Report.MarshalSARIF()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestTheReportDoesNotDependOnWhichJobFinishedFirst(t *testing.T) {
	aFirst := runFinishingFirst(t, "a")
	bFirst := runFinishingFirst(t, "b")
	if !bytes.Equal(aFirst, bFirst) {
		t.Fatalf("the same inputs wrote different SARIF depending on job order:\n"+
			"a first:\n%s\nb first:\n%s", aFirst, bFirst)
	}
	// Plan order decides: component a is declared first, so its description is the one kept and
	// its finding is listed first.
	rep, err := sarif.FromSARIF(aFirst)
	if err != nil {
		t.Fatal(err)
	}
	if got := rep.Rules["license/ISC/inherits"].FullDescription; got != "Described by component a." {
		t.Errorf("rule description = %q, want component a's", got)
	}
	if len(rep.Results) != 2 || rep.Results[0].Component != "a" || rep.Results[1].Component != "b" {
		t.Errorf("results are not in plan order: %+v", rep.Results)
	}
}
