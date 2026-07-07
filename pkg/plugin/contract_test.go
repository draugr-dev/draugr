package plugin

import (
	"context"
	"testing"

	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// Compile-time assertions that the fakes satisfy the interfaces. These lock the contract:
// if an interface changes incompatibly, the package stops compiling.
var (
	_ Scanner    = (*fakeScanner)(nil)
	_ Controller = (*fakeController)(nil)
	_ Surveyor   = (*fakeSurveyor)(nil)
)

type fakeScanner struct{}

func (fakeScanner) Info() ScannerInfo {
	return ScannerInfo{Name: "fake", Version: "0.0.0", Controls: []string{"images"}, TargetKinds: []TargetKind{TargetImage}}
}

func (fakeScanner) Scan(_ context.Context, _ Target, _ Config) (sarif.Report, error) {
	return sarif.Report{Tool: "fake", Results: []sarif.Result{{RuleID: "R1", Level: sarif.LevelWarning, Message: "m"}}}, nil
}

type fakeController struct{}

func (fakeController) Info() ControllerInfo {
	return ControllerInfo{Name: "images", Scope: ScopeComponent}
}

func (fakeController) Plan(_ saga.Model, comp *saga.Component) ([]ScanJob, error) {
	if comp == nil {
		return nil, nil
	}
	tgt := ImageTarget{Ref: comp.Name + ":latest"}
	return []ScanJob{{
		Scanner:  "fake",
		Target:   tgt,
		CacheKey: ComputeCacheKey("fake", "0.0.0", tgt, nil),
	}}, nil
}

func (fakeController) Aggregate(results []sarif.Report) (ControlResult, error) {
	var s Summary
	for _, r := range results {
		for _, res := range r.Results {
			switch res.Level {
			case sarif.LevelError:
				s.Errors++
			case sarif.LevelWarning:
				s.Warnings++
			case sarif.LevelNote:
				s.Notes++
			}
		}
	}
	return ControlResult{Control: "images", Summary: s}, nil
}

type fakeSurveyor struct{}

func (fakeSurveyor) Info() SurveyorInfo {
	return SurveyorInfo{Name: "fake", Provides: []TargetKind{TargetImage}}
}

func (fakeSurveyor) Survey(_ context.Context, _ SurveyScope) (saga.Fragment, error) {
	return saga.Fragment{Components: []saga.Component{{Name: "discovered"}}}, nil
}

func TestFakeControllerPlanAndAggregate(t *testing.T) {
	c := fakeController{}
	jobs, err := c.Plan(saga.Model{}, &saga.Component{Name: "backend"})
	if err != nil || len(jobs) != 1 {
		t.Fatalf("Plan = %v, %v; want 1 job", jobs, err)
	}
	if jobs[0].CacheKey == "" {
		t.Fatal("planned job should carry a cache key")
	}

	scan := fakeScanner{}
	rep, err := scan.Scan(context.Background(), jobs[0].Target, jobs[0].Config)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	res, err := c.Aggregate([]sarif.Report{rep})
	if err != nil {
		t.Fatalf("Aggregate error: %v", err)
	}
	if res.Summary.Warnings != 1 {
		t.Fatalf("summary = %+v, want 1 warning", res.Summary)
	}
}

func TestFakeSurveyor(t *testing.T) {
	f, err := fakeSurveyor{}.Survey(context.Background(), SurveyScope{Kind: "k8s"})
	if err != nil || len(f.Components) != 1 {
		t.Fatalf("Survey = %v, %v; want 1 component", f, err)
	}
}
