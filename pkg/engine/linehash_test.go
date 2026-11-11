package engine

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// A run's repeated fingerprints are numbered over every control at once, so the numbering reaches
// each control's own report, and the result in the control whose name sorts first counts first.
func TestARunNumbersItsRepeatedLineHashes(t *testing.T) {
	at := func(line int) sarif.Result {
		return sarif.Result{
			RuleID: "shared-rule", Component: "api", Location: sarif.Location{URI: "a.go", StartLine: line},
			PartialFingerprints: map[string]string{sarif.LineHashKey: "aaaa"},
		}
	}
	controls := map[string]plugin.ControlResult{
		"sast":    {Report: sarif.Report{Results: []sarif.Result{at(10), at(30)}}},
		"secrets": {Report: sarif.Report{Results: []sarif.Result{at(10)}}},
	}
	numberRepeatedLineHashes(controls)

	got := []string{
		controls["sast"].Report.Results[0].PartialFingerprints[sarif.LineHashKey],
		controls["secrets"].Report.Results[0].PartialFingerprints[sarif.LineHashKey],
		controls["sast"].Report.Results[1].PartialFingerprints[sarif.LineHashKey],
	}
	want := []string{"aaaa", "aaaa:2", "aaaa:3"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("fingerprints = %v, want %v", got, want)
		}
	}
}
