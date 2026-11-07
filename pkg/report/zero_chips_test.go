package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// A band with no findings draws its chip dimmed, in a class the rule that hides an inactive pane
// does not match, so a reader sees the band is empty rather than missing.
func TestAnEmptyBandsChipIsDrawn(t *testing.T) {
	d := Data{Project: "app",
		Verdict: norn.Result{Verdict: norn.Fail, Controls: []norn.ControlOutcome{{Control: "sca", Verdict: norn.Fail}}},
		Run: engine.Result{Controls: map[string]plugin.ControlResult{"sca": {Control: "sca", Report: sarif.Report{
			Tool: "trivy", Results: []sarif.Result{{RuleID: "CVE-1", Level: sarif.LevelError, Priority: "P1", Component: "app"}},
		}}}}}
	var b bytes.Buffer
	if err := (htmlReporter{}).Render(&b, d); err != nil {
		t.Fatal(err)
	}
	page := b.String()
	if !strings.Contains(page, `<span class="sev s-p2 zero">0 P2</span>`) {
		t.Errorf("the empty P2 band has no zero chip")
	}
	if strings.Contains(page, `class="sev s-p2 off"`) || strings.Contains(page, ".sev.off") {
		t.Errorf("a chip still wears the class that hides a pane")
	}
	if !strings.Contains(page, ".sev.zero {") {
		t.Errorf("the zero chip has no style of its own")
	}
}
