package report

import (
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// A finding a converter raised gives the converter's reason under the row and wears no `↑ floor`,
// which the Signals row counts as a control's own rule; a finding it only set properties on says
// which ones.
func TestAConvertersFindingSaysWhatItSetAndWhyItWasRaised(t *testing.T) {
	stamp := func(raise *sarif.Raise) *sarif.Converter {
		return &sarif.Converter{Name: "acme-deps", Contract: 1, Set: []string{"package", "cwe"}, Raise: raise}
	}
	raised := stamp(&sarif.Raise{Priority: "P1", Reason: "listed"})
	d := Data{Run: engine.Result{Controls: map[string]plugin.ControlResult{
		"sca": {Control: "sca", Report: sarif.Report{Results: []sarif.Result{
			{RuleID: "GHSA-a", Tool: "Acme", Scanner: plugin.ImportScanner, Level: sarif.LevelWarning, Priority: "P1",
				Message: "raised one", Converter: raised, PriorityFloor: raised.RaiseNote()},
			{RuleID: "GHSA-b", Tool: "Acme", Scanner: plugin.ImportScanner, Level: sarif.LevelWarning, Priority: "P2",
				Message: "plain one", Converter: stamp(nil)},
		}}},
	}}}
	out := renderConsole(t, d)
	for _, want := range []string{"raised to P1 by converter acme-deps, listed", "converter acme-deps: package, cwe"} {
		if !strings.Contains(out, want) {
			t.Errorf("console is missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "floor") {
		t.Errorf("a converter's raise is shown as a control's floor:\n%s", out)
	}
	if keys := signalKeys(findingOf("sca", sarif.Report{}, d.Run.Controls["sca"].Report.Results[0])); strings.Contains(strings.Join(keys, " "), signalKeyFloor) {
		t.Errorf("signal keys %v count the raise as a floor", keys)
	}
	if converterSet(stamp(nil)) == "" || converterSet(&sarif.Converter{Name: "x"}) != "" || converterSet(nil) != "" {
		t.Error("converterSet speaks for a converter that set nothing, or is silent for one that did")
	}
}
