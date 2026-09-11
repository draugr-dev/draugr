package scanpolicy

import (
	"fmt"
	"sort"

	"github.com/draugr-dev/draugr/internal/controllers"
	"github.com/draugr-dev/draugr/pkg/prioritization"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// A gate on a band no component can produce is a gate that cannot fire. Every scan passes it,
// including one carrying an actively exploited critical vulnerability, and the run looks exactly
// like one where the gate worked and found nothing.
//
// It matters more than it reads. The default gate is a priority band, so a descriptor that names
// no threshold and classifies a component below where that band is reachable has **no gate at
// all**, not a weak one. Somebody who set `failOnPriority: P1` asked for the strictest gate the
// product offers and would be told nothing.
//
// Reported rather than refused when only some components are affected: a descriptor may be
// classified today and reclassified tomorrow, and a component list that is about to grow is not a
// failed run. Refused when **no** component can reach the band, because then the gate is inert
// for the whole descriptor and there is nothing a later component can change about this run.

// Unreachable names the components that cannot produce the band this run gates on, with what each
// one is classified as and the worst band it can actually reach.
//
// Empty when the run gates on severity: a severity threshold is reachable from any classification,
// because it does not read one.
func Unreachable(model saga.Model, band string) []string {
	if band == "" {
		return nil
	}
	want := prioritization.Priority(band).Rank()
	if want == 0 {
		return nil
	}
	matrices := prioritization.DefaultMatrices()
	var out []string
	for _, comp := range model.Components {
		best, at := bestBand(matrices, model, comp)
		if prioritization.Priority(best).Rank() >= want {
			continue
		}
		out = append(out, fmt.Sprintf("%s  %s · %s → %s, which ranks %s findings %s",
			comp.Name, declared(string(comp.Exposure), "exposure"), declared(string(comp.Criticality), "criticality"),
			at, worstSeverity, best))
	}
	sort.Strings(out)
	return out
}

// worstSeverity is the severity the "best band" below is reached with, named in the message so a
// reader can see the comparison rather than being handed a conclusion.
const worstSeverity = "critical"

// bestBand is the worst band this component can produce, and the context tier it comes from.
//
// Floors are the reason this is not a table lookup. A control can declare that its findings are
// not bounded by the component at all, `secrets` ranks a leaked credential at the most exposed
// tier wherever it is found, so a component classified `restricted` still reaches P1 when that
// control is enabled. A check that ignored floors would report a gate as dead on descriptors where
// it fires every day.
func bestBand(m prioritization.Matrices, model saga.Model, comp saga.Component) (string, prioritization.Context) {
	tier := m.ContextOf(comp.Exposure, comp.Criticality)
	for _, control := range controllers.ControlsWithContextFloor() {
		if !comp.ControllerEnabled(control, model.Config) {
			continue
		}
		if floor, _ := controllers.ContextFloor(control); floor.Rank() > tier.Rank() {
			tier = floor
		}
	}
	return string(m.PriorityOf(tier, sarif.SeverityCritical)), tier
}

// declared says what a component was classified as, or that it was not.
//
// Never a default rendered as though somebody chose it: an undeclared component ranks at the most
// exposed tier, and printing "public" against a descriptor that says nothing would be the product
// asserting a classification on the author's behalf.
func declared(v string, what string) string {
	if v == "" {
		return "no " + what
	}
	return v
}
