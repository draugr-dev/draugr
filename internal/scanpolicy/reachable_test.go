package scanpolicy

import (
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/saga"
)

func comp(name string, exposure saga.Exposure, crit saga.Criticality) saga.Component {
	return saga.Component{Name: name, Exposure: exposure, Criticality: crit}
}

// A gate on a band nothing can produce is a gate that cannot fire, and the run is identical to one
// where it worked and found nothing. These cover the three answers, because acting on them is
// different each time: refuse, warn, say nothing.
func TestUnreachableNamesWhatCannotProduceTheBand(t *testing.T) {
	model := saga.Model{Components: []saga.Component{
		comp("public-api", saga.ExposurePublic, saga.CriticalityCritical),
		comp("internal-tool", saga.ExposureRestricted, saga.CriticalitySupporting),
	}}
	got := Unreachable(model, "P1")
	if len(got) != 1 {
		t.Fatalf("got %d, want just the restricted one: %v", len(got), got)
	}
	// The classification and the band it does reach, so a reader can see the comparison rather
	// than being handed a conclusion they have to take on trust.
	for _, want := range []string{"internal-tool", "restricted", "supporting", "C4", "P2"} {
		if !strings.Contains(got[0], want) {
			t.Errorf("%q missing from %q", want, got[0])
		}
	}
}

func TestAControlsFloorKeepsABandReachable(t *testing.T) {
	// `secrets` ranks a leaked credential at the most exposed tier wherever it is found, so a
	// component classified restricted still reaches P1 when it is enabled. A check that ignored
	// floors would call the gate dead on descriptors where it fires every day.
	restricted := comp("api", saga.ExposureRestricted, saga.CriticalityImportant)
	bare := saga.Model{Components: []saga.Component{restricted}}
	if got := Unreachable(bare, "P1"); len(got) != 1 {
		t.Fatalf("without secrets, P1 should be out of reach: %v", got)
	}

	restricted.Controllers = map[string]saga.ControllerSettings{"secrets": {"enabled": true}}
	withFloor := saga.Model{Components: []saga.Component{restricted}}
	if got := Unreachable(withFloor, "P1"); len(got) != 0 {
		t.Errorf("the secrets floor reaches P1 and this said otherwise: %v", got)
	}
}

func TestUnreachableSaysNothingWhereItCannotApply(t *testing.T) {
	model := saga.Model{Components: []saga.Component{
		comp("api", saga.ExposureRestricted, saga.CriticalitySupporting),
	}}
	// A severity gate does not read a classification, so no classification can put it out of
	// reach. An empty band is a run that gates on severity.
	if got := Unreachable(model, ""); got != nil {
		t.Errorf("a severity gate was reported unreachable: %v", got)
	}
	// A band nobody recognizes ranks 0 and is not a comparison; validation refuses it earlier, and
	// reporting every component against it here would be noise on the way to that error.
	if got := Unreachable(model, "P9"); got != nil {
		t.Errorf("an unparseable band produced findings: %v", got)
	}
	// The loosest band is reachable from every classification there is.
	if got := Unreachable(model, "P4"); got != nil {
		t.Errorf("P4 was reported out of reach: %v", got)
	}
}

func TestAnUndeclaredComponentReachesTheStrictestBand(t *testing.T) {
	// Undeclared ranks at the most exposed tier so findings surface rather than hide, which means
	// the default gate is never dead on a descriptor that has classified nothing. That is the case
	// most projects are in on their first run.
	model := saga.Model{Components: []saga.Component{{Name: "api"}}}
	if got := Unreachable(model, "P1"); got != nil {
		t.Errorf("an unclassified component cannot reach P1: %v", got)
	}
}
