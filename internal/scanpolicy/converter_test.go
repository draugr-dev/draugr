package scanpolicy

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// A converter's raise is a floor under the band: it lifts a band below it to the one it names, with
// the converter's reason, and leaves a band at or above it where it is.
func TestAConvertersRaiseIsAFloorUnderTheBand(t *testing.T) {
	rank := PrioritizerWith(nil, nil)
	raised := func(priority string) sarif.Result {
		return sarif.Result{RuleID: "GHSA-x", Level: sarif.LevelWarning,
			Converter: &sarif.Converter{Name: "acme-deps", Raise: &sarif.Raise{Priority: priority, Reason: "listed"}}}
	}
	low := rank("sca", saga.ExposureInternal, saga.CriticalitySupporting, raised("P1"))
	if low.Band != "P1" || low.Floor != "raised to P1 by converter acme-deps, listed" {
		t.Errorf("band %s, floor %q, want P1 with the converter's reason", low.Band, low.Floor)
	}
	high := rank("sca", saga.ExposurePublic, saga.CriticalityCritical, raised("P4"))
	plain := rank("sca", saga.ExposurePublic, saga.CriticalityCritical, sarif.Result{RuleID: "GHSA-x", Level: sarif.LevelWarning})
	if high.Band != plain.Band || high.Floor != "" {
		t.Errorf("band %s, floor %q, want %s and no floor: a raise never lowers", high.Band, high.Floor, plain.Band)
	}
	stamped := sarif.Result{RuleID: "GHSA-x", Level: sarif.LevelWarning, Converter: &sarif.Converter{Name: "acme-deps"}}
	if got := rank("sca", saga.ExposureInternal, saga.CriticalitySupporting, stamped); got.Floor != "" {
		t.Errorf("a converter that asked no raise moved the band: %+v", got)
	}
}
