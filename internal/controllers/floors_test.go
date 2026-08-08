package controllers

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

func TestSeverityFloor(t *testing.T) {
	if got := SeverityFloor("secrets"); got != sarif.SeverityHigh {
		t.Errorf("secrets floor = %q, want high", got)
	}
	// A control with no declared floor returns the empty severity (no floor).
	if got := SeverityFloor("sca"); got != "" {
		t.Errorf("sca floor = %q, want none", got)
	}
}

func TestContextFloorIsDeclaredWithItsReason(t *testing.T) {
	// A floor with no reason produces a band nobody can account for from the report, which is the
	// half of this that matters to a reader.
	for control := range contextFloors {
		floor, reason := ContextFloor(control)
		if floor == "" {
			t.Errorf("%s: declared in contextFloors but ContextFloor returned nothing", control)
		}
		if reason == "" {
			t.Errorf("%s: a floor with no reason is a band a reader has to take on trust", control)
		}
	}
	if floor, reason := ContextFloor("sca"); floor != "" || reason != "" {
		t.Errorf("sca declares no floor, got %q / %q", floor, reason)
	}
}
