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
