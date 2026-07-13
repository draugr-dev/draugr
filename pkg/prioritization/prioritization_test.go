package prioritization

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

func TestPriorityRankOrdering(t *testing.T) {
	ranks := []int{P1.Rank(), P2.Rank(), P3.Rank(), P4.Rank()}
	for i := 1; i < len(ranks); i++ {
		if ranks[i] >= ranks[i-1] {
			t.Errorf("priority ranks not strictly descending: %v", ranks)
		}
	}
	if Priority("").Rank() != 0 {
		t.Error("unknown priority should rank 0")
	}
}

func TestDefaultMatricesKeyCells(t *testing.T) {
	m := DefaultMatrices()
	cases := []struct {
		e    saga.Exposure
		c    saga.Criticality
		sev  sarif.Severity
		want Priority
	}{
		{saga.ExposurePublic, saga.CriticalityCritical, sarif.SeverityCritical, P1}, // public + critical + crit
		{saga.ExposurePublic, saga.CriticalityCritical, sarif.SeverityHigh, P1},
		{saga.ExposurePublic, saga.CriticalityCritical, sarif.SeverityLow, P3},       // public+critical but low sev
		{saga.ExposureRestricted, saga.CriticalitySupporting, sarif.SeverityLow, P4}, // restricted + supporting + low
		{saga.ExposureRestricted, saga.CriticalitySupporting, sarif.SeverityCritical, P2},
		{saga.ExposureInternal, saga.CriticalityImportant, sarif.SeverityMedium, P3},
	}
	for _, tc := range cases {
		if got := m.Prioritize(tc.e, tc.c, tc.sev); got != tc.want {
			t.Errorf("Prioritize(%s,%s,%s) = %s, want %s", tc.e, tc.c, tc.sev, got, tc.want)
		}
	}
}

// The shipped matrices must be monotonic: making a component more exposed or more critical,
// or a finding more severe, must never lower its priority.
func TestDefaultMatricesMonotonic(t *testing.T) {
	m := DefaultMatrices()
	exp := []saga.Exposure{saga.ExposurePublic, saga.ExposureAuthenticated, saga.ExposureInternal, saga.ExposureRestricted} // most→least
	crit := []saga.Criticality{saga.CriticalityCritical, saga.CriticalityImportant, saga.CriticalitySupporting}
	sev := []sarif.Severity{sarif.SeverityCritical, sarif.SeverityHigh, sarif.SeverityMedium, sarif.SeverityLow}

	// Along each axis (ordered most→least), priority urgency must not increase.
	for _, c := range crit {
		for _, s := range sev {
			for i := 1; i < len(exp); i++ {
				if m.Prioritize(exp[i], c, s).Rank() > m.Prioritize(exp[i-1], c, s).Rank() {
					t.Errorf("exposure not monotonic at %s/%s/%s", exp[i], c, s)
				}
			}
		}
	}
	for _, e := range exp {
		for _, s := range sev {
			for i := 1; i < len(crit); i++ {
				if m.Prioritize(e, crit[i], s).Rank() > m.Prioritize(e, crit[i-1], s).Rank() {
					t.Errorf("criticality not monotonic at %s/%s/%s", e, crit[i], s)
				}
			}
		}
	}
	for _, e := range exp {
		for _, c := range crit {
			for i := 1; i < len(sev); i++ {
				if m.Prioritize(e, c, sev[i]).Rank() > m.Prioritize(e, c, sev[i-1]).Rank() {
					t.Errorf("severity not monotonic at %s/%s/%s", e, c, sev[i])
				}
			}
		}
	}
}

// Unclassified components are treated as worst-case (public/critical) so their findings surface.
func TestUnclassifiedTreatedAsElevated(t *testing.T) {
	m := DefaultMatrices()
	if got := m.ContextOf("", ""); got != C1 {
		t.Errorf("unclassified context = %s, want C1", got)
	}
	if got := m.ContextOf("bogus", "bogus"); got != C1 {
		t.Errorf("invalid classification context = %s, want C1", got)
	}
	// Same priority as an explicit public/critical.
	if m.Prioritize("", "", sarif.SeverityHigh) != m.Prioritize(saga.ExposurePublic, saga.CriticalityCritical, sarif.SeverityHigh) {
		t.Error("unclassified should match public/critical")
	}
}

func TestPriorityOfUnknownSeverity(t *testing.T) {
	m := DefaultMatrices()
	// Unknown severity treated as low: C1 × low = P3.
	if got := m.PriorityOf(C1, sarif.Severity("bogus")); got != P3 {
		t.Errorf("unknown severity at C1 = %s, want P3 (treated as low)", got)
	}
}

func TestIncompleteMatricesFallBackSafely(t *testing.T) {
	// An override that dropped cells must not misrank — it falls back to worst-case concern
	// (C1) and a mid priority (P2) rather than returning an empty band.
	empty := Matrices{
		ContextTier:  map[saga.Exposure]map[saga.Criticality]Context{},
		PriorityBand: map[Context]map[sarif.Severity]Priority{},
	}
	if got := empty.ContextOf(saga.ExposurePublic, saga.CriticalityCritical); got != C1 {
		t.Errorf("missing context cell = %s, want C1", got)
	}
	if got := empty.PriorityOf(C1, sarif.SeverityHigh); got != P2 {
		t.Errorf("missing priority cell = %s, want P2", got)
	}
}

func TestOverrideCell(t *testing.T) {
	m := DefaultMatrices()
	// Org treats crown jewels (critical) as always highest concern regardless of exposure.
	m.ContextTier[saga.ExposureRestricted][saga.CriticalityCritical] = C1
	if got := m.Prioritize(saga.ExposureRestricted, saga.CriticalityCritical, sarif.SeverityCritical); got != P1 {
		t.Errorf("overridden restricted/critical crit = %s, want P1", got)
	}
	// A fresh default is unaffected (override mutated only this copy's maps).
	if DefaultMatrices().ContextOf(saga.ExposureRestricted, saga.CriticalityCritical) != C3 {
		t.Error("DefaultMatrices should return the shipped defaults, not the override")
	}
}
