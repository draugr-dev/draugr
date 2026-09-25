package sealed

import (
	"strings"
	"testing"
)

func TestForInitScan(t *testing.T) {
	exp := Expected{
		Findings: []FindingExpectation{
			{Control: "sca", Tool: "trivy", Rule: "CVE-1", Location: "a:1"},
			{Control: "sca", Tool: "trivy", Rule: "CVE-2", Location: "b:1"},
		},
		Errors: []ErrorExpectation{{Control: "sca", Contains: "stale"}},
	}

	got, err := exp.ForInitScan()
	if err != nil || len(got.Findings) != 2 || len(got.Errors) != 1 {
		t.Errorf("with nothing to depart from, ForInitScan changed the expectation: %+v (%v)", got, err)
	}

	none := []ErrorExpectation{}
	exp.InitScan = InitScanExpectation{Unreported: []string{"CVE-2"}, Errors: &none}
	got, err = exp.ForInitScan()
	if err != nil || len(got.Findings) != 1 || got.Findings[0].Rule != "CVE-1" || len(got.Errors) != 0 {
		t.Errorf("ForInitScan = %+v (%v), want CVE-1 alone and no errors", got, err)
	}
	if len(exp.Findings) != 2 {
		t.Error("ForInitScan changed the scenario's own findings")
	}

	exp.InitScan.Unreported = []string{"CVE-3"}
	if _, err := exp.ForInitScan(); err == nil || !strings.Contains(err.Error(), "CVE-3") {
		t.Errorf("an unreported rule no finding has was accepted: %v", err)
	}

	exp.InitScan = InitScanExpectation{Skip: "the options are the subject", Unreported: []string{"CVE-1"}}
	if _, err := exp.ForInitScan(); err == nil || !strings.Contains(err.Error(), "skip") {
		t.Errorf("a skipped init scan with departures that would never be checked was accepted: %v", err)
	}
}
