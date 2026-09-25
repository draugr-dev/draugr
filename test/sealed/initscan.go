package sealed

import (
	"fmt"
	"slices"
)

// InitScanExpectation is where a scan with the descriptor `draugr init` wrote departs from the
// scenario's findings and errors. Every scenario is scanned both ways, so a finding that depends
// on a descriptor option init does not write has to be named here, and a default that stops
// reaching one fails the scenario.
type InitScanExpectation struct {
	// Unreported are rules from findings that init's descriptor does not report, because they
	// need an option the hand-written descriptor sets and init leaves at its default.
	Unreported []string `yaml:"unreported"`
	// Errors replace the scenario's errors for this scan, where init enables a different set of
	// controls from the ones the scenario's failure reaches. Unset keeps the scenario's; empty
	// means every control runs.
	Errors *[]ErrorExpectation `yaml:"errors"`
}

// ForInitScan is e as a scan with init's descriptor must match it.
func (e Expected) ForInitScan() (Expected, error) {
	out := e
	out.Findings = nil
	matched := map[string]bool{}
	for _, f := range e.Findings {
		if slices.Contains(e.InitScan.Unreported, f.Rule) {
			matched[f.Rule] = true
			continue
		}
		out.Findings = append(out.Findings, f)
	}
	for _, rule := range e.InitScan.Unreported {
		if !matched[rule] {
			return Expected{}, fmt.Errorf("initScan.unreported names %s, which no finding in expected.yaml reports", rule)
		}
	}
	if e.InitScan.Errors != nil {
		out.Errors = *e.InitScan.Errors
	}
	return out, nil
}
