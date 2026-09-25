package sealed

import (
	"fmt"
	"os"
	"slices"

	"gopkg.in/yaml.v3"
)

// SemgrepDefaultRefusal is text the sast control's error carries when Semgrep refuses to run offline
// on the default ruleset, which is what a descriptor naming no ruleset asks for.
const SemgrepDefaultRefusal = "cannot run offline: config.controls.sast.semgrep.config is unset"

// InitScanExpectation is where a scan with the descriptor `draugr init` wrote departs from the
// scenario's findings and errors. Every scenario is scanned both ways, so a finding that depends
// on a descriptor option init does not write has to be named here, and a default that stops
// reaching one fails the scenario.
type InitScanExpectation struct {
	// Skip is why a scan with init's descriptor is not compared, for a scenario whose descriptor
	// is the subject: options init never writes, or components declared by hand. It is logged.
	Skip string `yaml:"skip"`
	// Unreported are rules from findings that init's descriptor does not report, because they
	// need an option the hand-written descriptor sets and init leaves at its default.
	Unreported []string `yaml:"unreported"`
	// Errors replace the scenario's errors for this scan, where init enables a different set of
	// controls from the ones the scenario's failure reaches. Unset keeps the scenario's; empty
	// means every control runs. Semgrep's offline refusal is added to either, where
	// InitRefusesSemgrep says it applies.
	Errors *[]ErrorExpectation `yaml:"errors"`
}

// InitRefusesSemgrep reports whether a scan with init's descriptor has Semgrep refuse to run. init
// names no ruleset, Semgrep's default is fetched from its registry, and an offline scan refuses a
// ruleset it would fetch, so the sast control reports SemgrepDefaultRefusal wherever init enables it,
// Semgrep is on PATH and the scan runs with --offline.
func (e Expected) InitRefusesSemgrep() bool {
	return slices.Contains(e.Init.Controls, "sast") && e.Sealed.WithoutTool != "semgrep" && !e.Sealed.WithoutOffline
}

// ForInitScan is e as a scan with init's descriptor must match it.
func (e Expected) ForInitScan() (Expected, error) {
	if e.InitScan.Skip != "" && (e.InitScan.Unreported != nil || e.InitScan.Errors != nil) {
		return Expected{}, fmt.Errorf("initScan.skip is set, so its unreported and errors would never be checked")
	}
	refused := e.InitRefusesSemgrep()
	out := e
	out.Findings = nil
	matched := map[string]bool{}
	for _, f := range e.Findings {
		if slices.Contains(e.InitScan.Unreported, f.Rule) {
			matched[f.Rule] = true
			continue
		}
		if refused && f.Tool == "semgrep" {
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
	if refused {
		out.Errors = append(slices.Clone(out.Errors), ErrorExpectation{Control: "sast", Contains: SemgrepDefaultRefusal})
	}
	return out, nil
}

// WithoutRules is anns less the annotations for rules, for a scan in which the scanner that
// declares them did not run.
func WithoutRules(anns []Annotation, rules []string) []Annotation {
	var out []Annotation
	for _, a := range anns {
		if !slices.Contains(rules, a.Rule) {
			out = append(out, a)
		}
	}
	return out
}

// SemgrepRuleIDs are the ids of the rules a Semgrep rules file declares.
func SemgrepRuleIDs(path string) ([]string, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- a rules file under testdata
	if err != nil {
		return nil, err
	}
	var doc struct {
		Rules []struct {
			ID string `yaml:"id"`
		} `yaml:"rules"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	ids := make([]string, 0, len(doc.Rules))
	for _, r := range doc.Rules {
		ids = append(ids, r.ID)
	}
	return ids, nil
}
