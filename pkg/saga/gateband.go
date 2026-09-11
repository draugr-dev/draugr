package saga

import (
	"fmt"
	"slices"
	"strings"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// A gate is one threshold written in one of two vocabularies, and which vocabulary it is written
// in is what decides the question being asked.
//
// `P1` asks what band a finding landed in for the component it was found in, which folds in the
// exposure and criticality this descriptor declares. `high` asks what the scanner called the flaw
// on its own terms. One field rather than two keys, because two keys made it possible to write
// both, and a verdict with two possible reasons cannot be read back to the rule that produced it.
// With one field the contradiction is not expressible, which is a better guarantee than an error
// message about it.
//
// The two vocabularies do not overlap — P1 through P4 against critical, high, medium, low, plus
// the SARIF levels a gate used to take — so a value says which it is without being told.

// GateKind is which question a threshold asks.
type GateKind int

const (
	// GateNone is a threshold nobody wrote.
	GateNone GateKind = iota
	// GatePriority is a band: the ranking this product computes.
	GatePriority
	// GateSeverity is a severity: what the scanner called it.
	GateSeverity
)

// ParseGate reads a threshold and says which vocabulary it is written in.
//
// The error names both vocabularies, because somebody who wrote a word that is in neither cannot
// tell from a message about one of them whether they misspelled a band or reached for a severity.
func ParseGate(value string) (GateKind, string, error) {
	v := strings.TrimSpace(value)
	if v == "" {
		return GateNone, "", nil
	}
	if slices.Contains(Priorities, strings.ToUpper(v)) {
		return GatePriority, strings.ToUpper(v), nil
	}
	// Severities, and the SARIF levels still accepted, are both ParseSeverity's business. Reusing
	// it keeps one answer to "is this a severity" rather than a second list that drifts from it.
	if sev, err := sarif.ParseSeverity(v); err == nil {
		return GateSeverity, string(sev), nil
	}
	return GateNone, "", fmt.Errorf(
		"%q is neither a priority band (%s) nor a severity (%s)",
		value, strings.Join(Priorities, ", "), strings.Join(gateSeverityWords(), ", "))
}

// gateSeverityWords names the severities a gate takes, for a message. The bands the report prints,
// not every spelling accepted: the older SARIF levels still work, and telling somebody making a
// fresh mistake about them teaches the wrong vocabulary.
func gateSeverityWords() []string {
	out := make([]string, 0, len(GateThresholds))
	for _, s := range GateThresholds {
		out = append(out, string(s))
	}
	return out
}

// Resolved is the gate this block asks for, from whichever spelling it was written in.
//
// One accessor, because reading the older field is the whole point of keeping it and every caller
// doing it themselves is a caller that will forget the new one. That has already happened once:
// a reader of `failOnPriority` alone reported no gate at all for a descriptor that had written the
// band in `failOn`.
//
// Validation refuses both together, so precedence here only decides what a descriptor that never
// reaches validation gets, and the current spelling wins.
func (g *GateConfig) Resolved() (GateKind, string) {
	if g == nil {
		return GateNone, ""
	}
	if g.FailOn != "" {
		kind, value, err := ParseGate(g.FailOn)
		if err == nil {
			return kind, value
		}
		return GateNone, ""
	}
	//nolint:staticcheck // SA1019: reading the older spelling is what keeps a descriptor written
	// before the merge working, and this is the one place that does it.
	if band := g.FailOnPriority; band != "" {
		kind, value, err := ParseGate(band)
		if err == nil {
			return kind, value
		}
	}
	return GateNone, ""
}
