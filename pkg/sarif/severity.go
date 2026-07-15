package sarif

// Severity is Draugr's normalized, cross-control severity ladder. Unlike Level (the SARIF
// wire values error/warning/note), Severity is what prioritization ranks on: it splits a
// numeric CVSS-style score into four bands so a dependency CVE, a leaked secret, and an IaC
// misconfiguration can share one ordered list. See docs/concepts.md (prioritization).
type Severity string

// Severity bands, from most to least severe.
const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

// Rank orders severities (higher is worse): critical=4, high=3, medium=2, low=1,
// empty/unknown=0.
func (s Severity) Rank() int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

// AtLeast reports whether s is at least as severe as other.
func (s Severity) AtLeast(other Severity) bool { return s.Rank() >= other.Rank() }

// Escalate returns the next-higher severity band; critical is already the maximum. Used by
// exploitability enrichment to bump a finding one band.
func (s Severity) Escalate() Severity {
	switch s {
	case SeverityLow:
		return SeverityMedium
	case SeverityMedium:
		return SeverityHigh
	default: // high → critical, critical → critical
		return SeverityCritical
	}
}

// severityFromScore maps a numeric CVSS-style score (0–10) to a band, using the standard
// CVSS v3 ranges.
func severityFromScore(score float64) Severity {
	switch {
	case score >= 9.0:
		return SeverityCritical
	case score >= 7.0:
		return SeverityHigh
	case score >= 4.0:
		return SeverityMedium
	default:
		return SeverityLow
	}
}

// severityFromLevel maps a SARIF level to a band, for findings that carry no numeric score
// (e.g. secrets, SAST, IaC). error→high, warning→medium, note/none→low.
func severityFromLevel(l Level) Severity {
	switch l {
	case LevelError:
		return SeverityHigh
	case LevelWarning:
		return SeverityMedium
	default:
		return SeverityLow
	}
}

// Severity resolves a finding's normalized severity, in the order the SARIF/prioritization
// design prescribes:
//
//  1. the finding's numeric score (CVSS / SARIF security-severity), if present;
//  2. otherwise its SARIF level;
//  3. then raised to floor if floor is more severe (a control-default floor, e.g. a leaked
//     secret is never "low"). Pass an empty floor for no floor.
func (r Result) Severity(floor Severity) Severity {
	base := severityFromLevel(r.Level)
	if r.HasScore {
		base = severityFromScore(r.Score)
	}
	if floor.Rank() > base.Rank() {
		return floor
	}
	return base
}
