package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// unsettledEvidenceFlag is where the console lists the checks left for a person, said beside their
// count in a view that does not list them.
const unsettledEvidenceFlag = "--evidence lists them"

// unsettledOf is a control's checks left for a person by one scanner, about one component where the
// provenance names one.
func unsettledOf(d Data, control string, p sarif.Provenance) (waiting, excluded int) {
	for _, u := range d.Run.Controls[control].Report.UnsettledChecks {
		if u.Scanner != p.Tool || (p.Component != "" && u.Component != p.Component) {
			continue
		}
		if u.Suppression != nil {
			excluded++
		} else {
			waiting++
		}
	}
	return waiting, excluded
}

// withUnsettled is p's fields with the count of checks it left for a person beside its coverage,
// which counts only what it decided. A scanner stating no coverage gets the count as a field of its
// own, so a run where it is the only one still says the checks are there. Every format shows these
// lines; where the checks are listed is the console's to say, beside them (see measuredText).
func withUnsettled(d Data, control string, p sarif.Provenance, fields []sarif.Field) []sarif.Field {
	note := unsettledNote(d, control, p)
	if note == "" {
		return fields
	}
	out := make([]sarif.Field, len(fields))
	copy(out, fields)
	for i := range out {
		if out[i].Key == "coverage" {
			out[i].Value += ", " + note
			return out
		}
	}
	return append(out, sarif.Field{Value: note})
}

// unsettledNote counts the checks a scanner left for a person, and those of them excluded, or is
// empty where it left none.
func unsettledNote(d Data, control string, p sarif.Provenance) string {
	waiting, excluded := unsettledOf(d, control, p)
	var parts []string
	if waiting > 0 {
		parts = append(parts, fmt.Sprintf("%d left for a person", waiting))
	}
	if excluded > 0 {
		parts = append(parts, fmt.Sprintf("%d excluded", excluded))
	}
	return strings.Join(parts, ", ")
}

// unsettledChecks is every check the run left for a person, by control, component and location, in
// the order each scanner reported them.
func unsettledChecks(d Data) []sarif.UnsettledCheck {
	var out []sarif.UnsettledCheck
	for _, name := range sortedControlNames(d) {
		out = append(out, d.Run.Controls[name].Report.UnsettledChecks...)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Component != out[j].Component {
			return out[i].Component < out[j].Component
		}
		return out[i].Location < out[j].Location
	})
	return out
}

// unsettledRows are the EVIDENCE block's rows for the checks left for a person: a row per target
// counting them, then a row per check, its rule id as config.exclude takes it and its title, or the
// reason it was excluded.
func unsettledRows(d Data) (heads []string, checks [][]string) {
	all := unsettledChecks(d)
	idWidth := 0
	for _, u := range all {
		idWidth = max(idWidth, len([]rune(u.RuleID)))
	}
	for i := 0; i < len(all); {
		first := all[i]
		var rows []string
		waiting, excluded := 0, 0
		for ; i < len(all) && all[i].Component == first.Component && all[i].Location == first.Location; i++ {
			u := all[i]
			text := u.Title
			if u.Suppression != nil {
				excluded++
				text = "excluded · " + u.Suppression.Justification
			} else {
				waiting++
			}
			rows = append(rows, fmt.Sprintf("%-*s  %s", idWidth, u.RuleID, text))
		}
		var parts []string
		if waiting > 0 {
			parts = append(parts, fmt.Sprintf("%d left for a person", waiting))
		}
		if excluded > 0 {
			parts = append(parts, fmt.Sprintf("%d excluded", excluded))
		}
		heads = append(heads, first.Location+" · "+strings.Join(parts, ", "))
		checks = append(checks, rows)
	}
	return heads, checks
}
