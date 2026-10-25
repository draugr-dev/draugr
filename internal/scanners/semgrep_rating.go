package scanners

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// semgrepCell is one cell of the impact × likelihood table, each in Semgrep's upper case.
type semgrepCell struct{ impact, likelihood string }

// semgrepMatrix is the severity a rule's impact and likelihood give it.
//
// The cells are the OWASP Risk Rating Methodology's overall-severity table, whose lowest cell, Note,
// is low here because Draugr has no band below it. Semgrep publishes the two ratings and says a
// registry rule's severity is assigned from them, without publishing the combination, so a table
// somebody else wrote and others already read is the one a reader can check.
var semgrepMatrix = map[semgrepCell]sarif.Severity{
	{"HIGH", "HIGH"}:     sarif.SeverityCritical,
	{"HIGH", "MEDIUM"}:   sarif.SeverityHigh,
	{"HIGH", "LOW"}:      sarif.SeverityMedium,
	{"MEDIUM", "HIGH"}:   sarif.SeverityHigh,
	{"MEDIUM", "MEDIUM"}: sarif.SeverityMedium,
	{"MEDIUM", "LOW"}:    sarif.SeverityLow,
	{"LOW", "HIGH"}:      sarif.SeverityMedium,
	{"LOW", "MEDIUM"}:    sarif.SeverityLow,
	{"LOW", "LOW"}:       sarif.SeverityLow,
}

// semgrepRatingFields are the rule metadata a rating is read from, in the order its detail names
// them.
var semgrepRatingFields = []string{"impact", "likelihood", "confidence", "subcategory"}

// semgrepRating is the rating a rule's metadata gives, or nil for a rule that does not state both
// its impact and its likelihood, which keeps the level Semgrep wrote.
//
// A rule that expects false positives, by confidence LOW, or that flags a pattern for review, by
// subcategory audit, is one band lower than its impact and likelihood give. Once, where it is both:
// Semgrep defines the two in the same words, a result to look at rather than a flaw it confirmed,
// and lowering twice would count one fact two bands. A secure-default rule is not lowered. It names
// a safer default, and its impact and likelihood say how much the current choice matters.
func semgrepRating(meta map[string]any) *sarif.Rating {
	impact, ok := ratingWord(meta["impact"])
	if !ok {
		return nil
	}
	likelihood, ok := ratingWord(meta["likelihood"])
	if !ok {
		return nil
	}
	severity := semgrepMatrix[semgrepCell{impact, likelihood}]
	detail := []string{"impact " + strings.ToLower(impact), "likelihood " + strings.ToLower(likelihood)}
	lowered := false
	if confidence, _ := ratingWord(meta["confidence"]); confidence == "LOW" {
		detail = append(detail, "confidence low")
		lowered = true
	}
	if semgrepAudit(meta["subcategory"]) {
		detail = append(detail, "subcategory audit")
		lowered = true
	}
	if lowered {
		severity = severity.Deescalate()
	}
	return newRating(severity, ratingFields(meta, semgrepRatingFields...), detail...)
}

// semgrepAudit reports whether a rule's subcategory names audit. Semgrep's registry writes it as a
// list, and as a bare string in a few rules.
func semgrepAudit(v any) bool {
	var subs []string
	switch t := v.(type) {
	case string:
		subs = []string{t}
	case []any:
		for _, e := range t {
			if s, ok := e.(string); ok {
				subs = append(subs, s)
			}
		}
	}
	return slices.ContainsFunc(subs, func(s string) bool { return strings.EqualFold(strings.TrimSpace(s), "audit") })
}

// rateSemgrep rates each result from its rule's metadata in doc, the JSON report Semgrep writes
// beside its SARIF.
//
// Keyed by rule rather than by result, because the metadata belongs to the rule, and because the
// JSON leaves out a result a nosemgrep comment suppressed while the SARIF keeps it marked: such a
// result takes its rule's rating wherever another result of that rule was reported. A result
// carrying a numeric score keeps it, Semgrep's SARIF writes none.
func rateSemgrep(report *sarif.Report, doc []byte) error {
	var out struct {
		Results []struct {
			CheckID string `json:"check_id"`
			Extra   struct {
				// Raw, so a rule whose metadata is not an object costs that rule its rating rather
				// than the scan its findings.
				Metadata json.RawMessage `json:"metadata"`
			} `json:"extra"`
		} `json:"results"`
	}
	if err := json.Unmarshal(doc, &out); err != nil {
		return fmt.Errorf("read the JSON report Semgrep writes beside its SARIF: %w", err)
	}
	ratings := map[string]*sarif.Rating{}
	for _, r := range out.Results {
		if _, seen := ratings[r.CheckID]; seen {
			continue
		}
		var meta map[string]any
		_ = json.Unmarshal(r.Extra.Metadata, &meta)
		ratings[r.CheckID] = semgrepRating(meta)
	}
	for i := range report.Results {
		res := &report.Results[i]
		if r := ratings[res.RuleID]; r != nil && !res.HasScore {
			// A copy per result, so nothing one finding does to its rating reaches another's.
			rating := *r
			res.Rating = &rating
		}
	}
	return nil
}
