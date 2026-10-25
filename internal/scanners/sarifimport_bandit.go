package scanners

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// banditSeverity is the severity each of Bandit's issue_severity ratings gives.
//
// Bandit rates on three rungs, and nothing in its output says which of its HIGH results would be
// critical, so none is.
var banditSeverity = map[string]sarif.Severity{
	"HIGH":   sarif.SeverityHigh,
	"MEDIUM": sarif.SeverityMedium,
	"LOW":    sarif.SeverityLow,
}

// banditRatingFields are the result properties a Bandit rating is read from, in the order its
// detail names them.
var banditRatingFields = []string{"issue_severity", "issue_confidence"}

// banditRating is the rating a Bandit result's properties give, or nil for one with no
// issue_severity Draugr has a row for, which keeps its level.
//
// A result Bandit rates confidence LOW is one band lower than its severity. Bandit's level already
// follows issue_severity, so the confidence is what the level loses.
//
// The detail names Bandit's own properties. Printed as "severity medium" beside a finding Draugr
// ranks low, the scanner's word would read as a contradiction of the severity next to it.
func banditRating(props map[string]any) *sarif.Rating {
	word, ok := ratingWord(props["issue_severity"])
	if !ok {
		return nil
	}
	severity := banditSeverity[word]
	detail := []string{"issue_severity " + strings.ToLower(word)}
	if confidence, _ := ratingWord(props["issue_confidence"]); confidence == "LOW" {
		detail = append(detail, "issue_confidence low")
		severity = severity.Deescalate()
	}
	return newRating(severity, ratingFields(props, banditRatingFields...), detail...)
}

// rateBandit rates each result of a run Bandit wrote from its issue_severity and issue_confidence.
//
// Read from the runs whose driver is Bandit, and from no other: the table is for Bandit's words,
// and another tool writing properties of the same name has not said it means the same thing by
// them. A result carrying a numeric score keeps it.
func rateBandit(rep *sarif.Report, data []byte) error {
	var log struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Name string `json:"name"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				Properties map[string]any `json:"properties"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(data, &log); err != nil {
		return fmt.Errorf("read Bandit's ratings: %w", err)
	}
	// FromSARIF flattens the runs' results in order, so the i-th result read here is rep's i-th.
	i := 0
	for _, run := range log.Runs {
		bandit := strings.EqualFold(run.Tool.Driver.Name, "bandit")
		for _, res := range run.Results {
			if i >= len(rep.Results) {
				return nil
			}
			at := &rep.Results[i]
			i++
			if !bandit || at.HasScore {
				continue
			}
			if r := banditRating(res.Properties); r != nil {
				at.Rating = r
			}
		}
	}
	return nil
}
