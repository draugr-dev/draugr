package scanners

import (
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
// A result Bandit rates confidence LOW is one level lower than its severity. Bandit's level already
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

// banditSource names the rating a Bandit file's severities came from.
const banditSource = "issue_severity and issue_confidence"
