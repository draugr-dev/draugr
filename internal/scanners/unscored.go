package scanners

import (
	"regexp"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// notScoredYet labels a vulnerability its source has not scored yet: an advisory published before
// its database rated it, as Trivy's UNKNOWN, Grype's Unknown and an OSV record with no severity are.
const notScoredYet = sarif.NotScoredYet

// markNotScored ranks r, a vulnerability with no score and no rating from its source, as high, and
// labels it as not scored yet in its rating and at the end of its message, which every report and
// upload shows.
//
// Ranked high rather than low, because a missing score says nothing about how bad the flaw is, and
// reading it as the mildest band is the safer assumption made under doubt. A newly published CVE is
// the usual case, and it is also one a reader needs to see. Once its database scores it, the score
// decides, and the label goes. Not critical: that band is for a flaw somebody has rated critical.
// Labeled, because a band of high with nothing beside it reads as a rating somebody gave.
//
// fields are the rating fields the scanner published, under its own names, such as Trivy's
// {"severity": "UNKNOWN"}. message is the message to end with the label.
func markNotScored(r *sarif.Result, fields map[string]string, message string) {
	r.Score, r.HasScore = 0, false
	r.Level = sarif.LevelError
	r.Rating = newRating(sarif.SeverityHigh, fields, notScoredYet)
	r.Message = message + sarif.MessageNotScoredYet
}

// grypeSeverityOpening is the opening of Grype's message, "A high vulnerability in", naming the
// severity it read.
var grypeSeverityOpening = regexp.MustCompile(`^An? \S+ vulnerability in `)

// withoutGrypeSeverity is Grype's message without the severity word it wrote for a vulnerability it
// has not rated, which for Unknown is "low" and so says something untrue.
func withoutGrypeSeverity(message string) string {
	if loc := grypeSeverityOpening.FindStringIndex(message); loc != nil {
		return "A vulnerability in " + message[loc[1]:]
	}
	return message
}
