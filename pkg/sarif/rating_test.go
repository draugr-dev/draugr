package sarif

import (
	"encoding/json"
	"strings"
	"testing"
)

// A scanner's own rating sets the severity where it decided one: a numeric score still wins, and
// the level answers only where neither is there.
func TestResultSeverityTakesTheScannersRating(t *testing.T) {
	rated := Result{Level: LevelError, Rating: &Rating{Severity: SeverityCritical, Detail: "impact high · likelihood high"}}
	if got := rated.Severity(""); got != SeverityCritical {
		t.Errorf("rated severity = %s, want the rating's critical over error's high", got)
	}
	lowered := Result{Level: LevelError, Rating: &Rating{Severity: SeverityLow}}
	if got := lowered.Severity(""); got != SeverityLow {
		t.Errorf("rated severity = %s, want the rating's low", got)
	}
	if got := lowered.Severity(SeverityHigh); got != SeverityHigh {
		t.Errorf("floored severity = %s, want the floor to raise a rated low", got)
	}
	scored := Result{Level: LevelNote, Score: 9.8, HasScore: true, Rating: &Rating{Severity: SeverityLow}}
	if got := scored.Severity(""); got != SeverityCritical {
		t.Errorf("scored severity = %s, want the score", got)
	}
	// A rating whose severity is not a band says nothing a severity can be read from.
	unreadable := Result{Level: LevelWarning, Rating: &Rating{Severity: "severe"}}
	if got := unreadable.Severity(""); got != SeverityMedium {
		t.Errorf("unreadable rating = %s, want the level's medium", got)
	}
}

// The rating survives the file with the scanner's words and its level intact, under a key no other
// tool's property bag is likely to use.
func TestRatingSurvivesTheFile(t *testing.T) {
	rep := Report{Results: []Result{{
		RuleID: "python.lang.security.dangerous-system-call.dangerous-system-call", Level: LevelError,
		Message: "a shell", Rating: &Rating{
			Severity: SeverityCritical, Detail: "impact high · likelihood high",
			Fields: map[string]string{"impact": "HIGH", "likelihood": "HIGH", "confidence": "MEDIUM", "subcategory": "vuln"},
		},
	}}}
	encoded, err := rep.MarshalSARIF()
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Runs []struct {
			Results []struct {
				Level      string                     `json:"level"`
				Properties map[string]json.RawMessage `json:"properties"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(encoded, &doc); err != nil {
		t.Fatal(err)
	}
	written := doc.Runs[0].Results[0]
	if written.Level != "error" {
		t.Errorf("level = %q, want the scanner's error", written.Level)
	}
	if _, ok := written.Properties["draugr/rating"]; !ok {
		t.Errorf("no draugr/rating in %s", encoded)
	}
	back, err := FromSARIF(encoded)
	if err != nil {
		t.Fatal(err)
	}
	got := back.Results[0]
	if got.Rating == nil || got.Rating.Severity != SeverityCritical || got.Rating.Detail != "impact high · likelihood high" ||
		got.Rating.Fields["subcategory"] != "vuln" || got.Severity("") != SeverityCritical {
		t.Errorf("read back %+v", got.Rating)
	}
	// Not part of the identity: the same finding with and without a rating is one finding.
	unrated := rep.Results[0]
	unrated.Rating = nil
	if unrated.Fingerprint() != rep.Results[0].Fingerprint() {
		t.Error("the rating changed the fingerprint")
	}
}

// A rating alone is enough to write the property bag, or a finding carrying nothing else loses it.
func TestARatingAloneIsEnoughToWriteProperties(t *testing.T) {
	rep := Report{Results: []Result{{RuleID: "B602", Level: LevelError, Message: "a shell",
		Rating: &Rating{Severity: SeverityHigh, Detail: "issue_severity high"}}}}
	encoded, err := rep.MarshalSARIFWith(MarshalOptions{Compact: true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"draugr/rating"`) {
		t.Errorf("the rating was dropped for a finding with no other properties:\n%s", encoded)
	}
}
