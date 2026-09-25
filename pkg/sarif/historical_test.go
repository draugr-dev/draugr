package sarif

import (
	"bytes"
	"testing"
)

// TestHistoricalSurvivesTheFile is the round trip for the history mark. A history finding names
// the path its file had in an old commit, so without the mark a reader of the file sees a finding
// at a path the checkout lacks and cannot tell it from one already fixed.
func TestHistoricalSurvivesTheFile(t *testing.T) {
	in := Report{
		Results: []Result{{
			// Nothing but the mark, so the property bag is written for it alone.
			RuleID:     "aws-access-token",
			Level:      LevelError,
			Message:    "AWS access token",
			Location:   Location{URI: "old/aws.env", StartLine: 1},
			Historical: true,
		}, {
			RuleID:   "aws-access-token",
			Level:    LevelError,
			Message:  "AWS access token",
			Location: Location{URI: "app/settings.py", StartLine: 3},
		}},
	}
	data, err := in.MarshalSARIF()
	if err != nil {
		t.Fatal(err)
	}
	if n := bytes.Count(data, []byte(`"historical": true`)); n != 1 {
		t.Fatalf("the history mark is written %d times, want once, on the history finding only:\n%s", n, data)
	}
	out, err := FromSARIF(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Results) != 2 {
		t.Fatalf("read back %d results, wrote 2", len(out.Results))
	}
	if !out.Results[0].Historical || out.Results[1].Historical {
		t.Errorf("historical read back as %v, %v; want true, false",
			out.Results[0].Historical, out.Results[1].Historical)
	}
}
