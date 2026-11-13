package sarif

import (
	"bytes"
	"testing"
)

// TestUndecidedSurvivesTheFile is the round trip for the mark on a check a scanner referred to a
// person. It decides which of two scanners' copies of a check is counted, so a report read back by
// `draugr diff` has to carry it as the run did.
func TestUndecidedSurvivesTheFile(t *testing.T) {
	t.Parallel()
	in := Report{
		Results: []Result{{
			// Nothing but the mark, so the property bag is written for it alone.
			RuleID:    "draugr/cis/5.1.10",
			Level:     LevelWarning,
			Message:   "Minimize access to the proxy sub-resource of nodes, requires manual review",
			Location:  Location{URI: "kubernetes/prod"},
			Undecided: true,
		}, {
			RuleID:   "draugr/cis/5.1.1",
			Level:    LevelWarning,
			Message:  "bound to cluster-admin: ci-admin",
			Location: Location{URI: "kubernetes/prod"},
		}},
	}
	data, err := in.MarshalSARIF()
	if err != nil {
		t.Fatal(err)
	}
	if n := bytes.Count(data, []byte(`"undecided": true`)); n != 1 {
		t.Fatalf("the mark is written %d times, want once, on the marked finding only:\n%s", n, data)
	}
	out, err := FromSARIF(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Results) != 2 {
		t.Fatalf("read back %d results, wrote 2", len(out.Results))
	}
	if !out.Results[0].Undecided || out.Results[1].Undecided {
		t.Errorf("undecided read back as %v, %v; want true and false", out.Results[0].Undecided, out.Results[1].Undecided)
	}
}
