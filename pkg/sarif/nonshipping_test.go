package sarif

import (
	"bytes"
	"testing"
)

// TestNonShippingSurvivesTheFile is the round trip for the mark on a finding under documentation,
// examples or tests. A report read back by `draugr diff` lists findings by it, so a mark lost on the
// way through the file would list a test fixture's finding among the shipped code's.
func TestNonShippingSurvivesTheFile(t *testing.T) {
	t.Parallel()
	in := Report{
		Results: []Result{{
			// Nothing but the mark, so the property bag is written for it alone.
			RuleID:      "DS-0002",
			Level:       LevelError,
			Message:     "Image user should not be 'root'",
			Location:    Location{URI: "tests/Dockerfile", StartLine: 1},
			NonShipping: "test",
		}, {
			RuleID:   "DS-0002",
			Level:    LevelError,
			Message:  "Image user should not be 'root'",
			Location: Location{URI: "Dockerfile", StartLine: 1},
		}},
	}
	data, err := in.MarshalSARIF()
	if err != nil {
		t.Fatal(err)
	}
	if n := bytes.Count(data, []byte(`"nonShipping": "test"`)); n != 1 {
		t.Fatalf("the mark is written %d times, want once, on the marked finding only:\n%s", n, data)
	}
	out, err := FromSARIF(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Results) != 2 {
		t.Fatalf("read back %d results, wrote 2", len(out.Results))
	}
	if out.Results[0].NonShipping != "test" || out.Results[1].NonShipping != "" {
		t.Errorf("nonShipping read back as %q, %q; want test and nothing",
			out.Results[0].NonShipping, out.Results[1].NonShipping)
	}
}
