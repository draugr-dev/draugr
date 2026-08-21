package report

import (
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
)

func TestReachabilityLineNamesTheUndetermined(t *testing.T) {
	// Unknown is the honest qualifier on the rest of the sentence: an analyzer that could not
	// cover half the dependencies has said much less than the unreachable count suggests.
	line := reachabilityLine(Data{Run: engine.Result{Reachability: engine.ReachabilitySummary{
		Analyzer: "govulncheck", Reachable: 2, Unreachable: 6, Unknown: 3,
	}}})
	for _, want := range []string{"govulncheck", "2 reachable", "6 not", "3 undetermined", "ranked down, not removed"} {
		if !strings.Contains(line, want) {
			t.Errorf("line %q does not mention %q", line, want)
		}
	}
}

func TestReachabilityLineOmitsUndeterminedWhenThereAreNone(t *testing.T) {
	line := reachabilityLine(Data{Run: engine.Result{Reachability: engine.ReachabilitySummary{
		Analyzer: "govulncheck", Reachable: 2, Unreachable: 6,
	}}})
	if strings.Contains(line, "undetermined") {
		t.Errorf("line %q mentions undetermined when there were none", line)
	}
}

func TestReachabilityLineSilentWhenNothingRan(t *testing.T) {
	if line := reachabilityLine(Data{Run: engine.Result{}}); line != "" {
		t.Errorf("line = %q, want nothing when no analyzer ran", line)
	}
}
