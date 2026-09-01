package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// TestBothListingsCarryTheReceipts is what a golden cannot catch.
//
// A golden records what the output *is*, so a block dropped from one rendering is captured as
// expected the next time it is regenerated. These are facts a report owes whichever way it was
// asked to list things: what the run did to somebody's systems, what it produced, and whether
// what it read may be stale.
func TestBothListingsCarryTheReceipts(t *testing.T) {
	base := Data{
		Release: saga.Release{Version: "1.0"},
		Verdict: norn.Result{Verdict: norn.Fail},
		Run: engine.Result{
			Effects: []plugin.Effect{{Kind: "network", Detail: "sent requests to a live endpoint"}},
			Stats:   engine.Stats{UnpinnedCacheHits: []string{"acme/api:latest"}},
			Controls: map[string]plugin.ControlResult{"sca": {Control: "sca", Report: sarif.Report{
				Tool: "trivy", Results: []sarif.Result{{
					RuleID: "CVE-1", Level: sarif.LevelError, Priority: "P1", Tool: "trivy",
					Message: "a finding", Location: sarif.Location{URI: "go.mod", StartLine: 1},
				}},
			}}},
		},
	}

	for _, grouped := range []bool{true, false} {
		name := "grouped"
		if !grouped {
			name = "ungrouped"
		}
		t.Run(name, func(t *testing.T) {
			d := base
			d.GroupActions = grouped
			var buf bytes.Buffer
			if err := (consoleReporter{}).Render(&buf, d); err != nil {
				t.Fatal(err)
			}
			out := buf.String()
			// What the scan did to somebody's systems. A consent record that appears in only one
			// listing is one the reader using the other never sees.
			if !strings.Contains(out, "sent requests to a live endpoint") {
				t.Errorf("the effects record is missing:\n%s", out)
			}
			// Whether what was read may be stale. The caveat counts rather than names — the rows
			// carry which — so this asserts it reached the reader, not that it listed anything.
			if !strings.Contains(out, "from cache") {
				t.Errorf("the cache caveat is missing:\n%s", out)
			}
		})
	}
}
