package skald

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// producedBy is a run in which two scanners ran, one of which could not be asked its version.
func producedBy() engine.Result {
	return engine.Result{Controls: map[string]plugin.ControlResult{
		"sca": {Control: "sca", Report: sarif.Report{
			Provenance: []sarif.Provenance{
				{Tool: "trivy-fs", Version: "trivy@0.69.3;db@2026-09-12T13:01:09Z"},
				{Tool: "retirejs"},
				// Accounts for the run rather than for a tool, and is not a scanner.
				{Tool: "draugr/scope", Fields: []sarif.Field{{Key: "controls", Value: "sca"}}},
			},
		}},
		"secrets": {Control: "secrets", Report: sarif.Report{
			Provenance: []sarif.Provenance{{Tool: "gitleaks", Version: "8.30.1"}},
		}},
	}}
}

func renderProduced(t *testing.T, run engine.Result, prov Provenance) map[string]any {
	t.Helper()
	var b bytes.Buffer
	err := RenderJSONFor(&b, "storefront", saga.Release{Version: "1.0"}, run,
		norn.Result{Verdict: norn.Pass}, "", nil, sarif.MarshalOptions{}, prov)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return doc
}

// The document names the Draugr that produced it, which release.version beside it does not:
// that one is the version of the software being scanned.
func TestTheReportNamesTheDraugrThatProducedIt(t *testing.T) {
	doc := renderProduced(t, producedBy(), Provenance{Build: &Build{Version: "0.121.1", Commit: "273db6e"}})
	got, _ := doc["draugr"].(map[string]any)
	if got == nil {
		t.Fatal("no draugr block, so two reports that disagree cannot be told apart")
	}
	if got["version"] != "0.121.1" || got["commit"] != "273db6e" {
		t.Errorf("draugr = %v", got)
	}
	if rel, _ := doc["release"].(map[string]any); rel["version"] != "1.0" {
		t.Errorf("release.version = %v, want the scanned software's own version", rel["version"])
	}
}

// A caller that did not know which Draugr it was writes none, rather than a placeholder somebody
// could later mistake for a reading.
func TestNoBuildWritesNoBlock(t *testing.T) {
	if _, ok := renderProduced(t, producedBy(), Provenance{})["draugr"]; ok {
		t.Error("a draugr block appeared with nothing behind it")
	}
}

// One entry per scanner that ran, sorted, with what decides its answers. A tool that could not be
// asked is listed without a version rather than left out: it ran, and that is the fact.
func TestTheReportNamesTheScannersThatRan(t *testing.T) {
	doc := renderProduced(t, producedBy(), Provenance{})
	raw, _ := doc["scanners"].([]any)
	if len(raw) != 3 {
		t.Fatalf("scanners = %v, want three", raw)
	}
	var names, versions []string
	for _, e := range raw {
		m := e.(map[string]any)
		names = append(names, m["name"].(string))
		v, _ := m["version"].(string)
		versions = append(versions, v)
	}
	if got, want := names, []string{"gitleaks", "retirejs", "trivy-fs"}; !equal(got, want) {
		t.Errorf("names = %v, want %v sorted and without the run's own entries", got, want)
	}
	if versions[1] != "" {
		t.Errorf("retirejs reported %q, want an absence rather than an invention", versions[1])
	}
	if versions[2] != "trivy@0.69.3;db@2026-09-12T13:01:09Z" {
		t.Errorf("trivy-fs version = %q, want the tool and the data behind it", versions[2])
	}
}

// A run that scanned nothing lists no scanners, rather than an empty array a consumer would read
// as "asked and none ran".
func TestARunWithNoScannersListsNone(t *testing.T) {
	if _, ok := renderProduced(t, engine.Result{}, Provenance{})["scanners"]; ok {
		t.Error("a scanners key appeared for a run that used none")
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
