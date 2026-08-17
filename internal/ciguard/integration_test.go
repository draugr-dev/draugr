package ciguard

import (
	"os"
	"strings"
	"testing"
)

// TestIntegrationRunsWhenItsOwnSuiteChanges keeps the opt-in from swallowing the one case where it
// must not apply.
//
// The integration job is advisory on a pull request: it costs a kind cluster and several minutes,
// and most changes learn nothing from it. But a pull request that adds or edits an integration
// test and does not run it merges a test that has never executed — reviewed, green, and proving
// nothing. A skipped job in the checks list reads much like a passing one, so nothing about that
// is visible to the person merging.
func TestIntegrationRunsWhenItsOwnSuiteChanges(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("../../.github/workflows/integration.yml")
	if err != nil {
		t.Fatalf("read the integration workflow: %v", err)
	}
	workflow := string(raw)

	if !strings.Contains(workflow, "needs.suite.outputs.changed == 'true'") {
		t.Error("the integration job no longer runs when the suite itself changes, so a pull " +
			"request adding an integration test can merge without that test ever having run")
	}
	if !strings.Contains(workflow, "test/integration/") {
		t.Error("the change detection no longer looks at test/integration/, so it can never " +
			"report that the suite changed")
	}
	// Without the dependency the condition reads an output that is never produced, which is
	// indistinguishable from "nothing changed" — and fails exactly when it matters.
	if !strings.Contains(workflow, "needs: suite") {
		t.Error("the integration job does not depend on the detection job, so its output is empty")
	}
}

// TestIntegrationRunsWhenWhatItReadsBackChanges keeps the packages that produce a scan's output
// inside the change filter.
//
// These tests are the only ones that check a claim against a real run rather than a fixture: they
// scan something, then read the artifacts back to assert which tools actually ran and what the
// scan recorded about the repository. That makes them the only thing that notices when the code
// writing those artifacts changes shape — and they are opt-in, so a change outside the filter
// leaves them skipped. A skipped job reads like a passing one, and the next run is the release
// tag.
//
// Named per package with what each contributes, so a package leaving the list has to argue with
// the reason rather than delete a path.
func TestIntegrationRunsWhenWhatItReadsBackChanges(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("../../.github/workflows/integration.yml")
	if err != nil {
		t.Fatalf("read the integration workflow: %v", err)
	}
	workflow := string(raw)

	for path, produces := range map[string]string{
		"pkg/report/": "renders what a scan prints, which several of these tests assert on",
		"pkg/skald/":  "writes the SARIF and the JSON evidence these tests parse back",
	} {
		if !strings.Contains(workflow, path) {
			t.Errorf("%s is not in the integration change filter, but it %s — a change there "+
				"leaves the only tests that would catch it skipped, and green", path, produces)
		}
	}
}
