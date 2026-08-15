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
