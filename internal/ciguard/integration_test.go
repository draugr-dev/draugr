package ciguard

import (
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestIntegrationRunsOnEveryPullRequest holds the suite to being unconditional.
//
// It is a required check, and the two halves of that are one decision. A condition on the job, or a
// pull request trigger narrowed to some paths, turns a failure into a job that never reports, and
// a branch waiting on a report that will not arrive cannot merge at all. The suite is also the only
// place several behaviors are checked against real tools, real registries and a real cluster rather
// than against fixtures, so a run it skips is a claim nothing else makes.
func TestIntegrationRunsOnEveryPullRequest(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("../../.github/workflows/integration.yml")
	if err != nil {
		t.Fatalf("read the integration workflow: %v", err)
	}

	var workflow struct {
		On   map[string]any `yaml:"on"`
		Jobs map[string]struct {
			If    string `yaml:"if"`
			Steps []struct {
				Run string            `yaml:"run"`
				Env map[string]string `yaml:"env"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(raw, &workflow); err != nil {
		t.Fatalf("parse the integration workflow: %v", err)
	}

	trigger, ok := workflow.On["pull_request"]
	if !ok {
		t.Error("the suite no longer runs on a pull request, so the required check never reports " +
			"and nothing can merge")
	}
	// `pull_request:` on its own parses as nil, which is the unfiltered trigger. Anything else is a
	// narrowing, and the ones that matter here, `paths` and `paths-ignore`, decide silently.
	if trigger != nil {
		t.Errorf("the pull request trigger is filtered (%v); a pull request it excludes waits "+
			"forever on a required check that will not run", trigger)
	}

	job, ok := workflow.Jobs["integration"]
	if !ok {
		t.Fatal("no integration job; branch protection requires it by name")
	}
	if job.If != "" {
		t.Errorf("the integration job is conditional on %q, so it can be skipped, and a skipped "+
			"required check blocks a pull request rather than failing it", job.If)
	}

	// The suite provisions its own scanners, so a missing one is provisioning being wrong rather
	// than the test being unrunnable. Without this the tests skip themselves and the job reports
	// success for having run nothing, which is the one failure that stays quiet now.
	strict := false
	for _, step := range job.Steps {
		if strings.Contains(step.Run, "go test -tags integration") {
			strict = step.Env["DRAUGR_INTEGRATION_STRICT"] == "1"
		}
	}
	if !strict {
		t.Error("DRAUGR_INTEGRATION_STRICT is not set on the test step, so a scanner that failed " +
			"to install leaves the tests skipping and the job green")
	}
}
