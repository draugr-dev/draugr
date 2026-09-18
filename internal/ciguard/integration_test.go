package ciguard

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// needed is the condition every step that costs time carries, so that the job can report without
// doing the work. Named once, because a step guarded by a different spelling is a step that runs
// when nothing asked it to.
const needed = "steps.needed.outputs.run == 'true'"

type integrationWorkflow struct {
	On   map[string]any `yaml:"on"`
	Jobs map[string]struct {
		If    string `yaml:"if"`
		Steps []struct {
			Name string            `yaml:"name"`
			ID   string            `yaml:"id"`
			Uses string            `yaml:"uses"`
			If   string            `yaml:"if"`
			Run  string            `yaml:"run"`
			Env  map[string]string `yaml:"env"`
			With map[string]any    `yaml:"with"`
		} `yaml:"steps"`
	} `yaml:"jobs"`
}

func readIntegrationWorkflow(t *testing.T) integrationWorkflow {
	t.Helper()
	raw, err := os.ReadFile("../../.github/workflows/integration.yml")
	if err != nil {
		t.Fatalf("read the integration workflow: %v", err)
	}
	var workflow integrationWorkflow
	if err := yaml.Unmarshal(raw, &workflow); err != nil {
		t.Fatalf("parse the integration workflow: %v", err)
	}
	return workflow
}

// TestIntegrationReportsOnEveryPullRequest holds the job to running and reporting every time.
//
// It is a required check, and a required check that does not report is worse than a failing one: a
// condition on the job, or a pull request trigger narrowed to some paths, leaves a branch waiting
// on an answer that will not arrive, and it cannot merge at all. Whether the job does the work is
// decided inside it, where the answer is a fast green rather than a silence.
func TestIntegrationReportsOnEveryPullRequest(t *testing.T) {
	t.Parallel()
	workflow := readIntegrationWorkflow(t)

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
	// success for having run nothing.
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

// TestEveryCostlyStepWaitsForTheDecision keeps the fast path fast.
//
// Everything after the decision belongs behind it. A step added without the condition runs on a
// pull request that changed nothing it can see, which is the cost this arrangement exists to avoid
// and which nothing else would report: the job is green either way, several minutes later.
func TestEveryCostlyStepWaitsForTheDecision(t *testing.T) {
	t.Parallel()
	job := readIntegrationWorkflow(t).Jobs["integration"]

	decided := -1
	for i, step := range job.Steps {
		if step.ID == "needed" {
			decided = i
			break
		}
	}
	if decided < 0 {
		t.Fatal("no step with id `needed`, so nothing decides whether the suite has anything to " +
			"judge and every pull request pays for a kind cluster")
	}
	// The decision reads a diff, so the clone has to hold both ends of it.
	if depth := job.Steps[0].With["fetch-depth"]; depth != 0 {
		t.Errorf("the checkout asks for fetch-depth %v; the decision diffs against the base "+
			"commit, which a shallow clone does not have", depth)
	}

	for _, step := range job.Steps[decided+1:] {
		label := step.Name
		if label == "" {
			label = step.Uses
		}
		if !strings.Contains(step.If, needed) {
			t.Errorf("step %q is not conditioned on %s, so it runs even when the diff holds "+
				"nothing the suite can see", label, needed)
		}
	}
}

// TestTheDecisionRunsAnythingItHasNotBeenTold holds the filter to naming what cannot reach the
// suite rather than what can.
//
// The direction is the whole of it. A list of relevant paths has to name every package the tests
// reach into, including the ones that only produce what they read back, and one it forgets turns a
// failure into a run that never happened. A list of inert paths is wrong in the other direction,
// and being wrong costs several minutes.
func TestTheDecisionRunsAnythingItHasNotBeenTold(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		changed []string
		want    string
	}{
		"a package the suite asserts on":  {[]string{"internal/controllers/provenance.go"}, "true"},
		"a package nobody has added yet":  {[]string{"internal/whatever/new.go"}, "true"},
		"a descriptor a test might load":  {[]string{"examples/kubernetes.saga.yaml"}, "true"},
		"another workflow":                {[]string{".github/workflows/ci.yml"}, "true"},
		"a scanner's colocated docs":      {[]string{"internal/scanners/cosign.md"}, "false"},
		"the reference docs":              {[]string{"docs/reference/cli.md"}, "false"},
		"a screenshot":                    {[]string{"docs/img/report.png"}, "false"},
		"release notes":                   {[]string{"changelog.d/1146.md", "CHANGELOG.md"}, "false"},
		"the license":                     {[]string{"LICENSE", "NOTICE"}, "false"},
		"prose beside code":               {[]string{"README.md", "pkg/report/console.go"}, "true"},
		"a diff that could not be read":   {nil, "true"},
		"an issue template":               {[]string{".github/ISSUE_TEMPLATE/bug.yml"}, "false"},
		"a path that merely starts as md": {[]string{"internal/mdutil/parse.go"}, "true"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cmd := exec.Command("../../scripts/integration-needed.sh")
			cmd.Stdin = strings.NewReader(strings.Join(tc.changed, "\n") + "\n")
			var out, errs bytes.Buffer
			cmd.Stdout, cmd.Stderr = &out, &errs
			if err := cmd.Run(); err != nil {
				t.Fatalf("run the decision: %v\n%s", err, errs.String())
			}
			if got := strings.TrimSpace(out.String()); got != tc.want {
				t.Errorf("%v: decided %q, wanted %q", tc.changed, got, tc.want)
			}
		})
	}
}
