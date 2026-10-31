package ciguard

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// requiredChecks are the status checks branch protection requires on main, by the name each job
// reports under. The protection rule lives in the repository's settings rather than in this tree,
// so this list is where the tree states it, and it changes when the rule does.
var requiredChecks = []string{
	"Build & test",
	"Lint (golangci-lint + gosec)",
	"Vulnerability scan",
	"Integration (kind + real scanners)",
	"Integration (sealed scenarios)",
	"selfscan",
}

type queueWorkflow struct {
	file string
	On   any `yaml:"on"`
	Jobs map[string]struct {
		Name  string         `yaml:"name"`
		If    string         `yaml:"if"`
		Uses  string         `yaml:"uses"`
		Steps []queueJobStep `yaml:"steps"`
	} `yaml:"jobs"`
}

type queueJobStep struct {
	Uses string            `yaml:"uses"`
	With map[string]string `yaml:"with"`
	Env  map[string]string `yaml:"env"`
	ID   string            `yaml:"id"`
}

func readQueueWorkflows(t *testing.T) []queueWorkflow {
	t.Helper()
	paths, err := filepath.Glob("../../.github/workflows/*.yml")
	if err != nil || len(paths) == 0 {
		t.Fatalf("no workflows found: %v", err)
	}
	var out []queueWorkflow
	for _, path := range paths {
		raw, err := os.ReadFile(path) // #nosec G304 -- a checked-in workflow
		if err != nil {
			t.Fatal(err)
		}
		w := queueWorkflow{file: filepath.Base(path)}
		if err := yaml.Unmarshal(raw, &w); err != nil {
			t.Fatalf("parse %s: %v", w.file, err)
		}
		out = append(out, w)
	}
	return out
}

// events returns each event in a workflow's `on:` with its settings, whichever of the three shapes
// `on:` was written in.
func events(on any) map[string]any {
	out := map[string]any{}
	switch v := on.(type) {
	case string:
		out[v] = nil
	case []any:
		for _, e := range v {
			if name, ok := e.(string); ok {
				out[name] = nil
			}
		}
	case map[string]any:
		return v
	}
	return out
}

// queueTriggerProblem says what keeps a workflow from reporting on every merge queue entry, or ""
// when nothing does.
//
// `types: [checks_requested]` is the only setting allowed, because it is the only activity the event
// has. A branch or path filter is one more condition the entry has to meet before the check reports,
// and an entry it excludes waits on a check that will not arrive.
func queueTriggerProblem(on any) string {
	config, ok := events(on)["merge_group"]
	if !ok {
		return "does not run on merge_group"
	}
	if config == nil {
		return ""
	}
	settings, _ := config.(map[string]any)
	for key, value := range settings {
		if key != "types" {
			return "narrows merge_group with " + key
		}
		types, _ := value.([]any)
		if !slices.Contains(types, any("checks_requested")) {
			return "limits merge_group to types that leave out checks_requested"
		}
	}
	return ""
}

// TestEveryRequiredCheckReportsInTheMergeQueue holds each required check to reporting on a queue
// entry, passing or failing, every time.
//
// The queue merges an entry once every required check has reported success on it, and fails it
// when one has not reported by the queue's timeout. A required check whose workflow does not run
// on merge_group therefore fails every entry, after the full wait. A job-level `if:` is the
// opposite failure: GitHub counts a skipped required check as passed, so an entry it skips merges
// without the check having run. Each of these jobs runs unconditionally and decides inside itself
// whether there is work to do.
func TestEveryRequiredCheckReportsInTheMergeQueue(t *testing.T) {
	t.Parallel()
	workflows := readQueueWorkflows(t)

	for _, check := range requiredChecks {
		found := false
		for _, w := range workflows {
			for id, job := range w.Jobs {
				// A job that calls another workflow reports as "caller / called", never under its
				// own name, so release.yml's call to selfscan.yml is not the required selfscan.
				if job.Uses != "" {
					continue
				}
				name := job.Name
				if name == "" {
					name = id
				}
				if name != check {
					continue
				}
				found = true
				if _, ok := events(w.On)["pull_request"]; !ok {
					t.Errorf("%s (%s) does not run on pull_request, so a pull request waits on it forever", check, w.file)
				}
				if problem := queueTriggerProblem(w.On); problem != "" {
					t.Errorf("%s: %s, so the required check %q never reports on a queue entry and "+
						"the queue fails every entry when it times out", w.file, problem, check)
				}
				if job.If != "" {
					t.Errorf("%s (%s) is conditional on %q; a skipped required check counts as passed, "+
						"so an entry it skips merges without it having run", check, w.file, job.If)
				}
			}
		}
		if !found {
			t.Errorf("no job reports %q, which branch protection requires by name; every pull "+
				"request and every queue entry would wait on it", check)
		}
	}
}

// TestEveryPullRequestWorkflowRunsInTheMergeQueue holds a check to the queue from the day it first
// runs on pull requests, rather than from the day it becomes required.
//
// A check is made required in the repository's settings, where no test can see the change. If its
// workflow ran on pull requests alone, that change would be the moment the queue began failing every
// entry, and the list above would still read as complete.
func TestEveryPullRequestWorkflowRunsInTheMergeQueue(t *testing.T) {
	t.Parallel()
	for _, w := range readQueueWorkflows(t) {
		if _, ok := events(w.On)["pull_request"]; !ok {
			continue
		}
		if problem := queueTriggerProblem(w.On); problem != "" {
			t.Errorf("%s runs on pull requests and %s; a check it produces cannot be made "+
				"required without the queue failing every entry", w.file, problem)
		}
	}
}

// TestTheSelfScanGatesAQueueEntryOnWhatItIntroduces holds the self-scan to asking a queue entry the
// pull request's question, through the Action's diff mode, against the commit the entry is built on.
//
// The Action's `auto` resolves to a full scan on any event that is not a pull request. On a queue
// entry that would gate a change on findings already on main, and a branch that is red because an
// advisory was published would stop every merge until somebody fixed it.
func TestTheSelfScanGatesAQueueEntryOnWhatItIntroduces(t *testing.T) {
	t.Parallel()
	var mode string
	for _, w := range readQueueWorkflows(t) {
		if w.file != "selfscan.yml" {
			continue
		}
		for _, step := range w.Jobs["selfscan"].Steps {
			if step.Uses == "./" {
				mode = step.With["mode"]
			}
		}
	}
	if !strings.Contains(mode, "merge_group") || !strings.Contains(mode, "'diff'") {
		t.Errorf("the self-scan's mode is %q; on merge_group it has to be diff, or the queue gates "+
			"each entry on everything already on main", mode)
	}

	raw, err := os.ReadFile("../../action.yml")
	if err != nil {
		t.Fatal(err)
	}
	var action struct {
		Runs struct {
			Steps []queueJobStep `yaml:"steps"`
		} `yaml:"runs"`
	}
	if err := yaml.Unmarshal(raw, &action); err != nil {
		t.Fatal(err)
	}
	for _, step := range action.Runs.Steps {
		if step.ID == "diff" && !strings.Contains(step.Env["BASE_SHA"], "github.event.merge_group.base_sha") {
			t.Errorf("the Action's diff step takes its base from %q, which is empty on merge_group, "+
				"so diff mode stops there with no base to compare against", step.Env["BASE_SHA"])
		}
	}
}

// The trigger check reads every shape `merge_group` takes, and names the two that keep a check from
// reporting on an entry.
func TestQueueTriggerProblemReadsEveryShape(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		on   string
		want string
	}{
		"no merge_group":          {on: "\n  pull_request:\n", want: "does not run on merge_group"},
		"bare merge_group":        {on: "\n  merge_group:\n", want: ""},
		"checks_requested":        {on: "\n  merge_group:\n    types: [checks_requested]\n", want: ""},
		"a branch filter":         {on: "\n  merge_group:\n    branches: [main]\n", want: "narrows merge_group with branches"},
		"types without the event": {on: "\n  merge_group:\n    types: [destroyed]\n", want: "limits merge_group to types that leave out checks_requested"},
		"one event, no settings":  {on: "push", want: "does not run on merge_group"},
	} {
		var workflow struct {
			On any `yaml:"on"`
		}
		if err := yaml.Unmarshal([]byte("on: "+tc.on), &workflow); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := queueTriggerProblem(workflow.On); got != tc.want {
			t.Errorf("%s: queueTriggerProblem = %q, want %q", name, got, tc.want)
		}
	}
}
