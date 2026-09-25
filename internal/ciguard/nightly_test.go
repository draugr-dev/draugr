package ciguard

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// nightlyStep is one step of a job in integration.yml, as the guards below read it.
type nightlyStep struct {
	Name string            `yaml:"name"`
	ID   string            `yaml:"id"`
	Uses string            `yaml:"uses"`
	If   string            `yaml:"if"`
	Run  string            `yaml:"run"`
	Env  map[string]string `yaml:"env"`
	With map[string]any    `yaml:"with"`
}

// nightlyJob is one job of integration.yml. Needs is a list or a single name in the file, so it is
// read as a node and flattened by needs().
type nightlyJob struct {
	If          string            `yaml:"if"`
	Needs       yaml.Node         `yaml:"needs"`
	Uses        string            `yaml:"uses"`
	With        map[string]any    `yaml:"with"`
	Permissions map[string]string `yaml:"permissions"`
	Steps       []nightlyStep     `yaml:"steps"`
}

func (j nightlyJob) needs() []string {
	switch j.Needs.Kind {
	case yaml.ScalarNode:
		return []string{j.Needs.Value}
	case yaml.SequenceNode:
		var out []string
		for _, n := range j.Needs.Content {
			out = append(out, n.Value)
		}
		return out
	}
	return nil
}

type nightlyWorkflow struct {
	On          map[string]any `yaml:"on"`
	Concurrency struct {
		Group string `yaml:"group"`
	} `yaml:"concurrency"`
	Jobs map[string]nightlyJob `yaml:"jobs"`
}

func readWorkflow(t *testing.T, name string) nightlyWorkflow {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("../../.github/workflows", name)) // #nosec G304 -- this repository's own workflow directory
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	var w nightlyWorkflow
	if err := yaml.Unmarshal(raw, &w); err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return w
}

// job returns the named job, failing the test if it is gone.
func (w nightlyWorkflow) job(t *testing.T, name string) nightlyJob {
	t.Helper()
	j, ok := w.Jobs[name]
	if !ok {
		t.Fatalf("integration.yml has no %s job", name)
	}
	return j
}

// testStep returns the step that runs the Go test named by run, failing the test if there is none.
func (j nightlyJob) testStep(t *testing.T, run string) nightlyStep {
	t.Helper()
	for _, s := range j.Steps {
		if strings.Contains(s.Run, "go test -tags integration") && strings.Contains(s.Run, run) {
			return s
		}
	}
	t.Fatalf("no step runs `go test -tags integration -run %s`", run)
	return nightlyStep{}
}

// TestTheLiveTierRunsOnlyWhereItsAnswerIsNotAVerdict holds the live job to the schedule and to a
// dispatch on a branch.
//
// Its answer depends on the day as much as on the tree: an advisory published this morning changes
// what it finds without any change to Draugr. On a pull request or a release tag that would block a
// change, or a release, for something neither did. And a job that pushes a branch and opens a pull
// request must not run on a pull request from a fork, whose code it would be executing.
func TestTheLiveTierRunsOnlyWhereItsAnswerIsNotAVerdict(t *testing.T) {
	t.Parallel()
	w := readWorkflow(t, "integration.yml")
	if _, ok := w.On["schedule"]; !ok {
		t.Fatal("integration.yml has no schedule, so the live tier and the air-gapped run never run on their own")
	}
	live := w.job(t, "live")

	if !strings.Contains(live.If, "github.event_name == 'schedule'") {
		t.Errorf("the live job's condition %q does not name the schedule, so it never runs nightly", live.If)
	}
	for _, event := range []string{"pull_request", "push"} {
		if strings.Contains(live.If, event) {
			t.Errorf("the live job's condition mentions %s (%q); it runs on the schedule and on dispatch only", event, live.If)
		}
	}
	if !strings.Contains(live.If, "!startsWith(github.ref, 'refs/tags/')") || !strings.Contains(live.If, "!inputs.ref") {
		t.Errorf("the live job's condition %q does not exclude a release, so a release would wait on "+
			"a verdict that moves with the advisory databases", live.If)
	}

	step := live.testStep(t, "TestLive")
	for key, want := range map[string]string{"DRAUGR_LIVE": "1", "DRAUGR_INTEGRATION_STRICT": "1"} {
		if step.Env[key] != want {
			t.Errorf("the live test step sets %s=%q, want %q", key, step.Env[key], want)
		}
	}
	if step.Env["DRAUGR_LIVE_DEMO"] == "" {
		t.Error("the live test step does not set DRAUGR_LIVE_DEMO, so draugr-demo is never scanned")
	}
	if !strings.Contains(step.Run, "-update-live") {
		t.Error("the live test step does not pass -update-live, so drift fails the job instead of " +
			"becoming a pull request")
	}
}

// TestTheLiveTierHoldsNoWriteCredentialWhileItScans. The live job executes third-party scanners
// over fixture repositories and fetches from public registries. Whatever credential is on the
// machine while that happens is reachable by anything they run, so the job's own token reads only,
// no checkout leaves a credential in .git/config, and the token that pushes the drift is minted
// after the scans have finished.
//
// That token is the app's rather than GITHUB_TOKEN because GitHub starts no workflow for anything
// GITHUB_TOKEN does: a drift pull request opened with it would carry no checks, and nothing on the
// page would say so.
func TestTheLiveTierHoldsNoWriteCredentialWhileItScans(t *testing.T) {
	t.Parallel()
	live := readWorkflow(t, "integration.yml").job(t, "live")

	for scope, level := range live.Permissions {
		if level != "read" && level != "none" {
			t.Errorf("the live job grants %s: %s; it pushes with an app token minted after the scans, and needs no write of its own", scope, level)
		}
	}
	if len(live.Permissions) == 0 {
		t.Error("the live job declares no permissions, so it takes the workflow's and any scope added there reaches the scans")
	}

	tested, minted := -1, -1
	for i, s := range live.Steps {
		if strings.HasPrefix(s.Uses, "actions/checkout@") && s.With["persist-credentials"] != false {
			t.Errorf("step %d (%s) leaves its token in .git/config while the scans run; set persist-credentials: false", i+1, s.Uses)
		}
		if strings.Contains(s.Run, "-run 'TestLive'") || strings.Contains(s.Run, "-run TestLive") {
			tested = i
		}
		if strings.HasPrefix(s.Uses, "actions/create-github-app-token@") {
			minted = i
		}
		for _, v := range s.Env {
			if strings.Contains(v, "github.token") || strings.Contains(v, "secrets.GITHUB_TOKEN") {
				t.Errorf("step %q uses GITHUB_TOKEN; a pull request opened with it starts no checks", s.Name)
			}
		}
		if strings.Contains(s.Run, "gh pr ") && s.Env["GH_TOKEN"] != "${{ steps.app.outputs.token }}" {
			t.Errorf("step %q runs gh with GH_TOKEN=%q, not the app token", s.Name, s.Env["GH_TOKEN"])
		}
	}
	if minted < 0 {
		t.Fatal("the live job mints no app token, so its drift pull request would start no checks")
	}
	if tested < 0 || minted < tested {
		t.Errorf("the app token is minted at step %d and the live tier runs at step %d; a credential "+
			"that can push must not exist while the scanners run", minted, tested)
	}
}

// TestTheAirGappedRunJudgesEveryRelease holds the air-gapped job to the schedule and to every
// release tag, and to checking out the tree it was given.
//
// release.yml calls this workflow with the tag and publishes only when all of it passes. The
// air-gapped job is what stands behind docs/guides/air-gapped.md at that moment, so a condition
// that skipped it on a tag would publish a release whose offline promise nobody had checked, with
// every check on the page green. Checking out anything but inputs.ref would check a different tree
// from the one being released.
func TestTheAirGappedRunJudgesEveryRelease(t *testing.T) {
	t.Parallel()
	w := readWorkflow(t, "integration.yml")
	air := w.job(t, "airgapped")

	for _, want := range []string{"github.event_name == 'schedule'", "startsWith(github.ref, 'refs/tags/')"} {
		if !strings.Contains(air.If, want) {
			t.Errorf("the airgapped job's condition %q does not contain %s", air.If, want)
		}
	}
	if strings.Contains(air.If, "!startsWith(github.ref, 'refs/tags/')") {
		t.Errorf("the airgapped job's condition %q excludes release tags", air.If)
	}
	for k, level := range air.Permissions {
		if level != "read" && level != "none" {
			t.Errorf("the airgapped job grants %s: %s; it writes nothing", k, level)
		}
	}
	if len(air.Steps) == 0 || air.Steps[0].With["ref"] != "${{ inputs.ref }}" {
		t.Error("the airgapped job's first step does not check out inputs.ref, so against a release " +
			"it judges the caller's commit rather than the tag")
	}
	step := air.testStep(t, "TestAirGapped")
	for key, want := range map[string]string{"DRAUGR_AIRGAPPED": "1", "DRAUGR_INTEGRATION_STRICT": "1"} {
		if step.Env[key] != want {
			t.Errorf("the air-gapped test step sets %s=%q, want %q; without it the test skips and the job is green for running nothing", key, step.Env[key], want)
		}
	}

	release := readWorkflow(t, "release.yml")
	call, ok := release.Jobs["integration"]
	if !ok || call.Uses != "./.github/workflows/integration.yml" {
		t.Fatal("release.yml no longer calls integration.yml, so no release runs the air-gapped job")
	}
	if ref, _ := call.With["ref"].(string); !strings.Contains(ref, "inputs.tag") || !strings.Contains(ref, "github.ref_name") {
		t.Errorf("release.yml calls integration.yml with ref %q; it has to be the tag being released", ref)
	}
	if !slices.Contains(release.job(t, "goreleaser").needs(), "integration") {
		t.Error("goreleaser does not wait on integration, so a release is published whether or not it works offline")
	}
}

// TestEveryJobThatCanGoRedOnMainReachesAPerson. The notifier opens an issue for each job that fails
// on main. A job it does not wait on is one whose failure on the schedule is a color on a page
// nobody opens, and a job it waits on without a label of its own shares an issue with another, so
// the first to go green closes the issue while the second is still red.
//
// The concurrency group is part of the same promise: without the event in it, a push to main
// cancels the nightly run in flight, and the day's only live and air-gapped verdicts never arrive.
func TestEveryJobThatCanGoRedOnMainReachesAPerson(t *testing.T) {
	t.Parallel()
	w := readWorkflow(t, "integration.yml")
	notify := w.job(t, "notify")
	needs := notify.needs()

	script := ""
	for _, s := range notify.Steps {
		if src, ok := s.With["script"].(string); ok {
			script += src
		}
	}
	for name := range w.Jobs {
		if name == "notify" {
			continue
		}
		if !slices.Contains(needs, name) {
			t.Errorf("notify does not wait on %s, so its failure on main raises nothing", name)
		}
		if !regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(name) + `: \{`).MatchString(script) {
			t.Errorf("the notifier's script has no entry for %s, so its failure has no issue of its own", name)
		}
	}
	if !strings.Contains(notify.If, "always()") {
		t.Errorf("notify's condition %q lacks always(), so it is skipped exactly when a job it waits on fails", notify.If)
	}
	if !strings.Contains(w.Concurrency.Group, "github.event_name") {
		t.Errorf("the concurrency group %q omits the event, so a push to main cancels the nightly run", w.Concurrency.Group)
	}
}

// pinned is a `uses:` reference fixed to a commit: 40 hex digits, then optionally the version the
// commit was tagged with as a comment.
var pinned = regexp.MustCompile(`^[^@\s]+@[0-9a-f]{40}$`)

// TestEveryActionIsPinnedToACommit. A tag or branch can be moved to another commit by whoever
// controls the action's repository, and every workflow referencing it then runs the new code with
// that workflow's token on its next run, without a line changing here. A commit cannot be moved.
// Local actions (`./…`) are this repository's own and are reviewed with it.
func TestEveryActionIsPinnedToACommit(t *testing.T) {
	t.Parallel()
	files, err := filepath.Glob("../../.github/workflows/*.yml")
	if err != nil {
		t.Fatal(err)
	}
	files = append(files, "../../action.yml")
	uses := regexp.MustCompile(`(?m)^\s*(?:-\s+)?uses:\s*([^\s#]+)`)
	checked := 0
	for _, f := range files {
		raw, err := os.ReadFile(f) // #nosec G304 -- this repository's own workflows
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		for _, m := range uses.FindAllStringSubmatch(string(raw), -1) {
			ref := strings.Trim(m[1], `"'`)
			if strings.HasPrefix(ref, "./") {
				continue
			}
			checked++
			if !pinned.MatchString(ref) {
				t.Errorf("%s uses %s, which is not pinned to a commit", filepath.Base(f), ref)
			}
		}
	}
	if checked == 0 {
		t.Fatal("found no `uses:` references at all, so this guard is reading the wrong files")
	}
}
