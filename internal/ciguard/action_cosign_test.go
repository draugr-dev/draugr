package ciguard

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// actionStepKeys is one step of action.yml, with the keys these tests read.
type actionStepKeys struct {
	ID              string            `yaml:"id"`
	Name            string            `yaml:"name"`
	If              string            `yaml:"if"`
	Uses            string            `yaml:"uses"`
	Run             string            `yaml:"run"`
	Env             map[string]string `yaml:"env"`
	ContinueOnError bool              `yaml:"continue-on-error"`
}

func actionSteps(t *testing.T) []actionStepKeys {
	t.Helper()
	raw, err := os.ReadFile("../../action.yml")
	if err != nil {
		t.Fatal(err)
	}
	var action struct {
		Runs struct {
			Steps []actionStepKeys `yaml:"steps"`
		} `yaml:"runs"`
	}
	if err := yaml.Unmarshal(raw, &action); err != nil {
		t.Fatal(err)
	}
	return action.Runs.Steps
}

// TestTheActionInstallsCosignASecondTimeBeforeItFails holds the shape of the retry. The installer
// downloads cosign once, with no retry of its own, so one cut-short download would otherwise fail
// the job before anything is scanned. Both attempts are the same pinned installer, so the second
// is held to the same checks as the first, and a check after them stops the job when neither
// installed it, so the continue-on-error on each attempt cannot turn into a green tick.
func TestTheActionInstallsCosignASecondTimeBeforeItFails(t *testing.T) {
	steps := actionSteps(t)
	var installs []int
	check, download := -1, -1
	for i, s := range steps {
		switch {
		case strings.HasPrefix(s.Uses, "sigstore/cosign-installer@"):
			installs = append(installs, i)
		case s.ID == "cosign-check":
			check = i
		case strings.HasPrefix(s.Name, "Download and verify Draugr"):
			download = i
		}
	}
	if len(installs) != 2 {
		t.Fatalf("action.yml runs the cosign installer %d times, want 2: once, and once more when that fails", len(installs))
	}
	first, second := steps[installs[0]], steps[installs[1]]
	if first.Uses != second.Uses {
		t.Errorf("the second attempt uses %q and the first %q; a retry with another installer is held to other checks", second.Uses, first.Uses)
	}
	if first.ID != "cosign-first" || second.ID != "cosign-second" {
		t.Errorf("the installs have ids %q and %q, and the check reads cosign-first and cosign-second", first.ID, second.ID)
	}
	if !first.ContinueOnError || !second.ContinueOnError {
		t.Error("an install attempt without continue-on-error fails the job itself, before the check can say why")
	}
	if !strings.Contains(second.If, "steps.cosign-first.outcome == 'failure'") {
		t.Errorf("the second attempt runs on %q; it should run only when the first failed", second.If)
	}
	if check < installs[1] || download < check {
		t.Errorf("the steps run install (%d), install (%d), check (%d), download (%d); the check belongs after both attempts and before the download it protects", installs[0], installs[1], check, download)
	}
	c := steps[check]
	if c.ContinueOnError {
		t.Error("the check carries continue-on-error, so a job with no cosign would go on to fail somewhere less clear")
	}
	if c.If != "inputs.verify == 'true'" {
		t.Errorf("the check runs on %q; it must run whenever cosign was to be installed", c.If)
	}
	if c.Env["FIRST"] != "${{ steps.cosign-first.outcome }}" || c.Env["SECOND"] != "${{ steps.cosign-second.outcome }}" {
		t.Errorf("the check reads FIRST=%q SECOND=%q, not the two attempts' outcomes", c.Env["FIRST"], c.Env["SECOND"])
	}
}

// TestTheCosignCheckFailsOnlyWhenNeitherAttemptInstalledIt runs the check's script as GitHub runs it,
// with each pair of outcomes the two attempts can leave.
func TestTheCosignCheckFailsOnlyWhenNeitherAttemptInstalledIt(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is not installed")
	}
	script := actionStep(t, "cosign-check")
	for _, c := range []struct {
		first, second string
		fails         bool
	}{
		{"success", "skipped", false},
		{"failure", "success", false},
		{"failure", "failure", true},
		{"failure", "skipped", true},
	} {
		cmd := exec.Command("bash", "-c", script) // #nosec G204 -- our own action's script
		cmd.Env = append(os.Environ(), "FIRST="+c.first, "SECOND="+c.second)
		out, err := cmd.CombinedOutput()
		if failed := err != nil; failed != c.fails {
			t.Errorf("first %s, second %s: failed=%v, want %v\n%s", c.first, c.second, failed, c.fails, out)
		}
		if c.fails && !strings.Contains(string(out), "could not install cosign") {
			t.Errorf("first %s, second %s: the failure does not say cosign could not be installed:\n%s", c.first, c.second, out)
		}
		if c.fails && !strings.Contains(string(out), "no finding caused this") {
			t.Errorf("first %s, second %s: the failure does not say no finding caused it:\n%s", c.first, c.second, out)
		}
	}
}
