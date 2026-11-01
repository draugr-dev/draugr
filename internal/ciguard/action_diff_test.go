package ciguard

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// stubDraugr stands in for the binary the Action downloads. It records each diff it is asked for,
// refuses to scan a descriptor that is not there, and to validate or scan one that sets acceptedBy,
// as the real one does, and advertises a diff of the head alone unless STUB_OLD is set. Its help
// runs past a pipe buffer, so a feature check that closes the pipe early fails here every time
// rather than now and then.
const stubDraugr = `#!/usr/bin/env bash
case "$1" in
  version) echo "draugr stub" ;;
  help)
    if [ -n "$STUB_OLD" ]; then echo "  draugr diff <base.sarif> <head.sarif> [flags]"
    else echo "  draugr diff [base.sarif] <head.sarif> [flags]"; echo "  --saga string   the descriptor"; fi
    echo "  --format string   console, markdown, json, sarif"
    echo "  --repository string"
    # As long as the real help, and longer: a reader that stops at the first match closes the pipe
    # while this is still writing, which is what a check under pipefail has to survive.
    for i in $(seq 1 4000); do echo "  --flag-$i string   padding the help past a pipe buffer"; done ;;
  validate)
    if grep acceptedBy "$2" >/dev/null; then
      echo "draugr: parse saga: config.exclude.acceptedBy was removed: delete the line" >&2; exit 1
    fi ;;
  scan)
    saga="$2"; shift 2; out=""
    while [ $# -gt 0 ]; do [ "$1" = "-o" ] && out="$2"; shift; done
    [ -e "$saga" ] || { echo "no descriptor at $saga" >&2; exit 1; }
    if grep acceptedBy "$saga" >/dev/null; then echo "acceptedBy was removed" >&2; exit 1; fi
    mkdir -p "$out"; echo '{"version":"2.1.0","runs":[]}' > "$out/results.sarif" ;;
  diff)
    if [ "$2" = "--help" ]; then exec "$0" help; fi
    echo "diff ${*:2}" >> "$STUB_LOG" ;;
esac
`

// actionDiffScript is the run block of the Action's diff step, exactly as GitHub runs it.
func actionDiffScript(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("../../action.yml")
	if err != nil {
		t.Fatal(err)
	}
	var action struct {
		Runs struct {
			Steps []struct {
				ID  string `yaml:"id"`
				Run string `yaml:"run"`
			} `yaml:"steps"`
		} `yaml:"runs"`
	}
	if err := yaml.Unmarshal(raw, &action); err != nil {
		t.Fatal(err)
	}
	for _, s := range action.Runs.Steps {
		if s.ID == "diff" {
			return s.Run
		}
	}
	t.Fatal("action.yml has no step with id diff")
	return ""
}

// runActionDiff runs the diff step in a repository whose base commit holds baseFiles and whose
// head holds headFiles, each a name or name=content, and returns what the step printed, the diffs
// it asked for, and whether it succeeded.
func runActionDiff(t *testing.T, baseFiles, headFiles []string, env ...string) (out, diffs string, ok bool) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	root := t.TempDir()
	repo, bin, tmp := filepath.Join(root, "repo"), filepath.Join(root, "bin"), filepath.Join(root, "tmp")
	for _, d := range []string{repo, bin, tmp} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	// #nosec G306 -- the stub has to be executable to stand in for the binary
	if err := os.WriteFile(filepath.Join(bin, "draugr"), []byte(stubDraugr), 0o700); err != nil {
		t.Fatal(err)
	}
	git := func(args ...string) string {
		t.Helper()
		// #nosec G204 -- git with arguments this test writes, in a scratch repository
		cmd := exec.Command("git", append([]string{"-c", "user.name=t", "-c", "user.email=t@t.invalid",
			"-c", "commit.gpgsign=false"}, args...)...)
		cmd.Dir = repo
		b, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, b)
		}
		return strings.TrimSpace(string(b))
	}
	commit := func(files []string) string {
		t.Helper()
		git("rm", "-rq", "--cached", "--ignore-unmatch", ".")
		entries, _ := os.ReadDir(repo)
		for _, e := range entries {
			if e.Name() != ".git" {
				_ = os.RemoveAll(filepath.Join(repo, e.Name()))
			}
		}
		for _, f := range append([]string{"README.md"}, files...) {
			name, content, found := strings.Cut(f, "=")
			if !found {
				content = name
			}
			if err := os.WriteFile(filepath.Join(repo, name), []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		git("add", "-A")
		git("commit", "-qm", "c")
		return git("rev-parse", "HEAD")
	}
	git("init", "-q", "-b", "main")
	base := commit(baseFiles)
	commit(headFiles)

	log := filepath.Join(root, "diffs.log")
	// #nosec G204 -- the Action's own checked-in script, run as GitHub runs it
	cmd := exec.Command("bash", "-c", actionDiffScript(t))
	cmd.Dir = repo
	cmd.Env = append(os.Environ(),
		"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"STUB_LOG="+log, "BASE_SHA="+base, "RUNNER_TEMP="+tmp,
		"INPUT_SAGA=draugr.saga.yaml", "INPUT_WORKING_DIRECTORY=", "INPUT_OUTPUT="+filepath.Join(root, "out"),
		"INPUT_CACHE_DIR=", "CACHE_READ_ONLY=", "INPUT_ARGS=", "INPUT_FAIL_ON_NEW=P1",
		"INPUT_FAIL_ON_NEW_PRIORITY=", "INPUT_DIFF_VIEW=", "INPUT_CODE_SCANNING=new",
		"INPUT_CODE_SCANNING_MIN_PRIORITY=", "GITHUB_OUTPUT="+filepath.Join(root, "github-output"),
		"GITHUB_SERVER_URL=https://github.com", "GITHUB_REPOSITORY=acme/shop")
	cmd.Env = append(cmd.Env, env...)
	b, err := cmd.CombinedOutput()
	d, _ := os.ReadFile(log) // #nosec G304 -- written by the stub under t.TempDir()
	return string(b), string(d), err == nil
}

// The pull request that adds the descriptor is gated like any other: the base has nothing to scan,
// so the diff compares the head against no findings and says why, for the comment and for code
// scanning alike.
func TestTheActionGatesThePullRequestThatAddsTheDescriptor(t *testing.T) {
	t.Parallel()
	out, diffs, ok := runActionDiff(t, nil, []string{"draugr.saga.yaml"})
	if !ok {
		t.Fatalf("the step failed:\n%s", out)
	}
	if !strings.Contains(out, "::notice::The base commit has no draugr.saga.yaml") {
		t.Errorf("no notice that the base has no descriptor:\n%s", out)
	}
	// Both diffs take the head alone: the comment's and the one code scanning receives.
	head := filepath.Join("out", "results.sarif")
	for _, want := range []string{head + " --publish --fail-on-new P1", head + " --format sarif"} {
		if !strings.Contains(diffs, want) {
			t.Errorf("no diff of the head alone with %q in:\n%s", want, diffs)
		}
	}
	if strings.Contains(diffs, "draugr-base") {
		t.Errorf("a diff named a base report:\n%s", diffs)
	}
}

// A Draugr pinned to a release that needs two reports says so, rather than failing on a file the
// reader never asked for.
func TestTheActionSaysWhenThePinnedDraugrCannotCompareAgainstNoBase(t *testing.T) {
	t.Parallel()
	out, diffs, _ := runActionDiff(t, nil, []string{"draugr.saga.yaml"}, "STUB_OLD=1")
	if !strings.Contains(out, "::warning::The base commit has no draugr.saga.yaml") {
		t.Errorf("no warning that the pinned release cannot compare against no base:\n%s", out)
	}
	if !strings.Contains(diffs, "draugr-base/results.sarif") {
		t.Errorf("an old binary was handed the head alone:\n%s", diffs)
	}
}

// The pull request that removes the descriptor has nothing at the head to scan, and the step says
// that, before scanning the base, rather than leaving the diff to fail on a missing file.
func TestTheActionSaysWhenThePullRequestRemovesTheDescriptor(t *testing.T) {
	t.Parallel()
	out, diffs, ok := runActionDiff(t, []string{"draugr.saga.yaml"}, nil)
	if ok {
		t.Fatalf("the step passed with no descriptor at the head:\n%s", out)
	}
	if !strings.Contains(out, "::error::draugr.saga.yaml is missing at the head") {
		t.Errorf("no error naming the missing descriptor:\n%s", out)
	}
	if diffs != "" {
		t.Errorf("a diff ran with nothing at the head:\n%s", diffs)
	}
	if strings.Contains(out, "base commit has no") {
		t.Errorf("the base was looked at after the head had nothing to compare:\n%s", out)
	}
}

// A pull request with the descriptor on both sides diffs two scans, as it always has.
func TestTheActionDiffsTwoScansWhenBothSidesHaveTheDescriptor(t *testing.T) {
	t.Parallel()
	out, diffs, ok := runActionDiff(t, []string{"draugr.saga.yaml"}, []string{"draugr.saga.yaml", "app.js"})
	if !ok {
		t.Fatalf("the step failed:\n%s", out)
	}
	if strings.Count(diffs, "draugr-base/results.sarif") != 2 {
		t.Errorf("not a diff of two scans:\n%s", diffs)
	}
}

// A base descriptor the running release refuses is scanned with the head's copy, and the step says
// so with the refusal's reason. Otherwise the base writes no report and every pull request fails,
// the one that corrects the descriptor included.
func TestTheActionScansARefusedBaseWithTheHeadsDescriptor(t *testing.T) {
	t.Parallel()
	out, diffs, ok := runActionDiff(t, []string{"draugr.saga.yaml=acceptedBy: someone"},
		[]string{"draugr.saga.yaml", "app.js"})
	if !ok {
		t.Fatalf("the step failed:\n%s", out)
	}
	want := "::warning::This Draugr release refuses the base commit's draugr.saga.yaml, so the base is " +
		"scanned with this pull request's copy. Refusal: draugr: parse saga: config.exclude.acceptedBy was removed"
	if !strings.Contains(out, want) {
		t.Errorf("no warning naming the refusal and its reason:\n%s", out)
	}
	// The stub writes a base report only from a descriptor it accepts, so a diff of two scans is
	// the head's copy scanning the base.
	if strings.Count(diffs, "draugr-base/results.sarif") != 2 {
		t.Errorf("not a diff of two scans:\n%s", diffs)
	}
}

// A base descriptor the release accepts is scanned as it is, with nothing said.
func TestTheActionScansAnAcceptedBaseWithItsOwnDescriptor(t *testing.T) {
	t.Parallel()
	out, _, ok := runActionDiff(t, []string{"draugr.saga.yaml"}, []string{"draugr.saga.yaml", "app.js"})
	if !ok {
		t.Fatalf("the step failed:\n%s", out)
	}
	if strings.Contains(out, "refuses the base") {
		t.Errorf("an accepted base was reported as refused:\n%s", out)
	}
}

// Every shipped pipeline that scans a base validates its descriptor first and scans a refused one
// with the head's copy. A pipeline that does not fails on every change while the base carries a
// key a release removed, and nothing about the template looks wrong until a release removes one.
func TestEveryPipelineScansARefusedBaseWithTheHeadsDescriptor(t *testing.T) {
	t.Parallel()
	for _, path := range []string{"action.yml", "azure-pipelines/draugr.yml", "gitlab-ci/draugr.yml"} {
		// #nosec G304 -- path comes from the hardcoded list above, inside this repository.
		body, err := os.ReadFile(filepath.Join("../..", path))
		if err != nil {
			t.Errorf("%s: %v", path, err)
			continue
		}
		if !strings.Contains(string(body), "draugr validate") || !strings.Contains(string(body), "copy. Refusal: $(printf") {
			t.Errorf("%s scans the base without validating its descriptor, or says nothing when it is refused", path)
		}
	}
}

// The diff reads the descriptor the head was scanned with, so its config.gate.failOnNew gates the
// pull request when no input sets a threshold. A release that predates `diff --saga` is not
// handed the flag, which it would refuse.
func TestTheActionNamesTheDescriptorToTheDiff(t *testing.T) {
	t.Parallel()
	base, head := []string{"draugr.saga.yaml"}, []string{"draugr.saga.yaml", "app.js"}
	out, diffs, ok := runActionDiff(t, base, head)
	if !ok {
		t.Fatalf("the step failed:\n%s", out)
	}
	if !strings.Contains(diffs, "--saga draugr.saga.yaml") {
		t.Errorf("the diff was not given the descriptor:\n%s", diffs)
	}
	out, diffs, ok = runActionDiff(t, base, head, "STUB_OLD=1")
	if !ok {
		t.Fatalf("the step failed on an older release:\n%s", out)
	}
	if strings.Contains(diffs, "--saga") {
		t.Errorf("an older release was handed --saga:\n%s", diffs)
	}
}

// Every shipped pipeline hands its diff the descriptor, after asking the binary whether it takes
// one. A template that never passes it gates only on its own input, and a descriptor's
// failOnNew is read only by chance, when it is the one descriptor in the directory.
func TestEveryPipelineNamesTheDescriptorToTheDiff(t *testing.T) {
	t.Parallel()
	for _, path := range []string{"action.yml", "azure-pipelines/draugr.yml", "gitlab-ci/draugr.yml"} {
		// #nosec G304 -- path comes from the hardcoded list above, inside this repository.
		body, err := os.ReadFile(filepath.Join("../..", path))
		if err != nil {
			t.Errorf("%s: %v", path, err)
			continue
		}
		if !strings.Contains(string(body), "grep -- '--saga'") || !strings.Contains(string(body), "--saga ") {
			t.Errorf("%s does not hand draugr diff its descriptor behind a check for --saga", path)
		}
	}
}

// Every shipped pipeline with a diff mode compares the change that adds the descriptor against no
// base. A template that scans the base unconditionally fails on exactly that change, the first one
// that turns Draugr on, and nothing about the template looks wrong until somebody adopts it.
func TestEveryPipelineDiffsTheChangeThatAddsTheDescriptor(t *testing.T) {
	t.Parallel()
	for _, path := range []string{"action.yml", "azure-pipelines/draugr.yml", "gitlab-ci/draugr.yml"} {
		// #nosec G304 -- path comes from the hardcoded list above, inside this repository.
		body, err := os.ReadFile(filepath.Join("../..", path))
		if err != nil {
			t.Errorf("%s: %v", path, err)
			continue
		}
		if strings.Contains(string(body), "draugr diff") && !strings.Contains(string(body), "[base.sarif]") {
			t.Errorf("%s runs draugr diff and never compares against a base with no descriptor", path)
		}
	}
}

// A feature check reads `draugr help diff` through a pipe. `grep -q` exits at the first match and
// leaves the writer to die of SIGPIPE, and under pipefail the test then reads as false on a binary
// that has the feature, so the pipeline takes the path meant for an older release.
func TestNoTemplateEndsAPipeInGrepQ(t *testing.T) {
	t.Parallel()
	for _, path := range []string{"action.yml", "azure-pipelines/draugr.yml", "gitlab-ci/draugr.yml"} {
		// #nosec G304 -- path comes from the hardcoded list above, inside this repository.
		body, err := os.ReadFile(filepath.Join("../..", path))
		if err != nil {
			t.Errorf("%s: %v", path, err)
			continue
		}
		for i, line := range strings.Split(string(body), "\n") {
			if strings.Contains(line, "| grep -q") {
				t.Errorf("%s:%d ends a pipe in grep -q; use grep ... >/dev/null: %s", path, i+1, strings.TrimSpace(line))
			}
		}
	}
}
