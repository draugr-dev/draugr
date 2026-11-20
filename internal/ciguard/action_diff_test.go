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
// fails a diff when STUB_GATE_TRIPS is set, or when it is asked to publish and STUB_PUBLISH_FAILS is,
// refuses to scan a descriptor that is not there, and to validate or scan one that sets acceptedBy,
// as the real one does, and advertises a diff of the head alone unless STUB_OLD is set. Each commit
// it scans goes to STUB_SCANS when that is set, so a test can read which base was scanned. Its help
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
    [ -z "$STUB_SCANS" ] || git rev-parse HEAD >> "$STUB_SCANS"
    if grep acceptedBy "$saga" >/dev/null; then echo "acceptedBy was removed" >&2; exit 1; fi
    mkdir -p "$out"; echo '{"version":"2.1.0","runs":[]}' > "$out/results.sarif" ;;
  diff)
    if [ "$2" = "--help" ]; then exec "$0" help; fi
    echo "diff ${*:2}" >> "$STUB_LOG"
    case " ${*:2} " in *" --format markdown "*) echo "## stub markdown diff" ;; esac
    case " ${*:2} " in *" --format sarif "*) [ -n "$STUB_SARIF_EMPTY" ] || echo '{"version":"2.1.0","runs":[]}' ;; esac
    # As the real one: a tripped gate exits non-zero after writing the report, and so does a
    # comment that cannot be posted.
    if [ -n "$STUB_GATE_TRIPS" ]; then echo "1 new finding at or above P1" >&2; exit 1; fi
    case " ${*:2} " in *" --publish "*)
      if [ -n "$STUB_PUBLISH_FAILS" ]; then echo "the gate passed, but publishing failed: 403" >&2; exit 1; fi ;;
    esac ;;
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

// diffRepo is a scratch repository with the stub binary beside it, to run the diff step in.
type diffRepo struct {
	t                               *testing.T
	root, dir, bin, tmp, log, scans string
}

func newDiffRepo(t *testing.T) *diffRepo {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	root := t.TempDir()
	r := &diffRepo{t: t, root: root, dir: filepath.Join(root, "repo"), bin: filepath.Join(root, "bin"),
		tmp: filepath.Join(root, "tmp"), log: filepath.Join(root, "diffs.log"), scans: filepath.Join(root, "scans.log")}
	for _, d := range []string{r.dir, r.bin, r.tmp} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	// #nosec G306 -- the stub has to be executable to stand in for the binary
	if err := os.WriteFile(filepath.Join(r.bin, "draugr"), []byte(stubDraugr), 0o700); err != nil {
		t.Fatal(err)
	}
	r.git("init", "-q", "-b", "main")
	return r
}

func (r *diffRepo) git(args ...string) string {
	r.t.Helper()
	// #nosec G204 -- git with arguments this test writes, in a scratch repository
	cmd := exec.Command("git", append([]string{"-c", "user.name=t", "-c", "user.email=t@t.invalid",
		"-c", "commit.gpgsign=false"}, args...)...)
	cmd.Dir = r.dir
	b, err := cmd.CombinedOutput()
	if err != nil {
		r.t.Fatalf("git %v: %v\n%s", args, err, b)
	}
	return strings.TrimSpace(string(b))
}

// commit replaces the tree with files, each a name or name=content, and returns the new commit.
func (r *diffRepo) commit(files []string) string {
	r.t.Helper()
	r.git("rm", "-rq", "--cached", "--ignore-unmatch", ".")
	entries, _ := os.ReadDir(r.dir)
	for _, e := range entries {
		if e.Name() != ".git" {
			_ = os.RemoveAll(filepath.Join(r.dir, e.Name()))
		}
	}
	for _, f := range append([]string{"README.md"}, files...) {
		name, content, found := strings.Cut(f, "=")
		if !found {
			content = name
		}
		if err := os.WriteFile(filepath.Join(r.dir, name), []byte(content), 0o600); err != nil {
			r.t.Fatal(err)
		}
	}
	r.git("add", "-A")
	r.git("commit", "-qm", "c")
	return r.git("rev-parse", "HEAD")
}

// run runs the diff step at the repository's HEAD with base as BASE_SHA, and returns what the step
// printed, the diffs it asked for, and whether it succeeded. The commits the stub scanned, head
// first, are in r.scans.
func (r *diffRepo) run(base string, env ...string) (out, diffs string, ok bool) {
	r.t.Helper()
	// #nosec G204 -- the Action's own checked-in script, run as GitHub runs it
	cmd := exec.Command("bash", "-c", actionDiffScript(r.t))
	cmd.Dir = r.dir
	cmd.Env = append(os.Environ(),
		"PATH="+r.bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"STUB_LOG="+r.log, "STUB_SCANS="+r.scans, "BASE_SHA="+base, "PR_HEAD_SHA=", "RUNNER_TEMP="+r.tmp,
		"INPUT_SAGA=draugr.saga.yaml", "INPUT_WORKING_DIRECTORY=", "INPUT_OUTPUT="+filepath.Join(r.root, "out"),
		"INPUT_CACHE_DIR=", "CACHE_READ_ONLY=", "INPUT_ARGS=", "INPUT_FAIL_ON_NEW=P1",
		"INPUT_FAIL_ON_NEW_PRIORITY=", "INPUT_DIFF_VIEW=", "INPUT_CODE_SCANNING=new",
		"INPUT_CODE_SCANNING_MIN_PRIORITY=", "GITHUB_OUTPUT="+filepath.Join(r.root, "github-output"),
		"GITHUB_SERVER_URL=https://github.com", "GITHUB_REPOSITORY=acme/shop")
	cmd.Env = append(cmd.Env, env...)
	b, err := cmd.CombinedOutput()
	d, _ := os.ReadFile(r.log) // #nosec G304 -- written by the stub under t.TempDir()
	return string(b), string(d), err == nil
}

// scanned returns the commits the stub scanned, in order.
func (r *diffRepo) scanned() []string {
	r.t.Helper()
	b, _ := os.ReadFile(r.scans) // #nosec G304 -- written by the stub under t.TempDir()
	return strings.Fields(string(b))
}

// runActionDiff runs the diff step in a repository whose base commit holds baseFiles and whose
// head holds headFiles, each a name or name=content, and returns what the step printed, the diffs
// it asked for, and whether it succeeded.
func runActionDiff(t *testing.T, baseFiles, headFiles []string, env ...string) (out, diffs string, ok bool) {
	t.Helper()
	r := newDiffRepo(t)
	base := r.commit(baseFiles)
	r.commit(headFiles)
	return r.run(base, env...)
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

// A fork's pull request gets a read-only token, so the comment cannot be posted. The step says so,
// leaves --publish off, writes the diff to the job summary, and passes or fails on the gate alone.
func TestTheActionDoesNotPublishFromAFork(t *testing.T) {
	t.Parallel()
	summary := filepath.Join(t.TempDir(), "summary.md")
	out, diffs, ok := runActionDiff(t, []string{"draugr.saga.yaml"}, []string{"draugr.saga.yaml", "app.js"},
		"FORK_PR=true", "STUB_PUBLISH_FAILS=1", "GITHUB_STEP_SUMMARY="+summary)
	if !ok {
		t.Fatalf("the step failed on a fork whose gate passed:\n%s", out)
	}
	if !strings.Contains(out, "::notice::This pull request comes from a fork") {
		t.Errorf("no notice that a fork's diff is not posted:\n%s", out)
	}
	if strings.Contains(diffs, "--publish") {
		t.Errorf("a fork's diff asked to publish:\n%s", diffs)
	}
	b, err := os.ReadFile(summary) // #nosec G304 -- under t.TempDir()
	if err != nil || !strings.Contains(string(b), "## stub markdown diff") {
		t.Errorf("the job summary does not hold the diff (%v):\n%s", err, b)
	}
}

// On a fork the gate still decides: a tripped gate fails the step.
func TestTheActionFailsAForkOnItsGate(t *testing.T) {
	t.Parallel()
	out, _, ok := runActionDiff(t, []string{"draugr.saga.yaml"}, []string{"draugr.saga.yaml", "app.js"},
		"FORK_PR=true", "STUB_GATE_TRIPS=1", "GITHUB_STEP_SUMMARY="+filepath.Join(t.TempDir(), "summary.md"))
	if ok {
		t.Fatalf("the step passed on a fork whose gate tripped:\n%s", out)
	}
}

// A tripped gate still hands code scanning the new findings rather than the whole scan: the step
// fails on the gate only after the new-findings SARIF and the `sarif` output are written.
func TestATrippedGateStillUploadsOnlyTheNewFindings(t *testing.T) {
	t.Parallel()
	output := filepath.Join(t.TempDir(), "github-output")
	out, diffs, ok := runActionDiff(t, []string{"draugr.saga.yaml"}, []string{"draugr.saga.yaml", "app.js"},
		"FORK_PR=", "STUB_GATE_TRIPS=1", "GITHUB_OUTPUT="+output)
	if ok {
		t.Fatalf("the step passed on a gate that tripped:\n%s", out)
	}
	if !strings.Contains(diffs, "--format sarif") {
		t.Fatalf("no new-findings diff ran after the gate tripped:\n%s", diffs)
	}
	b, err := os.ReadFile(output) // #nosec G304 -- under t.TempDir()
	if err != nil || !strings.Contains(string(b), "sarif=") || !strings.Contains(string(b), "results-new.sarif") {
		t.Errorf("the sarif output does not name the new findings (%v):\n%s", err, b)
	}
}

// A new-findings diff that writes no report fails the step, rather than leaving code scanning the
// whole scan without a word.
func TestANewFindingsDiffThatWritesNothingFailsTheStep(t *testing.T) {
	t.Parallel()
	out, _, ok := runActionDiff(t, []string{"draugr.saga.yaml"}, []string{"draugr.saga.yaml", "app.js"},
		"FORK_PR=", "STUB_SARIF_EMPTY=1")
	if ok {
		t.Fatalf("the step passed with no new-findings report:\n%s", out)
	}
	if !strings.Contains(out, "wrote no report") {
		t.Errorf("the failure does not say the report is missing:\n%s", out)
	}
}

// From the base repository the comment is posted, and a comment that cannot be posted still fails
// the step: a flag either does something or says why it did not.
func TestTheActionPublishesFromTheBaseRepository(t *testing.T) {
	t.Parallel()
	out, diffs, ok := runActionDiff(t, []string{"draugr.saga.yaml"}, []string{"draugr.saga.yaml", "app.js"},
		"FORK_PR=", "STUB_PUBLISH_FAILS=1")
	if ok {
		t.Fatalf("the step passed when the comment could not be posted:\n%s", out)
	}
	if !strings.Contains(diffs, "--publish") || strings.Contains(out, "comes from a fork") {
		t.Errorf("the base repository's diff was treated as a fork's:\n%s\n%s", out, diffs)
	}
}

// A pull request is a fork's when its head repository is not the base repository. head.repo.fork
// is true for a pull request between two branches of a repository that is itself a fork, whose token
// can post the comment and whose runs are the repository's own, so neither the comment nor the
// cache may key on it.
func TestTheActionTreatsOnlyAnotherRepositoryAsAFork(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("../../action.yml")
	if err != nil {
		t.Fatal(err)
	}
	const want = "github.event.pull_request.head.repo.full_name != github.repository"
	set := 0
	for i, line := range strings.Split(string(raw), "\n") {
		code := strings.TrimSpace(line)
		if strings.HasPrefix(code, "#") {
			continue
		}
		if strings.Contains(code, "head.repo.fork") {
			t.Errorf("action.yml:%d keys on head.repo.fork: %s", i+1, code)
		}
		for _, name := range []string{"FORK_PR:", "CACHE_READ_ONLY:"} {
			if strings.HasPrefix(code, name) {
				set++
				if !strings.Contains(code, want) {
					t.Errorf("action.yml:%d sets %s without %q: %s", i+1, strings.TrimSuffix(name, ":"), want, code)
				}
			}
		}
	}
	if set == 0 {
		t.Error("action.yml sets neither FORK_PR nor CACHE_READ_ONLY, so this test checks nothing")
	}
}

// pullRequestHistory builds a pull request's history: main at oldMain, the pull request's head
// branched from it, main moved on to newMain, and the head merged onto newMain, the shape of
// GitHub's default pull_request checkout. HEAD is left at the merge.
func pullRequestHistory(r *diffRepo) (oldMain, head, newMain string) {
	r.t.Helper()
	oldMain = r.commit([]string{"draugr.saga.yaml"})
	r.git("checkout", "-q", "-b", "pr")
	head = r.commit([]string{"draugr.saga.yaml", "app.js"})
	r.git("checkout", "-q", "main")
	newMain = r.commit([]string{"draugr.saga.yaml", "main.js"})
	r.git("merge", "-q", "--no-ff", "-m", "merge", "pr")
	return oldMain, head, newMain
}

// A pull request is compared against the commit its checkout is merged onto. When the event's base
// is another commit, a diff against it would credit the pull request with whatever main changed in
// between, so the step says which commit it uses and why. Every other checkout keeps the event's
// base: the head itself, a merge queue entry, and a merge that is not this pull request's.
func TestTheActionDiffsAPullRequestAgainstTheCommitItsCheckoutIsMergedOnto(t *testing.T) {
	t.Parallel()
	const notice = "::notice::The event names"
	// Each commit is named by its role in pullRequestHistory: "old" and "new" main, the pull
	// request's "head", "other" for a commit that is none of them, and "" for no commit.
	cases := []struct {
		name string
		// base and prHead are the event's base and head, and want is the commit the base scan
		// has to be. atHead checks out the head itself rather than the merge.
		base, prHead, want string
		atHead, wantNotice bool
	}{
		{name: "the event's base is older than the merge's", base: "old", prHead: "head", want: "new", wantNotice: true},
		{name: "the event's base is the merge's", base: "new", prHead: "head", want: "new"},
		{name: "the checkout is the head itself", base: "new", prHead: "head", want: "new", atHead: true},
		// PR_HEAD_SHA is empty on every event but pull_request and pull_request_target, which
		// TestTheActionReadsThePullRequestHeadOnlyOnPullRequestEvents holds.
		{name: "a merge queue entry", base: "old", prHead: "", want: "old"},
		{name: "the merge is not of this pull request's head", base: "old", prHead: "other", want: "old"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			r := newDiffRepo(t)
			oldMain, head, newMain := pullRequestHistory(r)
			commits := map[string]string{"old": oldMain, "new": newMain, "head": head,
				"other": strings.Repeat("ab", 20), "": ""}
			if c.atHead {
				r.git("checkout", "-q", "--detach", head)
			}
			base, prHead, want := commits[c.base], commits[c.prHead], commits[c.want]
			checkout := r.git("rev-parse", "HEAD")
			out, _, ok := r.run(base, "PR_HEAD_SHA="+prHead)
			if !ok {
				t.Fatalf("the step failed:\n%s", out)
			}
			if got := r.scanned(); len(got) != 2 || got[0] != checkout || got[1] != want {
				t.Errorf("scanned %v, want the checkout %s and then the base %s:\n%s", got, checkout, want, out)
			}
			if !c.wantNotice {
				if strings.Contains(out, notice) {
					t.Errorf("a notice about the base where the event's base is kept:\n%s", out)
				}
				return
			}
			if strings.Count(out, notice) != 1 {
				t.Errorf("want one notice about the base, got:\n%s", out)
			}
			line := "::notice::The event names " + base + " as the pull request's base, but the checkout merges " +
				"the pull request onto " + want + ". The diff compares against " + want
			if !strings.Contains(out, line) {
				t.Errorf("the notice does not name both commits; want %q in:\n%s", line, out)
			}
		})
	}
}

// The step reads the pull request's head only on the two pull request events, so a merge queue
// entry, or any other event, keeps the event's base. It reads it through the environment: a value
// interpolated into the script would be run as shell.
func TestTheActionReadsThePullRequestHeadOnlyOnPullRequestEvents(t *testing.T) {
	t.Parallel()
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
	var env string
	for _, step := range action.Runs.Steps {
		if step.ID == "diff" {
			env = step.Env["PR_HEAD_SHA"]
		}
	}
	for _, want := range []string{"github.event_name == 'pull_request'", "github.event_name == 'pull_request_target'",
		"github.event.pull_request.head.sha"} {
		if !strings.Contains(env, want) {
			t.Errorf("the diff step's PR_HEAD_SHA is %q, without %q", env, want)
		}
	}
	if strings.Contains(actionDiffScript(t), "${{") {
		t.Error("the diff step's script interpolates an expression; pass it in through env")
	}
}
