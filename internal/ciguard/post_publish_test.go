package ciguard

import (
	"maps"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// postPublish is the workflow holding everything a release does after it is published.
const postPublish = "release-post-publish.yml"

// afterThePublish names each job a published release still needs by a line of what it runs. Found
// by content rather than by job name, so renaming a job cannot make a guard below pass by finding
// nothing.
var afterThePublish = map[string]string{
	"the MCP Bundle":        "contrib/mcpb/build.sh",
	"the docs site rebuild": "CLOUDFLARE_PAGES_DEPLOY_HOOK",
	"the sample report":     "scripts/demo-report.sh",
	"the registry listing":  "mcp-publisher",
}

// codeOnly drops full-line comments. The comments in these workflows name the same scripts and
// steps the code runs, so a guard reading for what a job does reads the code alone.
func codeOnly(s string) string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(l), "#") {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}

// jobCode returns each job of a workflow as its code, keyed by job name.
func jobCode(t *testing.T, workflow string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, block := range jobBlocks(readRepoFile(t, ".github/workflows/"+workflow)) {
		first, _, _ := strings.Cut(block, "\n")
		out[strings.TrimSuffix(strings.TrimSpace(first), ":")] = codeOnly(block)
	}
	return out
}

// movesARef reports whether code changes a ref on the remote, by the API or by a push.
func movesARef(code string) bool {
	return strings.Contains(code, "/git/refs") || strings.Contains(code, "git push") ||
		strings.Contains(code, "git tag -f")
}

// upstream returns every job name waits on, directly or through another job.
func upstream(w nightlyWorkflow, name string) []string {
	var out []string
	queue := w.Jobs[name].needs()
	for len(queue) > 0 {
		next := queue[0]
		queue = queue[1:]
		if slices.Contains(out, next) {
			continue
		}
		out = append(out, next)
		queue = append(queue, w.Jobs[next].needs()...)
	}
	return out
}

// workflowShape is the part of any workflow the guards that read every file need. Only these fields
// are decoded, so a job written in a shape the other readers here do not expect cannot fail the
// parse.
type workflowShape struct {
	On   any `yaml:"on"`
	Jobs map[string]struct {
		Uses    string `yaml:"uses"`
		RunsOn  any    `yaml:"runs-on"`
		Secrets any    `yaml:"secrets"`
	} `yaml:"jobs"`
}

func readAllWorkflows(t *testing.T) map[string]workflowShape {
	t.Helper()
	paths, err := filepath.Glob(repoPath(".github/workflows/*.yml"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("no workflows found: %v", err)
	}
	out := map[string]workflowShape{}
	for _, p := range paths {
		name := filepath.Base(p)
		var w workflowShape
		if err := yaml.Unmarshal([]byte(readRepoFile(t, ".github/workflows/"+name)), &w); err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		out[name] = w
	}
	return out
}

// TestNothingAfterThePublishWaitsOnTheMajorTag holds the major tag's move to a job nothing else
// waits on.
//
// A failed step skips every step after it in its job, and a failed job skips every job that needs
// it. With the move in the job that publishes, or in one the others need, a refused move leaves a
// published release with no MCP Bundle, no registry listing, no sample report and stale docs, and
// none of them can be run again without running the publish again. The archives are signed and
// downloadable throughout, which is what makes the gap easy to miss.
//
// The run still has to go red when the move fails, so nothing here carries continue-on-error.
func TestNothingAfterThePublishWaitsOnTheMajorTag(t *testing.T) {
	t.Parallel()
	w := readWorkflow(t, postPublish)
	code := jobCode(t, postPublish)

	var movers []string
	for name, body := range code {
		if movesARef(body) {
			movers = append(movers, name)
		}
	}
	if len(movers) != 1 {
		t.Fatalf("%s moves a ref in %d jobs %v; the major tag's move has to be exactly one job",
			postPublish, len(movers), movers)
	}
	mover := movers[0]

	for what, marker := range afterThePublish {
		var found []string
		for name, body := range code {
			if strings.Contains(body, marker) {
				found = append(found, name)
			}
		}
		if len(found) == 0 {
			t.Errorf("no job in %s runs %s (%s), so a release publishes without it", postPublish, what, marker)
		}
		for _, name := range found {
			if name == mover {
				t.Errorf("%s runs %s in %s, the job that moves the major tag, so a refused move skips it",
					postPublish, what, mover)
			}
			if slices.Contains(upstream(w, name), mover) {
				t.Errorf("%s: %s, which runs %s, waits on %s, so a refused move skips it",
					postPublish, name, what, mover)
			}
		}
	}

	if strings.Contains(codeOnly(readRepoFile(t, ".github/workflows/"+postPublish)), "continue-on-error") {
		t.Errorf("%s uses continue-on-error, so a job that failed reports success and the release run "+
			"is green with a step missing", postPublish)
	}

	// And release.yml publishes and stops, handing everything above to this workflow.
	release := readWorkflow(t, "release.yml")
	goreleaser, ok := jobCode(t, "release.yml")["goreleaser"]
	if !ok {
		t.Fatal("release.yml has no goreleaser job")
	}
	if movesARef(goreleaser) {
		t.Error("release.yml's goreleaser job moves a ref, so a refused move skips every step after " +
			"it, and none of them can run again without publishing again")
	}
	for what, marker := range afterThePublish {
		if strings.Contains(goreleaser, marker) {
			t.Errorf("release.yml's goreleaser job runs %s (%s), which belongs in %s, where running it "+
				"again does not publish again", what, marker, postPublish)
		}
	}
	caller := ""
	for name, job := range release.Jobs {
		if job.Uses == "./.github/workflows/"+postPublish {
			caller = name
		}
	}
	if caller == "" {
		t.Fatalf("release.yml does not call %s, so a release publishes and stops there", postPublish)
	}
	if !slices.Contains(release.Jobs[caller].needs(), "goreleaser") {
		t.Errorf("release.yml's %s job does not wait on goreleaser, so it can run before the release exists", caller)
	}
	if tag, _ := release.Jobs[caller].With["tag"].(string); !strings.Contains(tag, "inputs.tag") || !strings.Contains(tag, "github.ref_name") {
		t.Errorf("release.yml passes tag %q to %s; it has to be the tag this run released", tag, postPublish)
	}
}

// TestTheMajorTagMovesWithAWorkflowsGrant holds the move to a token GitHub lets make it.
//
// GitHub refuses an App's ref update onto a commit carrying a workflow file that no branch holds
// with the same contents, unless the token has `workflows`, and GITHUB_TOKEN cannot be given that
// permission. Whether a move needs it depends on what main holds at that moment, so a move passes
// while main's workflows match the tag's and is refused once one of them changes.
//
// The token asks for `contents` and `workflows` by name and for nothing else, so it holds those
// two whatever the App is granted.
func TestTheMajorTagMovesWithAWorkflowsGrant(t *testing.T) {
	t.Parallel()
	w := readWorkflow(t, postPublish)
	mover := ""
	for name, body := range jobCode(t, postPublish) {
		if movesARef(body) {
			mover = name
		}
	}
	if mover == "" {
		t.Fatalf("%s moves no ref, so nothing moves the major tag", postPublish)
	}
	job := w.Jobs[mover]

	token := ""
	for _, s := range job.Steps {
		if !strings.HasPrefix(s.Uses, "actions/create-github-app-token@") {
			continue
		}
		token = s.ID
		granted := map[string]any{}
		for k, v := range s.With {
			if strings.HasPrefix(k, "permission-") {
				granted[k] = v
			}
		}
		want := map[string]any{"permission-contents": "write", "permission-workflows": "write"}
		if !maps.Equal(granted, want) {
			t.Errorf("the %s token requests %v, want exactly %v: without workflows the move is refused "+
				"whenever main's workflows differ from the tag's, and anything more is a grant the move "+
				"does not use", mover, granted, want)
		}
	}
	if token == "" {
		t.Fatalf("%s mints no App token, so it moves the tag as GITHUB_TOKEN, which cannot hold workflows", mover)
	}

	moved := false
	for _, s := range job.Steps {
		if !movesARef(s.Run) {
			continue
		}
		moved = true
		if want := "${{ steps." + token + ".outputs.token }}"; s.Env["GH_TOKEN"] != want {
			t.Errorf("step %q moves the tag with GH_TOKEN=%q, want %s", s.Name, s.Env["GH_TOKEN"], want)
		}
	}
	if !moved {
		t.Errorf("no step of %s moves a ref", mover)
	}
}

// hostedLabel is a GitHub-hosted runner image. A label read from a variable, or `self-hosted`, is
// not one.
var hostedLabel = regexp.MustCompile(`^(ubuntu|windows|macos)-[0-9a-z.-]+$`)

// TestTheReleaseAppKeyStaysOnHostedRunners. A self-hosted runner runs every pull request's code, so
// a credential a job holds there is reachable from a pull request. The release App's key pushes
// release tags, opens release pull requests and moves the major tag, so every job holding it runs
// on a GitHub-hosted runner whatever the repository's RUNNER variable says.
func TestTheReleaseAppKeyStaysOnHostedRunners(t *testing.T) {
	t.Parallel()
	checked := 0
	for name, w := range readAllWorkflows(t) {
		code := jobCode(t, name)
		for job, spec := range w.Jobs {
			// A job calling another workflow holds no runner; the called workflow's jobs are read
			// in their own file.
			if spec.Uses != "" || !strings.Contains(code[job], "secrets.RELEASE_APP_PRIVATE_KEY") {
				continue
			}
			checked++
			if label, _ := spec.RunsOn.(string); !hostedLabel.MatchString(label) {
				t.Errorf("%s: %s holds the release App's key on runs-on %v, which is not a GitHub-hosted "+
					"runner", name, job, spec.RunsOn)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no job holds the release App's key, so this guard is reading the wrong files")
	}
}

// TestTheMajorTagStartsNoWorkflow. The major tag is moved with an App token, and a push made with
// one starts any workflow listening for it, so a workflow whose push trigger matches `v0` starts
// on every release. If that workflow is release.yml, it tries to publish v0 as a release.
//
// Path filters do not apply to a tag push, so a push trigger that names no branches and no tags
// fires on every tag. A `create` trigger fires when a new major's tag is first created.
func TestTheMajorTagStartsNoWorkflow(t *testing.T) {
	t.Parallel()
	workflows := readAllWorkflows(t)
	for name, w := range workflows {
		for _, tag := range []string{"v0", "v1"} {
			if firesOnTag(w.On, tag) {
				t.Errorf("%s starts on a push of the tag %s, which the release moves on every release", name, tag)
			}
		}
	}
	// The matcher has to recognize the trigger it is guarding, or every answer above is "no".
	if !firesOnTag(workflows["release.yml"].On, "v1.2.3") {
		t.Error("release.yml does not start on a push of v1.2.3, so either its trigger no longer " +
			"matches a release tag or this guard cannot read it")
	}
}

// firesOnTag reports whether a workflow's `on:` starts it for a push of tag.
func firesOnTag(on any, tag string) bool {
	switch v := on.(type) {
	case string:
		return v == "push" || v == "create"
	case []any:
		return slices.Contains(v, any("push")) || slices.Contains(v, any("create"))
	case map[string]any:
		if _, ok := v["create"]; ok {
			return true
		}
		push, ok := v["push"]
		if !ok {
			return false
		}
		filters, _ := push.(map[string]any)
		if tags, ok := filters["tags"]; ok {
			return matchesFilter(tags, tag)
		}
		if ignore, ok := filters["tags-ignore"]; ok {
			return !matchesFilter(ignore, tag)
		}
		_, branches := filters["branches"]
		_, branchesIgnore := filters["branches-ignore"]
		// Branches named and tags not: GitHub runs it for branch pushes only.
		return !branches && !branchesIgnore
	}
	return false
}

// matchesFilter applies a list of GitHub ref patterns in order, a `!` pattern excluding what the
// ones before it matched. path.Match reads `*`, `?` and `[...]` as GitHub does for a name with no
// slash, which a tag here never has.
func matchesFilter(patterns any, ref string) bool {
	list, _ := patterns.([]any)
	matched := false
	for _, p := range list {
		s, _ := p.(string)
		if neg, ok := strings.CutPrefix(s, "!"); ok {
			if m, _ := path.Match(neg, ref); m {
				matched = false
			}
			continue
		}
		if m, _ := path.Match(s, ref); m {
			matched = true
		}
	}
	return matched
}

// TestThePostPublishPathNeverBuilds. release-post-publish.yml runs again for a release that is
// already out, by hand and as often as it takes, which is safe only because it publishes none of
// the release's archives. A build or a signature added here would put a second set under a tag
// people have already verified, and dispatched from main it would sign them as main, which no
// verifier accepts.
//
// It also refuses a tag with no published release, so every job waits on the job that checks.
func TestThePostPublishPathNeverBuilds(t *testing.T) {
	t.Parallel()
	code := codeOnly(readRepoFile(t, ".github/workflows/"+postPublish))
	for _, forbidden := range []string{
		"goreleaser",              // builds and publishes the archives
		"id-token: write",         // keyless signing
		"attestations: write",     // build provenance
		"attest-build-provenance", // the same, by the action
		"cosign sign",             // signing by hand
	} {
		if strings.Contains(code, forbidden) {
			t.Errorf("%s contains %q; it finishes a published release and must not build, sign or "+
				"publish one", postPublish, forbidden)
		}
	}

	w := readWorkflow(t, postPublish)
	for _, trigger := range []string{"workflow_call", "workflow_dispatch"} {
		spec, _ := w.On[trigger].(map[string]any)
		inputs, _ := spec["inputs"].(map[string]any)
		if _, ok := inputs["tag"]; !ok {
			t.Errorf("%s has no %s trigger taking a tag, so it cannot be %s", postPublish, trigger,
				map[string]string{"workflow_call": "called by release.yml", "workflow_dispatch": "run for a release that exists"}[trigger])
		}
	}

	var roots []string
	for name, job := range w.Jobs {
		if len(job.needs()) == 0 {
			roots = append(roots, name)
		}
	}
	if len(roots) != 1 {
		t.Fatalf("%s has %d jobs that wait on nothing %v; only the check that the release exists may",
			postPublish, len(roots), roots)
	}
	gate := roots[0]
	if !strings.Contains(jobCode(t, postPublish)[gate], "gh release view") {
		t.Errorf("%s's first job, %s, does not look the release up, so a tag with no release goes "+
			"through", postPublish, gate)
	}
	for name := range w.Jobs {
		if name != gate && !slices.Contains(upstream(w, name), gate) {
			t.Errorf("%s: %s does not wait on %s, so it runs for a tag with no published release",
				postPublish, name, gate)
		}
	}
}

// TestCallersPassEverySecretTheCalledWorkflowDeclares. A called workflow reads only the secrets its
// caller passes by name, and an environment secret is no exception: the caller names it even though
// only the called job's environment holds a value. A secret left out reads as empty, and a job
// written to skip when its key is unset, as one has to be for a fork, then skips with its step
// green.
func TestCallersPassEverySecretTheCalledWorkflowDeclares(t *testing.T) {
	t.Parallel()
	workflows := readAllWorkflows(t)
	for name, w := range workflows {
		for job, spec := range w.Jobs {
			called := calledWorkflow("uses: " + spec.Uses)
			if called == "" {
				continue
			}
			if spec.Secrets == "inherit" {
				continue
			}
			passed, _ := spec.Secrets.(map[string]any)
			for _, secret := range declaredSecrets(workflows[called].On) {
				if _, ok := passed[secret]; !ok {
					t.Errorf("%s: %s calls %s without passing %s, so the called workflow reads it as empty",
						name, job, called, secret)
				}
			}
		}
	}
}

// declaredSecrets lists the secrets a workflow's `workflow_call` trigger declares.
func declaredSecrets(on any) []string {
	triggers, _ := on.(map[string]any)
	call, _ := triggers["workflow_call"].(map[string]any)
	secrets, _ := call["secrets"].(map[string]any)
	return slices.Sorted(maps.Keys(secrets))
}
