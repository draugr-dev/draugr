package ciguard

import (
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The workflows the documentation shows a reader are files under examples/, and every page that
// shows one pastes the file. A workflow typed into a page by hand is a second copy, and copies of
// one workflow drift apart in triggers, thresholds and inputs without any of them looking wrong on
// the page it is read on.
//
// A fenced block is a workflow when it has both `on:` and `jobs:` at the top. A block of steps, such
// as the few lines showing one input of the action, is an excerpt: it is not pinned to a file,
// because it shows a reader where one input goes rather than a workflow to copy, and a file per
// input would be a workflow nobody runs. Every excerpt that uses the action is still held to the
// action's own inputs below.

// workflowExamples is where the shipped workflows live.
const workflowExamples = "../../examples/github-actions*.yml"

// actionRef is how a workflow names this repository's action.
const actionRef = "draugr-dev/draugr@"

// pastedDocs are the trees whose markdown a reader copies from.
var pastedDocs = []string{"../../README.md", "../../CONTRIBUTING.md", "../../docs", "../../contrib"}

// fence is one fenced YAML block in a markdown file.
type fence struct {
	path string
	line int
	body string
}

// yamlFences returns every ```yaml or ```yml block in the markdown under pastedDocs.
func yamlFences(t *testing.T) []fence {
	t.Helper()
	var fences []fence
	for _, root := range pastedDocs {
		err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".md") {
				return err
			}
			body, err := os.ReadFile(path) // #nosec G304,G122 -- a repository path this walk produced
			if err != nil {
				return err
			}
			fences = append(fences, fencesIn(path, string(body))...)
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
	return fences
}

// fencesIn returns the YAML blocks in one markdown document.
func fencesIn(path, doc string) []fence {
	var out []fence
	var cur *fence
	var lines []string
	for i, line := range strings.Split(doc, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case cur == nil && (trimmed == "```yaml" || trimmed == "```yml"):
			cur, lines = &fence{path: path, line: i + 1}, nil
		case cur != nil && trimmed == "```":
			cur.body = strings.Join(lines, "\n")
			out = append(out, *cur)
			cur = nil
		case cur != nil:
			lines = append(lines, line)
		}
	}
	return out
}

// exampleBody is a shipped workflow as a page pastes it: the file without the comment that opens
// it, which says what the file is for and is read in the file.
func exampleBody(raw string) string {
	lines := strings.Split(raw, "\n")
	start := 0
	for start < len(lines) {
		l := strings.TrimSpace(lines[start])
		if l != "" && !strings.HasPrefix(l, "#") {
			break
		}
		start++
	}
	return strings.TrimSpace(strings.Join(lines[start:], "\n"))
}

// workflowExampleFiles reads each shipped workflow, keyed by its path.
func workflowExampleFiles(t *testing.T) map[string]string {
	t.Helper()
	paths, err := filepath.Glob(workflowExamples)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatalf("nothing matches %s, so this guard has been checking nothing", workflowExamples)
	}
	files := map[string]string{}
	for _, p := range paths {
		b, err := os.ReadFile(p) // #nosec G304 -- a fixed glob under examples/
		if err != nil {
			t.Fatal(err)
		}
		files[p] = string(b)
	}
	return files
}

// mappingValue returns the value under key in a mapping node, or nil.
func mappingValue(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

// mappingKeys lists the keys of a mapping node.
func mappingKeys(n *yaml.Node) []string {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	keys := make([]string, 0, len(n.Content)/2)
	for i := 0; i+1 < len(n.Content); i += 2 {
		keys = append(keys, n.Content[i].Value)
	}
	return keys
}

// actionUses returns the `with` of every step that uses this repository's action, in document
// order, with the line of its `uses`. A step that gives no `with` is returned with a nil one.
func actionUses(root *yaml.Node) []actionUse {
	var out []actionUse
	var walk func(*yaml.Node)
	walk = func(n *yaml.Node) {
		if n.Kind == yaml.MappingNode {
			if uses := mappingValue(n, "uses"); uses != nil && strings.HasPrefix(uses.Value, actionRef) {
				out = append(out, actionUse{line: uses.Line, with: mappingValue(n, "with")})
			}
		}
		for _, c := range n.Content {
			walk(c)
		}
	}
	walk(root)
	return out
}

type actionUse struct {
	line int
	with *yaml.Node
}

// isWorkflow reports whether a parsed block is a whole workflow rather than an excerpt of one.
func isWorkflow(doc *yaml.Node) bool {
	top := doc
	if doc.Kind == yaml.DocumentNode && len(doc.Content) > 0 {
		top = doc.Content[0]
	}
	return mappingValue(top, "on") != nil && mappingValue(top, "jobs") != nil
}

// actionInputs is every input action.yml declares.
func actionInputs(t *testing.T) map[string]bool {
	t.Helper()
	raw, err := os.ReadFile("../../action.yml")
	if err != nil {
		t.Fatal(err)
	}
	var action struct {
		Inputs map[string]any `yaml:"inputs"`
	}
	if err := yaml.Unmarshal(raw, &action); err != nil {
		t.Fatal(err)
	}
	if len(action.Inputs) == 0 {
		t.Fatal("action.yml declares no inputs, so this guard has been checking nothing")
	}
	inputs := map[string]bool{}
	for k := range action.Inputs {
		inputs[k] = true
	}
	return inputs
}

// checkActionUse reports a use of the action that leaves out the descriptor, which action.yml
// requires, or names an input the action does not have. GitHub warns about an unknown input in
// the run's annotations and carries on, so a misspelled `fail-on-new` gates nothing and the run is
// green.
func checkActionUse(t *testing.T, where string, u actionUse, inputs map[string]bool) {
	t.Helper()
	if mappingValue(u.with, "saga") == nil {
		t.Errorf("%s:%d uses the action without `saga:`, which action.yml marks required", where, u.line)
	}
	for _, k := range mappingKeys(u.with) {
		if !inputs[k] {
			t.Errorf("%s:%d gives the action %q, which action.yml does not declare", where, u.line, k)
		}
	}
}

// TestEveryPastedWorkflowIsAnExample holds each workflow a page shows to the file under examples/
// it was pasted from, so a change to either fails until the other follows.
func TestEveryPastedWorkflowIsAnExample(t *testing.T) {
	t.Parallel()

	files := workflowExampleFiles(t)
	bodies := map[string]bool{}
	for _, raw := range files {
		bodies[exampleBody(raw)] = true
	}
	var names []string
	for p := range files {
		names = append(names, strings.TrimPrefix(p, "../../"))
	}
	sort.Strings(names)

	workflows := 0
	for _, f := range yamlFences(t) {
		var doc yaml.Node
		if err := yaml.Unmarshal([]byte(f.body), &doc); err != nil || !isWorkflow(&doc) {
			continue
		}
		workflows++
		if !bodies[strings.TrimSpace(f.body)] {
			t.Errorf("%s:%d shows a workflow that is none of %s.\n"+
				"Paste the file it shows, everything after its opening comment, or add the workflow "+
				"as a file under examples/ and paste that.",
				strings.TrimPrefix(f.path, "../../"), f.line, strings.Join(names, ", "))
		}
	}
	if workflows == 0 {
		t.Fatal("no page shows a workflow, so this guard has been checking nothing")
	}
}

// TestEveryUseOfTheActionInTheDocsGivesItsRealInputs holds each block a page shows, whole
// workflow or excerpt, to action.yml: the descriptor is given, and every input named is one the
// action has. A block that mentions the action and cannot be read as YAML fails, because it
// cannot be checked.
func TestEveryUseOfTheActionInTheDocsGivesItsRealInputs(t *testing.T) {
	t.Parallel()

	inputs := actionInputs(t)
	uses := 0
	for _, f := range yamlFences(t) {
		if !strings.Contains(f.body, actionRef) {
			continue
		}
		where := strings.TrimPrefix(f.path, "../../")
		var doc yaml.Node
		if err := yaml.Unmarshal([]byte(f.body), &doc); err != nil {
			t.Errorf("%s:%d names the action in a block that is not YAML, so it cannot be checked: %v",
				where, f.line, err)
			continue
		}
		for _, u := range actionUses(&doc) {
			uses++
			u.line += f.line // the block's own line numbers start after the fence
			checkActionUse(t, where, u, inputs)
		}
	}
	if uses == 0 {
		t.Fatal("no page uses the action, so this guard has been checking nothing")
	}
}

// TestEveryWorkflowExampleGatesAPullRequest holds each shipped workflow to what it is for: gating
// a pull request for the descriptor `draugr init` writes.
//
//   - It runs on pull_request, where the action compares the change with its base.
//   - A push trigger names its branches. An unfiltered push runs again on every branch a
//     same-repository pull request pushes, as a full scan that gates the backlog the change
//     inherited rather than the findings it added.
//   - Each use of the action sets `fail-on-new`. `draugr init` writes no config.gate.failOnNew, and
//     a diff with no threshold fails on nothing. A threshold in the workflow also stands when a
//     pull request edits the descriptor it is judged with.
//   - Each use gives `saga:` and only inputs action.yml declares.
func TestEveryWorkflowExampleGatesAPullRequest(t *testing.T) {
	t.Parallel()

	inputs := actionInputs(t)
	for path, raw := range workflowExampleFiles(t) {
		name := strings.TrimPrefix(path, "../../")
		t.Run(filepath.Base(path), func(t *testing.T) {
			var doc yaml.Node
			if err := yaml.Unmarshal([]byte(raw), &doc); err != nil {
				t.Fatalf("%s is not YAML: %v", name, err)
			}
			if !isWorkflow(&doc) {
				t.Fatalf("%s has no `on:` and `jobs:` at the top, so it is not a workflow", name)
			}
			on := mappingValue(doc.Content[0], "on")
			for _, problem := range triggerProblems(on) {
				t.Errorf("%s: %s", name, problem)
			}
			uses := actionUses(&doc)
			if len(uses) == 0 {
				t.Fatalf("%s never uses %s", name, actionRef)
			}
			for _, u := range uses {
				checkActionUse(t, name, u, inputs)
				if v := mappingValue(u.with, "fail-on-new"); v == nil || strings.TrimSpace(v.Value) == "" {
					t.Errorf("%s:%d sets no `fail-on-new`, so a pull request for a descriptor `draugr init` "+
						"wrote fails on nothing", name, u.line)
				}
			}
		})
	}
}

// triggerProblems says what is wrong with a workflow's `on:` for a job that gates pull requests.
func triggerProblems(on *yaml.Node) []string {
	var events []string
	switch on.Kind {
	case yaml.ScalarNode:
		events = []string{on.Value}
	case yaml.SequenceNode:
		for _, c := range on.Content {
			events = append(events, c.Value)
		}
	case yaml.MappingNode:
		events = mappingKeys(on)
	}
	var problems []string
	if !slices.Contains(events, "pull_request") {
		problems = append(problems, "it does not run on pull_request")
	}
	if slices.Contains(events, "push") {
		push := mappingValue(on, "push")
		if push == nil || (mappingValue(push, "branches") == nil && mappingValue(push, "tags") == nil) {
			problems = append(problems, "its push trigger names no branches, so a pull request from "+
				"this repository runs twice and the push run gates the whole backlog")
		}
	}
	return problems
}

// TestTriggerProblemsReadsEachShapeOfOn holds the trigger check to the three ways a workflow
// writes `on:`.
func TestTriggerProblemsReadsEachShapeOfOn(t *testing.T) {
	t.Parallel()
	cases := map[string]int{
		"on: pull_request":         0,
		"on: push":                 2,
		"on: [push, pull_request]": 1,
		"on:\n  pull_request:\n  push:\n    branches: [main]": 0,
		"on:\n  pull_request:\n  push:\n":                     1,
		"on:\n  push:\n    tags: ['v*']\n  pull_request:\n":   0,
	}
	for src, want := range cases {
		var doc yaml.Node
		if err := yaml.Unmarshal([]byte(src), &doc); err != nil {
			t.Fatal(err)
		}
		if got := triggerProblems(mappingValue(doc.Content[0], "on")); len(got) != want {
			t.Errorf("%q: %d problems %v, want %d", src, len(got), got, want)
		}
	}
}

// TestFencesInReadsOnlyYAMLBlocks holds the block reader to the fences it is meant to find.
func TestFencesInReadsOnlyYAMLBlocks(t *testing.T) {
	t.Parallel()
	doc := "text\n```yaml\na: 1\n```\n```console\n$ x\n```\n  ```yml\n  b: 2\n  ```\n"
	got := fencesIn("p.md", doc)
	if len(got) != 2 || got[0].body != "a: 1" || got[0].line != 2 || got[1].body != "  b: 2" {
		t.Errorf("fencesIn = %+v", got)
	}
	if b := exampleBody("# a\n#\n\nname: x\non: push\n"); b != "name: x\non: push" {
		t.Errorf("exampleBody = %q", b)
	}
}
