package ciguard

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// pipedQuietGrep matches a pipe into `grep -q`, with -q anywhere among its short flags, and leaves
// `||` alone.
var pipedQuietGrep = regexp.MustCompile(`(^|[^|])\|[ \t]*grep[ \t]+-[A-Za-z]*q`)

// quietGreps names each line of a script that pipes into `grep -q`, as "line N".
//
// `grep -q` exits at its first match and stops reading. Whatever writes into the pipe is then killed
// by SIGPIPE once the pipe is full, and under `pipefail`, which the `bash` shell of a GitHub Actions
// step sets, the pipeline fails although the match was found. An `if` around it takes the branch
// for "not found", which is how a filter comes to say no code changed and every check after it
// passes having run nothing. The list is captured first and searched second instead.
func quietGreps(text string) []string {
	var out []string
	for i, line := range strings.Split(text, "\n") {
		if pipedQuietGrep.MatchString(line) {
			out = append(out, "line "+strconv.Itoa(i+1))
		}
	}
	return out
}

// TestNoStepPipesIntoAQuietGrep holds every workflow and the published Action to capturing a list
// before searching it, never piping it into `grep -q`.
func TestNoStepPipesIntoAQuietGrep(t *testing.T) {
	t.Parallel()

	paths, err := filepath.Glob("../../.github/workflows/*.yml")
	if err != nil || len(paths) == 0 {
		t.Fatalf("no workflows found: %v", err)
	}
	paths = append(paths, "../../action.yml")
	for _, path := range paths {
		raw, err := os.ReadFile(path) // #nosec G304 -- a checked-in workflow
		if err != nil {
			t.Fatal(err)
		}
		for _, where := range quietGreps(string(raw)) {
			t.Errorf("%s, %s: pipes into `grep -q`, which can kill the writer with SIGPIPE and, "+
				"under pipefail, read a match as no match; capture the text first and search it "+
				"with `grep -q … <<<\"$text\"`", filepath.Base(path), where)
		}
	}
}

// The pattern finds the pipe wherever it sits on a line and in every spelling of the flag, and
// passes a here-string, a file argument and an `||`.
func TestQuietGrepsFindsAPipeIntoGrepQ(t *testing.T) {
	t.Parallel()
	for script, want := range map[string]int{
		"git diff --name-only \"$base\" HEAD | grep -qvE '^LICENSE$'":          1,
		"if git diff --name-only a b \\\n   | grep -q x; then":                 1,
		"jq -r . f.json|grep -q '[a-z]'":                                       1,
		"printf '%s' \"$out\" | grep -iq duplicate":                            1,
		"if grep -q 'duplicate' <<<\"$out\"; then":                             0,
		"grep -q . /tmp/left-out.txt":                                          0,
		"test -f x || grep -q y z":                                             0,
		"run: |\n  grep -q x file":                                             0,
		"changed=$(git diff --name-only a b)\ngrep -qvE '^LICENSE$' <<<\"$c\"": 0,
	} {
		if got := len(quietGreps(script)); got != want {
			t.Errorf("quietGreps(%q) found %d, want %d", script, got, want)
		}
	}
}
