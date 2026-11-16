package scanners

import (
	"bufio"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// goGeneratedLine is the comment the go command defines as marking a file a program wrote (`go help
// generate`). Every Go tool that reads it treats the file as output rather than source.
var goGeneratedLine = regexp.MustCompile(`^// Code generated .* DO NOT EDIT\.$`)

// markGenerated marks each result in a Go file under dir whose header says a generator wrote it,
// so the report lists it after the hand-written code's findings and points at the generator. The
// finding still counts: generated code is compiled into the program like any other.
//
// The mark rests on the convention the Go toolchain defines, not on a file's name, so a
// `_gen.go` file without the header is not marked.
func markGenerated(dir string, results []sarif.Result) {
	if dir == "" {
		return
	}
	read := map[string]bool{}
	for i := range results {
		// A scanner may report the path as written to it, absolute or as a file:// URI, before the
		// run makes it relative to the checkout.
		uri := repoRelPath(dir, results[i].Location.URI)
		if !strings.HasSuffix(uri, ".go") || !insideCheckout(uri) {
			continue
		}
		generated, ok := read[uri]
		if !ok {
			generated = goGenerated(filepath.Join(dir, filepath.FromSlash(uri)))
			read[uri] = generated
		}
		if generated {
			results[i].Aside = sarif.AsideGenerated
		}
	}
}

// insideCheckout reports whether uri is a relative path that stays inside the directory it is read
// against.
func insideCheckout(uri string) bool {
	if uri == "" || strings.Contains(uri, "://") || path.IsAbs(uri) {
		return false
	}
	clean := path.Clean(uri)
	return clean != ".." && !strings.HasPrefix(clean, "../")
}

// goGenerated reports whether the Go file at p carries the generated-code comment before its first
// line that is neither blank nor a comment, where the go command looks for it. A file that cannot
// be read is not marked.
func goGenerated(p string) bool {
	f, err := os.Open(p) // #nosec G304 -- a file a scanner reported inside the checkout it was given
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	lines := bufio.NewScanner(f)
	inBlock := false
	for lines.Scan() {
		line := strings.TrimSuffix(lines.Text(), "\r")
		if goGeneratedLine.MatchString(line) {
			return true
		}
		t := strings.TrimSpace(line)
		switch {
		case inBlock:
			inBlock = !strings.Contains(t, "*/")
		case t == "", strings.HasPrefix(t, "//"):
		case strings.HasPrefix(t, "/*"):
			inBlock = !strings.Contains(t[2:], "*/")
		default:
			return false
		}
	}
	return false
}

// actionsLockPath is where `gh actions-lock` writes the lockfile of a repository's workflows.
const actionsLockPath = ".github/workflows/actions.lock"

// actionsLock is the part of an actions lockfile the pinned mark reads: the references each
// workflow uses, and the commit each reference was resolved to.
type actionsLock struct {
	Workflows    map[string][]string `yaml:"workflows"`
	Dependencies map[string]struct {
		Commit string `yaml:"commit"`
	} `yaml:"dependencies"`
}

// usesLine is a step's or job's `uses:` value, quoted or not, with any trailing comment.
var usesLine = regexp.MustCompile(`^\s*(?:-\s*)?uses:\s*["']?([^"'\s#]+)`)

// mutableTagRule reports whether ruleID is Semgrep's GitHub Actions mutable-tag rule, under any
// prefix Semgrep gave it.
func mutableTagRule(ruleID string) bool {
	return strings.HasSuffix(ruleID, "github-actions-mutable-action-tag")
}

// workflowsDir is the directory GitHub reads a repository's workflows from. It reads no
// subdirectory of it.
const workflowsDir = ".github/workflows"

// linesOf is the lines of the file at uri inside dir, read once into lines.
func linesOf(dir, uri string, lines map[string][]string) []string {
	file, ok := lines[uri]
	if !ok {
		file = readLines(filepath.Join(dir, filepath.FromSlash(uri)))
		lines[uri] = file
	}
	return file
}

// usesAt is the `uses:` reference on the 1-based line of the file at uri inside dir. Empty where
// the line is past the end or holds no `uses:`.
func usesAt(dir, uri string, line int, lines map[string][]string) string {
	file := linesOf(dir, uri, lines)
	if line < 1 || line > len(file) {
		return ""
	}
	m := usesLine.FindStringSubmatch(file[line-1])
	if m == nil {
		return ""
	}
	return m[1]
}

// localAction is the directory, relative to the repository root, that a `uses:` reference to an
// action in the same repository names: `./.github/actions/setup` and `$/.github/actions/setup` are
// both `.github/actions/setup`. Empty for any other reference.
//
// A `./` path runs the action as checked out in the job's workspace, and a `$/` path runs it at the
// workflow's own commit; `gh actions-lock --migrate-local-actions` rewrites the first into the
// second.
func localAction(ref string) string {
	rest, ok := strings.CutPrefix(ref, "./")
	if !ok {
		rest, ok = strings.CutPrefix(ref, "$/")
	}
	if !ok {
		return ""
	}
	clean := path.Clean(rest)
	if !insideCheckout(clean) || clean == "." {
		return ""
	}
	return clean
}

// notAVersion reports whether a `uses:` reference names no version at all: a path to an action in
// the same repository, `./…` or `$/…`. A Docker image, `docker://alpine:3.20`, carries its tag
// without an `@` and is not among them, nor is any other reference without one, which keeps its
// finding.
func notAVersion(ref string) bool {
	return localAction(ref) != ""
}

// dropLocalActions removes each GitHub Actions mutable-tag result on a `uses:` reference with no
// version in it, a path to an action in the same repository such as `./.github/actions/setup` or
// `$/.github/actions/setup`, and returns the rest.
//
// The rule asks for a reference to another repository's action to name a commit rather than a tag
// or branch its owner can move. A local path names neither, so a result on one is the rule reading
// a reference it was not written for, not a finding somebody could fix or accept: marking it
// suppressed would record an acceptance of something that was never a finding. The steps of the
// local action are read where the action is written, and each is reported there.
//
// A result whose line cannot be read is kept, so a file Draugr cannot see stays reported.
func dropLocalActions(dir string, results []sarif.Result) []sarif.Result {
	if dir == "" {
		return results
	}
	lines := map[string][]string{}
	kept := results[:0]
	for _, r := range results {
		uri := repoRelPath(dir, r.Location.URI)
		if mutableTagRule(r.RuleID) && insideCheckout(uri) &&
			notAVersion(usesAt(dir, uri, r.Location.StartLine, lines)) {
			continue
		}
		kept = append(kept, r)
	}
	return kept
}

// markActions records on each GitHub Actions mutable-tag finding the `uses:` reference it is on
// (sarif.Result.Uses), and marks one the repository's actions lockfile pins, so the report names it
// as pinned and lists it after the references nothing pins. It still counts at its priority.
//
// A reference in a workflow is pinned where the lockfile lists it for that workflow with a commit.
// A reference in an action in the same repository, a composite action such as
// `.github/actions/setup/action.yml`, runs as part of each workflow that calls it, `uses:
// ./.github/actions/setup` or `uses: $/.github/actions/setup`, and GitHub resolves its steps against
// the lockfile's entries for that calling workflow. It is pinned where every workflow that calls the
// action lists the reference with a commit: a workflow the lockfile does not cover runs the tag as
// it stands.
//
// The match is exact: the workflow file, and the reference as written. A reference the lockfile does
// not list, an action no workflow calls, one called only from another action, and a reusable
// workflow's call, which the lockfile does not pin, are not marked; each still has its reference
// recorded.
func markActions(dir string, results []sarif.Result) {
	if dir == "" {
		return
	}
	var lock *actionsLock
	var callers map[string][]string
	lines := map[string][]string{}
	for i := range results {
		r := &results[i]
		uri := repoRelPath(dir, r.Location.URI)
		if !mutableTagRule(r.RuleID) || !insideCheckout(uri) {
			continue
		}
		ref := usesAt(dir, uri, r.Location.StartLine, lines)
		if ref == "" {
			continue
		}
		r.Uses = ref
		var workflows []string
		switch {
		case strings.HasPrefix(uri, workflowsDir+"/"):
			workflows = []string{uri}
		case actionFile(uri):
			if callers == nil {
				callers = localActionCallers(dir, lines)
			}
			workflows = callers[path.Dir(path.Clean(uri))]
		}
		if len(workflows) == 0 {
			continue
		}
		if lock == nil {
			lock = readActionsLock(filepath.Join(dir, filepath.FromSlash(actionsLockPath)))
		}
		if lock.pinsIn(ref, workflows) {
			r.Aside = sarif.AsidePinned
		}
	}
}

// pinsIn reports whether the lockfile lists ref with a commit for every workflow in workflows.
func (l *actionsLock) pinsIn(ref string, workflows []string) bool {
	if l.Dependencies[ref].Commit == "" {
		return false
	}
	for _, w := range workflows {
		listed := false
		for _, got := range l.Workflows[w] {
			if got == ref {
				listed = true
				break
			}
		}
		if !listed {
			return false
		}
	}
	return true
}

// actionFile reports whether uri is an action's metadata file, `action.yml` or `action.yaml`.
func actionFile(uri string) bool {
	base := path.Base(uri)
	return base == "action.yml" || base == "action.yaml"
}

// localActionCallers maps the directory of each action in the same repository that a workflow calls
// to the workflows that call it, read from every `uses:` line of the workflows in workflowsDir.
func localActionCallers(dir string, lines map[string][]string) map[string][]string {
	out := map[string][]string{}
	entries, err := os.ReadDir(filepath.Join(dir, filepath.FromSlash(workflowsDir)))
	if err != nil {
		return out
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || (!strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml")) {
			continue
		}
		uri := workflowsDir + "/" + name
		seen := map[string]bool{}
		for _, line := range linesOf(dir, uri, lines) {
			m := usesLine.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			if action := localAction(m[1]); action != "" && !seen[action] {
				seen[action] = true
				out[action] = append(out[action], uri)
			}
		}
	}
	return out
}

// readActionsLock reads the actions lockfile at p, or an empty one where there is none or it does
// not parse: a reference the lockfile cannot be read for is not pinned.
func readActionsLock(p string) *actionsLock {
	lock := &actionsLock{}
	raw, err := os.ReadFile(p) // #nosec G304 -- the lockfile at its fixed path inside the checkout
	if err != nil {
		return lock
	}
	if yaml.Unmarshal(raw, lock) != nil {
		return &actionsLock{}
	}
	return lock
}
