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

// markPinned marks each GitHub Actions mutable-tag finding on a `uses:` reference that the
// repository's actions lockfile lists for that same workflow with a commit, so the report names it
// as pinned and lists it after the references nothing pins. It still counts at its priority.
//
// The match is exact: the workflow file, and the reference as written. A reference the lockfile
// does not list, one in a composite action under `.github/actions/`, and a reusable workflow's
// call, which the lockfile does not pin, are left as they are.
func markPinned(dir string, results []sarif.Result) {
	if dir == "" {
		return
	}
	var lock *actionsLock
	lines := map[string][]string{}
	for i := range results {
		r := &results[i]
		uri := repoRelPath(dir, r.Location.URI)
		if !strings.HasSuffix(r.RuleID, "github-actions-mutable-action-tag") ||
			!strings.HasPrefix(uri, ".github/workflows/") || !insideCheckout(uri) || r.Location.StartLine < 1 {
			continue
		}
		if lock == nil {
			lock = readActionsLock(filepath.Join(dir, filepath.FromSlash(actionsLockPath)))
		}
		refs := lock.Workflows[uri]
		if len(refs) == 0 {
			continue
		}
		file, ok := lines[uri]
		if !ok {
			file = readLines(filepath.Join(dir, filepath.FromSlash(uri)))
			lines[uri] = file
		}
		if r.Location.StartLine > len(file) {
			continue
		}
		m := usesLine.FindStringSubmatch(file[r.Location.StartLine-1])
		if m == nil {
			continue
		}
		for _, ref := range refs {
			if ref == m[1] && lock.Dependencies[ref].Commit != "" {
				r.Aside = sarif.AsidePinned
				break
			}
		}
	}
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
