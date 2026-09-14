package saga

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ExcludeWarnings reports exclusion paths that are legal, match nothing, and were almost certainly
// meant to name a directory. root is the directory the descriptor sits in; patterns are tested
// against it, and a tree that is not there produces nothing.
//
// Warnings rather than errors. A pattern that matches nothing is legal and sometimes deliberate,
// written ahead of the file it covers, and refusing it would break a descriptor that is right about
// the future. What is not acceptable is saying nothing: the scan's own report names a dead rule as
// a footnote under a count, read after a scan somebody was running for another reason, and
// `draugr validate` is where a descriptor is checked and costs nothing to run.
//
// The trap is that `config.exclude[].paths` matches inside one path segment unless the pattern ends
// in `/`, so `tests` and `tests*` both match the directory entry itself and nothing under it. On a
// real descriptor that was seventeen findings a team believed were excused and the gate was judging.
func (m *Model) ExcludeWarnings(root string) []string {
	var out []string
	for i, e := range m.Config.Exclude {
		for j, p := range e.Paths {
			if want, ok := meantTheDirectory(root, p); ok {
				out = append(out, fmt.Sprintf(
					"config.exclude[%d].paths[%d] %q matches inside one path segment, so it will "+
						"not match anything under %s. Write %q to exclude the directory and "+
						"everything beneath it", i, j, p, want, want))
			}
		}
	}
	return out
}

// meantTheDirectory reports whether a pattern names a directory that exists and does not select
// what is in it, and returns the spelling that would.
//
// Four things have to hold, and each one removes a way of being wrong about somebody else's
// descriptor:
//
//   - It is not already the directory form, which matches everything beneath at any depth.
//   - Any wildcard is attached to the last segment's own name. `tests/*.go` is a deliberate and
//     correct pattern for the Go files directly in a directory, and warning on it would teach
//     people to stop reading these.
//   - The literal part names something that is a directory on disk. A pattern is only a mistake
//     against a tree; `LICENSE*` is not one.
//   - The tree is there at all. A descriptor whose repositories are remote is checked against
//     whatever sits beside it, which is usually nothing, and silence is the right answer then.
func meantTheDirectory(root, pattern string) (string, bool) {
	p := strings.TrimSpace(pattern)
	if p == "" || root == "" || strings.HasSuffix(p, "/") || strings.Contains(p, "**") {
		return "", false
	}
	literal := p
	if i := strings.IndexAny(p, "*?["); i >= 0 {
		literal = p[:i]
	}
	// A wildcard straight after a separator selects what is inside a directory, which is what the
	// author asked for.
	if literal == "" || strings.HasSuffix(literal, "/") {
		return "", false
	}
	// Wildcards belong to the last segment. `src/*/tests` names a level this rule cannot advise on.
	if i := strings.IndexAny(p, "*?["); i >= 0 && strings.Contains(p[i:], "/") {
		return "", false
	}
	info, err := os.Stat(filepath.Join(root, filepath.FromSlash(literal)))
	if err != nil || !info.IsDir() {
		return "", false
	}
	return literal + "/", true
}
