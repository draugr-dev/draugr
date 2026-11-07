// Package nonshipping names the directories a repository keeps beside its code without shipping
// them: documentation, examples and tests.
//
// One list, read by the scan that marks a finding under one of them and by `draugr init`, which
// proposes an ignore line for each. Two copies would disagree the first time somebody added a name
// to one.
//
// The list is short on purpose. A name is on it only where projects across ecosystems use it for
// nothing else: `testdata` is Go's convention, `__tests__` Jest's, `spec` RSpec's, `fixtures` every
// test runner's. Names that also hold shipped code somewhere, such as `demo`, `sample`, `testing`
// or `e2e`, are left off, because a finding in shipped code wearing a test label is worse than a
// finding in test code wearing none.
package nonshipping

import (
	"maps"
	"path"
	"slices"
	"strings"
)

// The kinds a directory is marked as, which is also the label a finding under one wears.
const (
	// Docs is a directory of documentation.
	Docs = "docs"
	// Example is a directory of examples and samples.
	Example = "example"
	// Test is a directory of tests, test data or fixtures.
	Test = "test"
)

// dirs maps each directory name to its kind. Matched exactly, case and all: `Docs/` and `Test/` are
// rare, and where they occur they are as often a product's own package as a convention.
var dirs = map[string]string{
	"docs":      Docs,
	"doc":       Docs,
	"examples":  Example,
	"example":   Example,
	"test":      Test,
	"tests":     Test,
	"testdata":  Test,
	"__tests__": Test,
	"spec":      Test,
	"fixtures":  Test,
}

// Names are the directory names on the list, sorted.
func Names() []string { return slices.Sorted(maps.Keys(dirs)) }

// DirKind is the kind of a directory by its name alone, or "" for a directory not on the list.
func DirKind(name string) string { return dirs[name] }

// KindOf is the kind of the outermost listed directory holding the file at rel, a slash-separated
// path relative to the repository's root, or "" where none holds it.
//
// Directories only. A file named `test` or `spec` is a file, and its own name says nothing about
// whether it ships. Each directory is a whole segment, so `contest/` and `docsite/` are not matched.
// A path that is absolute, climbs out of the root, or carries a scheme is not one this package can
// place, and is not marked.
func KindOf(rel string) string {
	if rel == "" || strings.Contains(rel, "://") || strings.HasPrefix(rel, "/") {
		return ""
	}
	rel = path.Clean(rel)
	if rel == ".." || strings.HasPrefix(rel, "../") {
		return ""
	}
	segs := strings.Split(rel, "/")
	for _, seg := range segs[:len(segs)-1] {
		if k := dirs[seg]; k != "" {
			return k
		}
	}
	return ""
}
