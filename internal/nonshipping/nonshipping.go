// Package nonshipping names the directories a repository keeps beside its code without shipping
// them: documentation, examples and tests. It also places Go test files, the one kind of file whose
// name alone a language promises keeps it out of the program.
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
// path relative to the repository's root, or Test for a Go test file, or "" where neither holds.
//
// Directories, and one file name. A Go file whose name ends in `_test.go` is never built into the
// program: the Go toolchain leaves it out by language rule, not by convention, so the name alone
// says it does not ship. No other language's name is read. `test_*.py`, `*.test.js` and `*Spec.rb`
// are conventions nothing in their languages enforces, and a file wearing one can be imported by
// shipped code. A file named `test` or `spec` is a file, and its own name says nothing about whether
// it ships. Each directory is a whole segment, so `contest/` and `docsite/` are not matched. A path
// that is absolute, climbs out of the root, or carries a scheme is not one this package can place,
// and is not marked.
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
	if strings.HasSuffix(segs[len(segs)-1], goTestSuffix) {
		return Test
	}
	return ""
}

// goTestSuffix ends the name of every Go test file, which `go build` never compiles into a program.
const goTestSuffix = "_test.go"

// ToolDependency reports whether the file at rel, a slash-separated path relative to the
// repository's root, is a dependency file of a tool the developers install rather than of the
// application: one under `.config/mise/`, where mise keeps the lockfiles of the tools it installs.
// The tools still run on developers' machines and in CI, so a flaw in one of their dependencies is
// a risk to those, not to the program the repository ships.
//
// A directory mise does not own is not matched. A Go module in a `tools` directory may hold the
// tools a project builds and ships, and only its files can say otherwise, which a path cannot: the
// repository scanners read them while the checkout exists and mark such a module there.
func ToolDependency(rel string) bool {
	if rel == "" || strings.Contains(rel, "://") || strings.HasPrefix(rel, "/") {
		return false
	}
	return strings.HasPrefix(path.Clean(rel), ".config/mise/")
}
