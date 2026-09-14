package saga

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A tree with the shapes a pattern can be wrong about, and the ones it can be right about.
func aTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, dir := range []string{"tests/unit", "src/generated", "internal/api/fixtures"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range []string{"LICENSE", "tests/helper.go", "Makefile"} {
		if err := os.WriteFile(filepath.Join(root, file), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func warnFor(t *testing.T, root string, paths ...string) []string {
	t.Helper()
	m := &Model{Config: Config{Exclude: []ExcludeRule{{Reason: "r", Paths: paths}}}}
	return m.ExcludeWarnings(root)
}

// `tests*` reads as "the tests directory" and matches the directory entry and `testsuite.go`,
// never anything inside. The rule is legal, applies to nothing, and is indistinguishable from a
// working one until somebody counts.
func TestExcludeWarnsWherePatternNamesADirectoryAndMissesIt(t *testing.T) {
	root := aTree(t)
	for _, p := range []string{"tests", "tests*", "src/generated", "internal/api/fixtures*"} {
		got := warnFor(t, root, p)
		if len(got) != 1 {
			t.Fatalf("%q: warnings = %v, want one", p, got)
		}
		// The spelling that works, not a description of the semantics. Somebody just told their
		// pattern is wrong wants the one that is right.
		want := strings.TrimSuffix(strings.TrimSuffix(p, "*"), "/") + "/"
		if !strings.Contains(got[0], `Write "`+want+`"`) {
			t.Errorf("%q: %q does not name %q", p, got[0], want)
		}
	}
}

// Every one of these is either correct or unknowable, and warning on any of them teaches a reader
// to stop reading the warnings.
func TestExcludeStaysQuietOnPatternsThatAreNotTheTrap(t *testing.T) {
	root := aTree(t)
	for _, tc := range []struct{ pattern, why string }{
		{"tests/", "already the directory form, which matches at any depth"},
		{"tests/*.go", "a deliberate one-level pattern for what is directly inside"},
		{"src/*/fixtures", "the wildcard is not in the last segment; this rule cannot advise"},
		{"LICENSE", "names a file, not a directory"},
		{"Makefile*", "names a file, not a directory"},
		{"nosuchdir*", "nothing in this tree; a rule written ahead of the file it covers is legal"},
		{"*.md", "no literal part to test"},
		{"tests/**", "refused at validation, and saying it twice helps nobody"},
	} {
		if got := warnFor(t, root, tc.pattern); len(got) != 0 {
			t.Errorf("%q warned %v, want nothing: %s", tc.pattern, got, tc.why)
		}
	}
}

// A descriptor whose repositories are remote is checked against whatever sits beside it, which is
// usually nothing. Silence is the answer then, because a pattern is only a mistake against a tree.
func TestExcludeWarnsNothingWithNoTree(t *testing.T) {
	if got := warnFor(t, t.TempDir(), "tests*"); len(got) != 0 {
		t.Errorf("warnings = %v, want none where the tree has no tests/", got)
	}
	if got := warnFor(t, "", "tests*"); len(got) != 0 {
		t.Errorf("warnings = %v, want none where there is no root at all", got)
	}
}

// The warning names the rule and the entry, because a descriptor with a dozen exclusions is one
// where "a path is wrong" costs a reader the search.
func TestExcludeWarningNamesWhichRuleAndWhichPath(t *testing.T) {
	root := aTree(t)
	m := &Model{Config: Config{Exclude: []ExcludeRule{
		{Reason: "r", Paths: []string{"LICENSE"}},
		{Reason: "r", Paths: []string{"*.md", "tests*"}},
	}}}
	got := m.ExcludeWarnings(root)
	if len(got) != 1 || !strings.HasPrefix(got[0], "config.exclude[1].paths[1] ") {
		t.Errorf("warnings = %v, want the second path of the second rule named", got)
	}
}
