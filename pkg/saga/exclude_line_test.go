package saga

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeFiles makes a tree holding the named files.
func writeFiles(t *testing.T, files ...string) string {
	t.Helper()
	root := t.TempDir()
	for _, f := range files {
		full := filepath.Join(root, filepath.FromSlash(f))
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func lineErrors(roots []string, rules []string, paths ...string) []error {
	m := &Model{Config: Config{Exclude: []ExcludeRule{{Reason: "r", Rules: rules, Paths: paths}}}}
	return m.ExcludeLineErrors(roots)
}

// A location as a finding prints it, `path:line`, matches nothing, because paths match files. The
// refusal names the entry, the spelling that works and what that spelling covers, in the entry's
// own rules.
func TestAnExclusionPathWithALineIsRefusedWithTheFileToWrite(t *testing.T) {
	root := writeFiles(t, "deploy/x/rbac.yaml")
	errs := lineErrors([]string{root}, []string{"KSV-0041"}, "deploy/x/rbac.yaml:18")
	if len(errs) != 1 {
		t.Fatalf("errors = %v, want one", errs)
	}
	const want = `config.exclude[0]: paths[0] "deploy/x/rbac.yaml:18" names a line, and paths match whole files. ` +
		`Write "deploy/x/rbac.yaml", which sets aside every KSV-0041 finding in the file, not only line 18`
	if got := errs[0].Error(); got != want {
		t.Errorf("message:\n got %s\nwant %s", got, want)
	}
	// The part after the entry's own address is what a reader acts on, and a reader that cuts an
	// error at its first ": " to fit a line keeps the whole of it.
	if _, reason, _ := strings.Cut(errs[0].Error(), ": "); strings.Contains(reason, ": ") {
		t.Errorf("the reason holds \": \", which a line cut there would drop: %q", reason)
	}
}

// What the entry without the line covers is said in the entry's terms: each of its rules, or every
// finding where it names none.
func TestTheRefusalSaysWhatTheFileAloneWouldCover(t *testing.T) {
	root := writeFiles(t, "a.yaml")
	for _, tc := range []struct {
		rules []string
		want  string
	}{
		{nil, "sets aside every finding in the file"},
		{[]string{"KSV-0041", "KSV-0046"}, "sets aside every KSV-0041 or KSV-0046 finding in the file"},
		{[]string{"A", "B", "C"}, "sets aside every A, B or C finding in the file"},
	} {
		errs := lineErrors([]string{root}, tc.rules, "a.yaml:3")
		if len(errs) != 1 || !strings.Contains(errs[0].Error(), tc.want) {
			t.Errorf("rules %v: errors = %v, want one saying %q", tc.rules, errs, tc.want)
		}
	}
}

// Every one of these names something real or cannot be judged, and refusing it would refuse a
// descriptor that is right.
func TestAnExclusionPathIsRefusedOnlyWhereTheLineIsCertain(t *testing.T) {
	root := writeFiles(t, "deploy/rbac.yaml", "odd/name:18", "odd/name", "deploy/charts/x.yaml")
	if err := os.MkdirAll(filepath.Join(root, "dir"), 0o750); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ pattern, why string }{
		{"odd/name:18", "a file whose real name ends in :18 is legal on Linux"},
		{"deploy/*.yaml:18", "a glob is the author's to mean"},
		{"deploy/rbac.yaml:1?", "a glob, even one after a colon"},
		{"deploy/charts/", "a directory pattern"},
		{"dir:18", "the part before the line is a directory, not a file"},
		{"missing.yaml:18", "the file is not in the tree, so nothing says what was meant"},
		{"deploy/rbac.yaml:18a", "not a line number"},
		{"deploy/rbac.yaml:", "no line after the colon"},
		{":18", "nothing before the colon"},
		{"deploy/rbac.yaml", "already the file"},
	} {
		if errs := lineErrors([]string{root}, nil, tc.pattern); len(errs) != 0 {
			t.Errorf("%q (%s): errors = %v, want none", tc.pattern, tc.why, errs)
		}
	}
}

// No tree to check against, a descriptor whose repositories are remote or not checked out here,
// refuses nothing: the scan's report names an exclusion that matched nothing.
func TestAnExclusionPathIsNotRefusedWithoutATree(t *testing.T) {
	if errs := lineErrors(nil, []string{"KSV-0041"}, "deploy/rbac.yaml:18"); len(errs) != 0 {
		t.Errorf("errors = %v, want none without a tree", errs)
	}
}

// Exclusions are not scoped to a repository: an entry matches a finding from any of them. So it is
// refused when the file is in one repository and the whole entry is in none, and accepted when the
// whole entry names a file in either.
func TestAnExclusionPathIsCheckedAgainstEveryRepository(t *testing.T) {
	first := writeFiles(t, "app/main.go", "odd/name")
	second := writeFiles(t, "deploy/rbac.yaml", "odd/name:18")
	roots := []string{first, second}

	if errs := lineErrors(roots, nil, "deploy/rbac.yaml:18"); len(errs) != 1 {
		t.Errorf("a file in the second repository: errors = %v, want one", errs)
	}
	if errs := lineErrors(roots, nil, "odd/name:18"); len(errs) != 0 {
		t.Errorf("a file the second repository holds under the whole name: errors = %v, want none", errs)
	}
}

// An entry is numbered within the file it was written in, and that file is named where the
// descriptor's exclusions came from more than one.
func TestTheRefusalNamesTheEntryWhereItWasWritten(t *testing.T) {
	root := writeFiles(t, "a.yaml")
	m := &Model{Config: Config{Exclude: []ExcludeRule{
		{Reason: "r", Rules: []string{"X"}, Source: "draugr.saga.yaml"},
		{Reason: "r", Rules: []string{"Y"}, Source: "team.saga-fragment.yaml"},
		{Reason: "r", Paths: []string{"a.yaml:2"}, Source: "team.saga-fragment.yaml"},
	}}}
	errs := m.ExcludeLineErrors([]string{root})
	if len(errs) != 1 || !strings.HasPrefix(errs[0].Error(), "config.exclude[1] in team.saga-fragment.yaml: paths[0] ") {
		t.Errorf("errors = %v, want one addressed to the fragment's second entry", errs)
	}
	m.Config.Exclude = m.Config.Exclude[2:]
	m.Config.Exclude[0].Source = "draugr.saga.yaml"
	if errs := m.ExcludeLineErrors([]string{root}); len(errs) != 1 || !strings.HasPrefix(errs[0].Error(), "config.exclude[0]: ") {
		t.Errorf("errors = %v, want one addressed as config.exclude[0], the only file", errs)
	}
}
