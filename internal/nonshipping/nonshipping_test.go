package nonshipping

import (
	"os"
	"slices"
	"strings"
	"testing"
)

// TestKindOfMatchesWholeDirectorySegments holds the matcher to whole directory names at any depth,
// and to nothing that only contains one.
func TestKindOfMatchesWholeDirectorySegments(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"docs/examples/values.yaml":           Docs,
		"doc/guide.md":                        Docs,
		"examples/app.js":                     Example,
		"example/main.go":                     Example,
		"test/go.mod":                         Test,
		"tests/fixture.tf":                    Test,
		"internal/foo/testdata/x.go":          Test,
		"src/__tests__/app.test.js":           Test,
		"spec/models/user_spec.rb":            Test,
		"pkg/fixtures/Dockerfile":             Test,
		"./tests/a.yaml":                      Test,
		"charts/app/docs/examples/deploy.yml": Docs,

		// Near misses: the name inside a longer segment, or as the file itself.
		"contest/main.go":       "",
		"docsite/index.js":      "",
		"latest/Dockerfile":     "",
		"testing/helpers.go":    "",
		"pkg/test":              "",
		"spec":                  "",
		"src/specs/a.js":        "",
		"Docs/readme.md":        "",
		"app/requirements.txt":  "",
		"":                      "",
		"/abs/tests/x.go":       "",
		"../tests/x.go":         "",
		"file:///repo/tests/x":  "",
		"https://example.test/": "",
	}
	for rel, want := range cases {
		if got := KindOf(rel); got != want {
			t.Errorf("KindOf(%q) = %q, want %q", rel, got, want)
		}
	}
}

// TestKindOfNamesTheOutermostDirectory gives a path under two listed directories the kind of the
// one nearer the root, so one finding has one label.
func TestKindOfNamesTheOutermostDirectory(t *testing.T) {
	t.Parallel()
	if got := KindOf("examples/app/tests/a.js"); got != Example {
		t.Errorf("KindOf = %q, want %q", got, Example)
	}
}

// TestTheReferenceListsEveryName holds the Saga reference's table to the list, so a name added here
// is a name a reader can find, under the label it wears.
func TestTheReferenceListsEveryName(t *testing.T) {
	t.Parallel()
	body, err := os.ReadFile("../../docs/reference/saga-schema.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(body)
	start := strings.Index(doc, "### Non-shipping paths")
	if start < 0 {
		t.Fatal("docs/reference/saga-schema.md has no Non-shipping paths section")
	}
	section := doc[start:]
	if end := strings.Index(section[1:], "\n### "); end > 0 {
		section = section[:end+1]
	}
	for _, n := range Names() {
		row := ""
		for _, line := range strings.Split(section, "\n") {
			if strings.HasPrefix(line, "| ") && strings.Contains(line, "`"+n+"`") {
				row = line
				break
			}
		}
		if !strings.HasSuffix(row, "| `"+DirKind(n)+"` |") {
			t.Errorf("the reference's table has no row giving %s the label %s: %q", n, DirKind(n), row)
		}
	}
}

// TestNamesAndDirKindAgree holds Names to the same list DirKind reads.
func TestNamesAndDirKindAgree(t *testing.T) {
	t.Parallel()
	names := Names()
	if !slices.IsSorted(names) {
		t.Errorf("Names() = %v, not sorted", names)
	}
	for _, n := range names {
		if DirKind(n) == "" {
			t.Errorf("DirKind(%q) is empty for a listed name", n)
		}
	}
	if DirKind("demo") != "" || DirKind("samples") != "" {
		t.Error("a name off the list has a kind")
	}
	if len(names) != len(dirs) {
		t.Errorf("Names() has %d entries, the list %d", len(names), len(dirs))
	}
}
