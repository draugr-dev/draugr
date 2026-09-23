package english

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestCountAgreesWithItsNoun(t *testing.T) {
	for _, c := range []struct {
		n    int
		word string
		want string
	}{
		// The case the package exists for. Every renderer got the plural right and wrote
		// "1 finding(s)" for the singular, because a count is never read aloud and the digit
		// beside it was always correct.
		{1, "finding", "1 finding"},
		{0, "finding", "0 findings"},
		{2, "finding", "2 findings"},
		// A consonant before the y takes -ies. "repositorys" is what a reader notices and a tool
		// does not, and it makes everything around it look less carefully made than it is.
		{1, "repository", "1 repository"},
		{3, "repository", "3 repositories"},
		// A vowel before it does not, which is the half of that rule that gets left out.
		{2, "day", "2 days"},
		{2, "key", "2 keys"},
		// A single letter has no letter before the y to look at.
		{2, "y", "2 ys"},
		{2, "", "2 s"},
		// Negative counts are not expected and must not read as singular, which is what a bare
		// `n == 1` inverted would give.
		{-1, "finding", "-1 findings"},
	} {
		if got := Count(c.n, c.word); got != c.want {
			t.Errorf("Count(%d, %q) = %q, want %q", c.n, c.word, got, c.want)
		}
	}
}

func TestNounIsTheWordWithoutTheNumber(t *testing.T) {
	// The form for sentences that put the count somewhere else, so the two must agree about the
	// word or one line says "images" while the next says "image".
	for _, c := range []struct{ n int }{{1}, {2}, {7}} {
		if want := Count(c.n, "image"); want[len(want)-len(Noun(c.n, "image")):] != Noun(c.n, "image") {
			t.Errorf("Count and Noun disagree at %d: %q against %q", c.n, want, Noun(c.n, "image"))
		}
	}
}

// TestChooseTakesBothForms. Verbs, pronouns and phrases have no rule to derive a plural by, so the
// caller supplies both and this only decides which one a count takes.
func TestChooseTakesBothForms(t *testing.T) {
	for _, c := range []struct {
		n    int
		want string
	}{
		{1, "is"},
		{0, "are"},
		{2, "are"},
		// Not expected, and must not read as singular, which a bare `n != 1` inverted would give.
		{-1, "are"},
	} {
		if got := Choose(c.n, "is", "are"); got != c.want {
			t.Errorf("Choose(%d, is, are) = %q, want %q", c.n, got, c.want)
		}
	}
}

// TestThereIsOneRuleForPlurals holds the repository to this package.
//
// Every renderer that needed a plural used to write its own, and the ones nobody reread drifted:
// "1 finding(s)" in four places, and two copies that never learned "repository" takes "ies". A
// helper added somewhere else is the same drift starting again, so a function whose name says it
// pluralizes has to live here.
func TestThereIsOneRuleForPlurals(t *testing.T) {
	root := filepath.Join("..", "..")
	helper := regexp.MustCompile(`(?m)^func (plural\w*|pluralize\w*|noun|isAre|countOf)\(`)
	// The inline form of the same thing: a verb that appends "s" to whatever noun it is handed,
	// which is right until the noun is "policy".
	inline := regexp.MustCompile(`"[^"\n]*%ss\b`)

	var sources []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "vendor", ".claude":
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ".go") && !strings.Contains(path, filepath.Join("internal", "english")) {
			sources = append(sources, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, path := range sources {
		// #nosec G304 -- a path this test found by walking the repository's own source.
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range helper.FindAllSubmatch(body, -1) {
			t.Errorf("%s declares %s, a second rule for plurals: use english.Count, english.Noun "+
				"or english.Choose", path, m[1])
		}
		if !strings.HasSuffix(path, "_test.go") && inline.Match(body) {
			t.Errorf("%s pluralizes with %%ss: use english.Count, english.Noun or english.Choose", path)
		}
	}
}
