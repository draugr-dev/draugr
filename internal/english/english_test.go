package english

import "testing"

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
