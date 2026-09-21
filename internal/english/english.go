// Package english forms the words a count is attached to.
//
// One implementation, because the alternative is each renderer carrying its own and the ones
// nobody is looking at drifting. `1 finding(s)` is what that drift produces: a form nobody would
// write by hand, which survives review because a count is never read aloud and the digit is right.
//
// Not in pkg/tui, which paints terminals, and not exported from pkg/report, which would make the
// markdown renderer and a gate's error message depend on the report package to say "one finding".
package english

import "fmt"

// Count renders a number and its noun together: "1 finding", "3 findings".
func Count(n int, word string) string {
	return fmt.Sprintf("%d %s", n, Noun(n, word))
}

// Noun is `word` in the form a count of n takes.
//
// Regular nouns and the -y ending, which is as far as this goes. Every word it is asked about is
// one Draugr chose (finding, image, repository, component, target), so an irregular plural would
// be a word we decided to use rather than one that arrived from outside, and the fix for it is to
// choose a different word.
func Noun(n int, word string) string {
	if n == 1 {
		return word
	}
	if len(word) > 1 && word[len(word)-1] == 'y' && !isVowel(word[len(word)-2]) {
		return word[:len(word)-1] + "ies"
	}
	return word + "s"
}

func isVowel(b byte) bool {
	switch b {
	case 'a', 'e', 'i', 'o', 'u':
		return true
	}
	return false
}
