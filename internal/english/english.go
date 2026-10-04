// Package english forms the words a count is attached to.
//
// One implementation, because the alternative is each renderer carrying its own and the ones
// nobody is looking at drifting. `1 finding(s)` is what that drift produces: a form nobody would
// write by hand, which survives review because a count is never read aloud and the digit is right.
//
// Not in pkg/tui, which paints terminals, and not exported from pkg/report, which would make the
// markdown renderer and a gate's error message depend on the report package to say "one finding".
package english

import (
	"fmt"
	"strconv"
	"strings"
)

// Two shapes, named apart so neither can be called for the other's job. Count and Noun derive the
// plural from the word, which is right for a regular noun. Choose takes both forms, which is what a
// verb, a pronoun or a phrase needs: "is" and "are", "it" and "them", "an effect" and "effects" have
// no rule to derive them by.

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

// Word spells n out from zero through twelve, the numbers prose writes as words, and in digits
// beyond.
func Word(n int) string {
	words := [...]string{"zero", "one", "two", "three", "four", "five", "six", "seven", "eight",
		"nine", "ten", "eleven", "twelve"}
	if n >= 0 && n < len(words) {
		return words[n]
	}
	return strconv.Itoa(n)
}

// Choose picks between two given forms by count: one for exactly one, many for anything else,
// zero and negative included.
func Choose(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func isVowel(b byte) bool {
	switch b {
	case 'a', 'e', 'i', 'o', 'u':
		return true
	}
	return false
}

// And joins names the way a sentence does, so three of them do not read as a chain of ands.
func And(names []string) string {
	switch len(names) {
	case 0:
		return ""
	case 1:
		return names[0]
	}
	return strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
}
