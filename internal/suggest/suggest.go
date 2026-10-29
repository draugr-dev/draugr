// Package suggest finds the name somebody most likely meant, for a "did you mean" beside an error.
//
// One implementation, shared by the descriptor checks in internal/cli and the configuration file in
// pkg/config, so a misspelled name reads the same wherever it was written.
package suggest

import "strings"

// Nearest returns the known name closest to name, or "" when nothing is close enough.
//
// The suggestion is most of the value: "iaac is not a control" leaves someone scanning a list,
// and "did you mean iac?" ends it. The threshold keeps it honest, a wild guess beside an error is
// worse than no guess, because it sends the reader somewhere wrong.
func Nearest(name string, known map[string]bool) string {
	best, bestDist := "", 0
	for candidate := range known {
		d := Distance(strings.ToLower(name), candidate)
		// At most a third of the name wrong, and never more than three edits: enough for a typo,
		// not enough to match something else entirely.
		limit := min(len(candidate)/3+1, 3)
		if d > limit {
			continue
		}
		if best == "" || d < bestDist || (d == bestDist && candidate < best) {
			best, bestDist = candidate, d
		}
	}
	return best
}

// Distance is the Levenshtein distance between a and b, enough for "did you mean" on short names.
func Distance(a, b string) int {
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(min(cur[j-1]+1, prev[j]+1), prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[len(b)]
}
