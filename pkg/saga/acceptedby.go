package saga

import (
	"fmt"
	"path/filepath"
)

// AcceptedByRemovedIn is the release that removes config.exclude[].acceptedBy. Until then the key
// is accepted and warned about, and a report carries its value only as the descriptor's unverified
// claim.
//
// The key holds whatever name the descriptor's author typed and nothing checks it. The record of
// who wrote an exclusion is the repository's history of the line, which the report carries.
const AcceptedByRemovedIn = "0.163.0"

// AcceptedByWarnings names every exclusion that still sets acceptedBy, by the file and line the key
// is written at, for `draugr validate` and `draugr scan` to print.
//
// A warning rather than an error until AcceptedByRemovedIn, so a descriptor that has one keeps
// working while its owner deletes the line.
func AcceptedByWarnings(rules []ExcludeRule) []string {
	var out []string
	for _, r := range rules {
		if r.AcceptedBy == "" {
			continue
		}
		line := r.acceptedByLine
		if line == 0 {
			line = r.Line
		}
		where := r.Source
		switch {
		case where == "":
			where = "config.exclude"
		case line > 0:
			where = fmt.Sprintf("%s:%d", r.Source, line)
		}
		next := "Delete the line; the exclusion's git history records who wrote it"
		// A fragment fetched from another repository is read from a checkout that is gone by the
		// time anybody reads this, so a command to run against it would point at nothing.
		if r.File != "" && r.Line > 0 && filepath.ToSlash(r.File) == r.Source {
			next = fmt.Sprintf("Delete the line. Who wrote the exclusion: git blame -L %d,%d %s",
				r.Line, r.Line, r.Source)
		}
		out = append(out, fmt.Sprintf("%s: acceptedBy is deprecated and %s removes it. %s",
			where, AcceptedByRemovedIn, next))
	}
	return out
}
