package scaffold

import (
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/draugr-dev/draugr/internal/nonshipping"
)

// ignoreEntry is one line of a proposed ignore: list and the comment beside it.
type ignoreEntry struct{ pattern, comment string }

// kindComment is what an ignore line's comment calls a kind of directory.
var kindComment = map[string]string{
	nonshipping.Docs:    "documentation",
	nonshipping.Example: "examples",
	nonshipping.Test:    "tests",
}

// nonShippingEntries proposes an ignore line for each name among dirs, the directories of docs,
// examples and tests a component holds.
//
// One line per name rather than per directory, so a Go repository with a testdata directory in each
// of forty packages reads one line for all of them. A name found once is written as that directory,
// `docs/`. A name found more than once is written for every depth, `**/testdata`, with where it was
// found in the comment, and also covers one added later. Each line stands alone, so a reader who
// wants one of them scanned deletes that line.
func nonShippingEntries(dirs []string) []ignoreEntry {
	byName := map[string][]string{}
	for _, d := range dirs {
		byName[path.Base(d)] = append(byName[path.Base(d)], d)
	}
	out := make([]ignoreEntry, 0, len(byName))
	for n := range byName {
		found := byName[n]
		kind := kindComment[nonshipping.DirKind(n)]
		if len(found) == 1 {
			out = append(out, ignoreEntry{pattern: found[0] + "/", comment: kind})
			continue
		}
		out = append(out, ignoreEntry{pattern: "**/" + n, comment: kind + " · " + PathList(found)})
	}
	// In the order of the paths, so a reader finds a directory where they would look for it.
	slices.SortFunc(out, func(a, b ignoreEntry) int { return strings.Compare(a.pattern, b.pattern) })
	return out
}

// ownedNonShipping are the directories of docs, examples and tests that belong to the component
// rooted at dir: beneath it, not beneath a part nested inside it, and not a part of their own, which
// the component above already carves out.
func ownedNonShipping(dirs []string, dir string, parts []string) []string {
	var out []string
	for _, d := range dirs {
		if slices.Contains(parts, d) || owner(d, parts) != dir {
			continue
		}
		out = append(out, d)
	}
	return out
}

// writeIgnore writes a repository's ignore: list, carving out the parts in carved, and proposes a
// commented-out line for each directory of docs, examples and tests in ns. Nothing where both are
// empty.
//
// The proposed lines are commented out. An ignored directory is read by no control, secrets
// included, and a credential committed in a test fixture is as live as one committed beside the
// code, so ignoring one is a decision somebody makes by uncommenting it. The scan marks their
// findings and lists them after the shipped code's either way. Carved parts alone keep the
// one-line form init has always written.
func writeIgnore(b *strings.Builder, carved, ns []string) {
	if len(ns) == 0 {
		if len(carved) > 0 {
			fmt.Fprintf(b, "        ignore: [%s]\n", dirList(carved))
		}
		return
	}
	// The key is live only where a carved part gives it an entry; otherwise it is commented too,
	// because an ignore: with no entry is not valid.
	key := "        # ignore:\n"
	if len(carved) > 0 {
		key = "        ignore:\n"
	}
	b.WriteString(key)
	for _, c := range carved {
		fmt.Fprintf(b, "          - %s\n", Scalar(c+"/"))
	}
	b.WriteString("          # Documentation, examples and tests. Their findings are labeled and listed after\n")
	b.WriteString("          # the shipped code's. Uncommenting a line stops every control reading it, secrets too.\n")
	entries := nonShippingEntries(ns)
	width := 0
	for _, e := range entries {
		width = max(width, len(Scalar(e.pattern)))
	}
	for _, e := range entries {
		fmt.Fprintf(b, "          # - %-*s   # %s\n", width, Scalar(e.pattern), e.comment)
	}
}
