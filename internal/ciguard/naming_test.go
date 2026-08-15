package ciguard

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// codeOnlyNames are the Norse names docs/contributing/naming.md reserves for the code.
//
// The rule it states, and the reason: "a reader shouldn't have to learn a Norse name to describe
// Draugr to a colleague". Published pages say the gate, the verdict, the report.
var codeOnlyNames = map[string]string{
	"Norn":  `the gate" or "the verdict`,
	"Skald": `the report" or "reporting`,
}

// userFacingDocs are the trees a user reads. docs/contributing/ is deliberately absent: naming.md
// names these on purpose, and the architecture pages are written for people reading the source.
var userFacingDocs = []string{
	"../../docs/reference",
	"../../docs/guides",
	"../../docs/getting-started",
	"../../docs/concepts",
}

// TestNorseNamesStayInTheCode keeps code vocabulary out of the pages people read.
//
// This is not style policing. `docs/reference/` is published to the website verbatim, so a name
// that leaks here reaches a reader who has no way to look it up — and from there into anything
// written against the docs, which is exactly the path one took to a blog post.
//
// The failure is quiet: the sentence reads fluently to anyone who already knows what the word
// means, which is everyone who would review it.
func TestNorseNamesStayInTheCode(t *testing.T) {
	t.Parallel()

	for name, instead := range codeOnlyNames {
		// Word boundaries: "Skald" must not match a package path like pkg/skald in a code sample,
		// which is a legitimate thing for a reference page to show.
		pattern := regexp.MustCompile(`\b` + name + `\b`)
		for _, dir := range userFacingDocs {
			err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
				if err != nil || d.IsDir() || !strings.HasSuffix(path, ".md") {
					return err
				}
				body, err := os.ReadFile(path) // #nosec G304,G122 -- a repository path this walk produced
				if err != nil {
					return err
				}
				for i, line := range strings.Split(string(body), "\n") {
					if pattern.MatchString(line) {
						t.Errorf("%s:%d uses %q, which docs/contributing/naming.md reserves for the "+
							"code. Published pages say \"%s\":\n    %s",
							path, i+1, name, instead, strings.TrimSpace(line))
					}
				}
				return nil
			})
			if err != nil {
				t.Fatalf("walk %s: %v", dir, err)
			}
		}
	}
}
