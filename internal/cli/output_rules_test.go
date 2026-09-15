package cli

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The house rules, held against every command's whole output rather than remembered.
//
// Each of these was a real defect found by reading a screen, and each passed every test the command
// had, because those tests asked whether a fragment appeared and never what the screen said. A rule
// that lives in a review is one that has to be rediscovered; a rule that lives here is one a change
// cannot get past.
var outputRules = []struct {
	name string
	// bad matches what must not appear.
	bad *regexp.Regexp
	// why is printed when it does, in the terms somebody would fix it in.
	why string
}{
	{
		"a string points at the screen",
		regexp.MustCompile(`(?i)\b(see (the )?(notes?|table|list) (above|below)|listed (above|below)|` +
			`(above|below) this|the (line|row|section) (above|below))\b`),
		"a reflow is the first thing that moves a position. Name the column, the section or the " +
			"command instead",
	},
	{
		"an em dash",
		regexp.MustCompile(`\x{2014}`),
		"replace it with a comma, a full stop, or the conjunction it stands in for. An absent " +
			"value in a table is a hyphen",
	},
	{
		"a Go slice printed at somebody",
		regexp.MustCompile(`\[[a-z0-9]+(?:[ ][a-z0-9-]+){2,}\]`),
		"`%v` on a string slice prints brackets nobody typed and no separators. Offer the values " +
			"as a sentence",
	},
	{
		"a Go type or test named at a user",
		// `in type config.File` is what yaml says about an unknown setting, and the first cut of
		// this rule missed it: it looked for a name ending in Config and this one begins with it.
		// A package-qualified Go identifier is the shape, whichever half carries the word.
		regexp.MustCompile(`\b(Test[A-Z]\w+|in type \w+\.\w+|\*?\w+\.\w+Config\b|` +
			`go generate|reflect\.)`),
		"the reasoning belongs in the comment beside the code, not on the screen",
	},
}

// Every golden, because the goldens are the screens. A rule proven against one command and not the
// rest is the drift these exist to end.
func TestEveryCommandObeysTheOutputRules(t *testing.T) {
	dir := filepath.Join("testdata", "golden")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("no goldens, so this asserts nothing")
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".golden") {
			continue
		}
		t.Run(e.Name(), func(t *testing.T) {
			body, err := os.ReadFile(filepath.Join(dir, e.Name())) // #nosec G304 -- a test fixture
			if err != nil {
				t.Fatal(err)
			}
			for _, rule := range outputRules {
				for _, line := range strings.Split(string(body), "\n") {
					if m := rule.bad.FindString(line); m != "" {
						t.Errorf("%s: %q\n  %s\n  in: %s", rule.name, m, rule.why, strings.TrimSpace(line))
					}
				}
			}
		})
	}
}
