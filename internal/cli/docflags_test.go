package cli

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// A flag named in the documentation and absent from the binary is advice that fails when somebody
// follows it, and nothing here noticed. `--fail-on-new-priority` survived in four documents after
// it was deprecated, taught as the way to do the thing it is no longer the way to do.
//
// Two checks, because they fail differently. A flag that does not exist is wrong for every reader.
// A flag marked deprecated is still correct and still works, and a document teaching it sends
// people to the older spelling forever, so those are listed, and the list has to say where each
// one is allowed to appear and why.

// docFlag matches a long flag as documentation writes one.
//
// The leading boundary is the whole difficulty. Markdown writes an anchor as
// `#6-execution--the-cheap-at-scale-pillar`, and a heading link to `#draugr-classify-sagayaml--directory`
// is a fragment rather than a flag. Both contain a run of two hyphens inside a word, so a pattern
// that only looks for `--` reports a table of contents as a broken flag reference.
//
// So: preceded by whitespace, a backtick or an opening bracket, which is how a flag is written
// everywhere a reader is meant to type it, and never by a word character, which is how an anchor
// is written everywhere else.
var docFlag = regexp.MustCompile("(?:^|[\\s`(\\[])(--[a-z][a-z0-9]*(?:-[a-z0-9]+)*)")

// notOurs are flags belonging to something else that our documentation quotes.
//
// A reason each, not a list of names: "it is somebody else's" and "we have not got round to it"
// look identical otherwise, and only one of them should survive review.
// #nosec G101 -- flag names and whose tool each belongs to. One of them ends in "token" because
// that is what the flag is called; no value from a credential is in this file.
var notOurs = map[string]string{
	// Trivy's, quoted where a scanner's own behavior, caching or air-gapped setup is explained.
	"--exit-code":        "Trivy's",
	"--severity":         "Trivy's",
	"--scanners":         "Trivy's",
	"--quiet":            "Trivy's, in a logged argv",
	"--vex":              "Trivy's, shown consuming the document Draugr writes",
	"--download-db-only": "Trivy's, for the air-gapped guide",
	"--skip-db-update":   "Trivy's, for the air-gapped guide",
	"--ignorefile":       "Trivy's",
	"--no-cache":         "Trivy's",
	"--token":            "Trivy server's, named in a comment about its environment variable",
	"--config":           "a scanner's own, several of them",
	"--exitwith":         "a scanner's own exit-code flag, in the extending guide",

	// Verification, where the reader runs these against our released artifacts.
	"--certificate-identity-regexp": "cosign's",
	"--certificate-oidc-issuer":     "cosign's",
	"--ignore-missing":              "sha256sum's",
	"--bundle":                      "cosign's",
	"--repo":                        "gh release download's, in the install guide",

	// Tooling a guide tells somebody to run.
	"--exclude-standard": "git ls-files'",
	"--no-tags":          "git clone's",
	"--detach":           "git checkout's",
	"--depth":            "git clone's",
	"--ignore-scripts":   "npm's",
	"--require-hashes":   "pip's",
	"--cache":            "npm's",

	// Ours and gone. Named only where the removal is explained, which is the one place naming
	// them helps: somebody arriving from a descriptor that used them needs to find out what
	// replaced them.
	"--k8s-images":    "removed; the surveyor took over, and the reference says so",
	"--k8s-namespace": "removed, with it",
	"--github-org":    "removed, with it",

	// Not a flag. Prose uses it as a placeholder for whichever flag overrides a setting.
	"--flag": "a placeholder in a sentence about flags overriding settings",
}

// deprecatedFlags are ours, still work, and must not be taught as the way to do the thing.
//
// `where` names the documents allowed to mention one, which is where a migration is explained. A
// document not listed that names one is teaching the older spelling.
var deprecatedFlags = map[string]struct {
	why   string
	where []string
}{
	"--fail-on-priority": {
		why:   "the band goes in --fail-on, which takes either vocabulary",
		where: []string{"docs/reference/cli.md", "docs/guides/github-action.md"},
	},
	"--fail-on-new-priority": {
		why:   "the band goes in --fail-on-new, which takes either vocabulary",
		where: []string{"docs/reference/cli.md", "docs/guides/github-action.md"},
	},
}

// ourFlags is every long flag the binary defines, across every command.
func ourFlags(t *testing.T) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	var walk func(*cobra.Command)
	walk = func(c *cobra.Command) {
		c.Flags().VisitAll(func(f *pflag.Flag) { out["--"+f.Name] = true })
		c.PersistentFlags().VisitAll(func(f *pflag.Flag) { out["--"+f.Name] = true })
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(newRootCommand())
	// Cobra adds --help lazily, so a command that has never been executed does not list it and
	// every document naming it would be reported as naming something that does not exist.
	out["--help"] = true
	return out
}

// docFiles are the documents a reader is handed, with their paths, so a failure names the file.
func docFiles(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	// os.Root rather than filepath.Walk, so the read is scoped to the directory being walked and
	// a symlink cannot point the reader at something outside it. The check that asked for this is
	// about a window between deciding a path is safe and opening it; the root closes the window
	// instead of arguing that nothing is in it.
	root, err := os.OpenRoot("../../docs")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()

	err = fs.WalkDir(root.FS(), ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".md") {
			return err
		}
		body, err := fs.ReadFile(root.FS(), path)
		if err != nil {
			return err
		}
		out["docs/"+filepath.ToSlash(path)] = string(body)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) == 0 {
		t.Fatal("no documents found, so this guard has been checking nothing")
	}
	return out
}

func TestDocsNameFlagsThatExist(t *testing.T) {
	t.Parallel()

	have := ourFlags(t)
	var missing []string
	for path, body := range docFiles(t) {
		for _, m := range docFlag.FindAllStringSubmatch(body, -1) {
			flag := m[1]
			if have[flag] || notOurs[flag] != "" {
				continue
			}
			missing = append(missing, path+": "+flag)
		}
	}
	sort.Strings(missing)
	missing = slicesCompact(missing)
	for _, m := range missing {
		t.Errorf("%s names a flag this binary does not have.\n"+
			"    Fix the document, or, if it belongs to a tool we quote, add it to notOurs "+
			"with whose it is.", m)
	}
}

func TestDocsDoNotTeachADeprecatedFlag(t *testing.T) {
	t.Parallel()

	for path, body := range docFiles(t) {
		for flag, d := range deprecatedFlags {
			if !strings.Contains(body, flag) {
				continue
			}
			if slicesContains(d.where, path) {
				continue
			}
			t.Errorf("%s names %s, which is deprecated: %s.\n"+
				"    A document is what somebody copies, so it teaches the current spelling. "+
				"Add the file to deprecatedFlags[%q].where only if it is explaining the migration.",
				path, flag, d.why, flag)
		}
	}
}

// TestTheFlagExemptionsAreStillNeeded keeps both lists from becoming places to park a name.
//
// An entry for a flag nothing mentions is an excuse nobody is using, and a list of those is how the
// next person comes to believe the rule is advisory. A deprecated flag that has actually been
// removed is worse: its `where` would keep a document exempt from a check it now passes.
func TestTheFlagExemptionsAreStillNeeded(t *testing.T) {
	t.Parallel()

	var corpus strings.Builder
	for _, body := range docFiles(t) {
		corpus.WriteString(body)
	}
	all := corpus.String()
	for flag, why := range notOurs {
		if !strings.Contains(all, flag) {
			t.Errorf("notOurs has %q (%s) and no document mentions it. Drop the entry.", flag, why)
		}
	}
	have := ourFlags(t)
	for flag, d := range deprecatedFlags {
		if !have[flag] {
			t.Errorf("deprecatedFlags has %q (%s) and the binary no longer defines it. "+
				"Drop the entry, and the documents explaining the migration with it.", flag, d.why)
		}
	}
}

func slicesContains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

func slicesCompact(in []string) []string {
	out := in[:0]
	var last string
	for i, s := range in {
		if i == 0 || s != last {
			out = append(out, s)
		}
		last = s
	}
	return out
}
