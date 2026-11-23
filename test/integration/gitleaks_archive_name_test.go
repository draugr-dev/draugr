//go:build integration

package integration

import (
	"context"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/scanners"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// A text file whose name holds an archive extension, which Gitleaks's tree pass skips, is searched
// at its own path: a secret in it is found there, and whatever sets a finding aside by its path
// sets this one aside too. A real archive stays unread.
func TestATextFileNamedLikeAnArchiveIsSearchedAtItsPath(t *testing.T) {
	requireTool(t, "gitleaks", "the skip by name is Gitleaks's own")
	requireTool(t, "git", "the scan checks the repository out, and the skipped files are read from a scratch commit")
	t.Setenv("HOME", t.TempDir())

	scan := func(t *testing.T, files map[string]string) sarif.Report {
		t.Helper()
		report, err := scanners.NewGitleaks().Scan(context.Background(), plugin.RepositoryTarget{URL: newRepo(t, files)}, plugin.Config{})
		if err != nil {
			t.Fatal(err)
		}
		return report
	}

	t.Run("found at its path, the real archive unread", func(t *testing.T) {
		report := scan(t, map[string]string{
			"notes.brief.md": fakePrivateKey,
			"bundle.zip":     "PK\x03\x04\x00\x00",
		})
		if got := strings.Join(ruleAndPath(report), "\n"); got != "private-key notes.brief.md" {
			t.Errorf("found\n%s\nwant private-key notes.brief.md", got)
		}
		var unread []string
		for _, in := range report.Inputs {
			if in.Unread != "" {
				unread = append(unread, in.Path)
			}
		}
		if strings.Join(unread, ",") != "bundle.zip" {
			t.Errorf("unread %q, want only bundle.zip", unread)
		}
		for _, r := range report.Results {
			if strings.Contains(r.Message, " at commit ") {
				t.Errorf("the message names the scratch commit: %q", r.Message)
			}
		}
	})

	// The entry is the fingerprint Gitleaks would print for the file in the tree.
	t.Run(".gitleaksignore", func(t *testing.T) {
		report := scan(t, map[string]string{
			"notes.brief.md":  fakePrivateKey,
			".gitleaksignore": "notes.brief.md:private-key:1\n",
		})
		if got := ruleAndPath(report); len(got) != 0 {
			t.Errorf("found %q, want the entry to set it aside", got)
		}
		if got := setAsideBy(report, sarif.OriginScanner); got != "private-key notes.brief.md" {
			t.Errorf("set aside by the scanner's own file\n%s\nwant private-key notes.brief.md", got)
		}
	})

	// A rule's allowlist applies to the path the finding is at, and only to that path.
	t.Run("a rule's path allowlist", func(t *testing.T) {
		ruleset := func(allowed string) string {
			return "[[rules]]\nid = \"test-marker\"\nregex = '''marker_[A-Z]{16}'''\n" +
				"[[rules.allowlists]]\npaths = ['''" + allowed + "''']\n"
		}
		const marker = "value = marker_ABCDEFGHIJKLMNOP\n"
		allowed := scan(t, map[string]string{
			"notes.brief.md": marker,
			".gitleaks.toml": ruleset(`notes\.brief\.md`),
		})
		if got := ruleAndPath(allowed); len(got) != 0 {
			t.Errorf("found %q under a path its rule allows", got)
		}
		elsewhere := scan(t, map[string]string{
			"notes.brief.md": marker,
			".gitleaks.toml": ruleset(`other\.md`),
		})
		if got := strings.Join(ruleAndPath(elsewhere), "\n"); got != "test-marker notes.brief.md" {
			t.Errorf("found\n%s\nwant test-marker notes.brief.md", got)
		}
	})
}
