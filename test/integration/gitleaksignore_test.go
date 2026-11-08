//go:build integration

package integration

import (
	"context"
	"os/exec"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/scanners"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// A `.gitleaksignore` entry is a fingerprint as Gitleaks prints it run from the repository root:
// `<path>:<rule>:<line>` for the tree and `<commit>:<path>:<rule>:<line>` for history. An entry
// recorded that way sets its finding aside in Draugr's scan, and leaves the same secret in another
// file reported.
func TestAGitleaksignoreEntrySetsItsFindingAside(t *testing.T) {
	requireTool(t, "gitleaks", "the ignore file is what Gitleaks reads")
	requireTool(t, "git", "the scan checks the repository out before scanning it")
	t.Setenv("HOME", t.TempDir())

	t.Run("tree", func(t *testing.T) {
		repo := newRepo(t, map[string]string{
			"id_rsa":          fakePrivateKey,
			"backup.pem":      fakePrivateKey,
			".gitleaksignore": "id_rsa:private-key:1\n",
		})
		report, err := scanners.NewGitleaks().Scan(context.Background(), plugin.RepositoryTarget{URL: repo}, plugin.Config{})
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.Join(ruleAndPath(report), "\n"); got != "private-key backup.pem" {
			t.Errorf("found\n%s\nwant only private-key backup.pem", got)
		}
		if got := setAsideBy(report, sarif.OriginScanner); got != "private-key id_rsa" {
			t.Errorf("set aside by the scanner's own file\n%s\nwant private-key id_rsa", got)
		}
	})

	t.Run("history", func(t *testing.T) {
		repo := newRepo(t, map[string]string{
			"id_rsa":     fakePrivateKey,
			"backup.pem": fakePrivateKey,
		})
		// #nosec G204 -- a fixed binary and literal arguments; repo is this test's own temporary directory.
		sha, err := exec.Command("git", "-C", repo, "rev-parse", "HEAD").Output()
		if err != nil {
			t.Fatal(err)
		}
		// Both keys leave the tree, so only the history pass can find them, and the entry names
		// the commit they arrived in.
		gitIn(t, repo, "rm", "--quiet", "id_rsa", "backup.pem")
		commitFile(t, repo, ".gitleaksignore", strings.TrimSpace(string(sha))+":id_rsa:private-key:1\n")
		report, err := scanners.NewGitleaks().Scan(context.Background(), plugin.RepositoryTarget{URL: repo},
			plugin.Config{"history": true})
		if err != nil {
			t.Fatal(err)
		}
		var history []string
		for _, r := range report.Results {
			if r.Historical && !r.Suppressed() {
				history = append(history, r.RuleID+" "+r.Location.URI)
			}
		}
		if got := strings.Join(history, "\n"); got != "private-key backup.pem" {
			t.Errorf("history found\n%s\nwant only private-key backup.pem", got)
		}
		if got := setAsideBy(report, sarif.OriginScanner); got != "private-key id_rsa" {
			t.Errorf("set aside by the scanner's own file\n%s\nwant private-key id_rsa", got)
		}
	})
}

// setAsideBy lists, as "rule path" lines, the results a report holds suppressed with origin.
func setAsideBy(report sarif.Report, origin string) string {
	var out []string
	for _, r := range report.Results {
		if r.Suppression != nil && r.Suppression.Origin == origin {
			out = append(out, r.RuleID+" "+r.Location.URI)
		}
	}
	return strings.Join(out, "\n")
}

// commitFile writes one file into repo and commits it, with whatever else is staged.
func commitFile(t *testing.T, repo, name, body string) {
	t.Helper()
	writeFile(t, repo, name, body)
	gitIn(t, repo, "add", name)
	gitIn(t, repo, "commit", "--quiet", "-m", "add "+name)
}

// gitIn runs git in repo and fails the test on an error.
func gitIn(t *testing.T, repo string, args ...string) {
	t.Helper()
	// #nosec G204 -- a fixed binary; the arguments are this file's literals.
	c := exec.Command("git", args...)
	c.Dir = repo
	if out, err := c.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}
