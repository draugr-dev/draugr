//go:build integration

package integration

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/draugr-dev/draugr/internal/scanners"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// repoRuleset is a repository's own .gitleaks.toml: Gitleaks' built-in rules, one rule of its own,
// and an allowlist for one file.
const repoRuleset = `[extend]
useDefault = true

[[rules]]
id = "repo-own-rule"
regex = '''zqxv-[0-9]{6}'''
keywords = ["zqxv-"]

[allowlist]
paths = ['''allowed\.txt$''']
`

// Gitleaks reads a tree's .gitleaks.toml only when it is given no --config, and Draugr always gives
// it one. Two repositories scanned at once, one with its own ruleset and one without, show each
// scanned with what it declares: the first with its rule, its allowlist, the built-in rules it asked
// for and Draugr's, the second with the built-in rules and Draugr's, and neither with the other's.
func TestEachRepositoryIsScannedWithItsOwnGitleaksRuleset(t *testing.T) {
	requireTool(t, "gitleaks", "the ruleset is what Gitleaks reads")
	requireTool(t, "git", "the scan checks each repository out before scanning it")
	t.Setenv("HOME", t.TempDir())

	// Assembled here so this file holds no literal the rule matches. 32 bytes of a hash are as
	// varied as a real token's; one character repeated is the shape a test fixture takes.
	sum := sha256.Sum256([]byte("an ingest token for this test"))
	token := "drgr_ci_" + base64.RawURLEncoding.EncodeToString(sum[:])
	flat := "drgr_ci_" + strings.Repeat("a", 43)

	shared := map[string]string{
		"own-rule.txt": "code = zqxv-482913\n",
		"token.env":    "DRAUGR_API_TOKEN=" + token + "\n",
		"fixture.env":  "DRAUGR_API_TOKEN=" + flat + "\n",
		"id_rsa":       fakePrivateKey,
	}
	withRuleset := map[string]string{
		".gitleaks.toml": repoRuleset,
		"allowed.txt":    "code = zqxv-777777\n",
	}
	for name, body := range shared {
		withRuleset[name] = body
	}

	repos := map[string]string{
		"with":    newRepo(t, withRuleset),
		"without": newRepo(t, shared),
	}
	found := map[string][]string{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for name, repo := range repos {
		wg.Add(1)
		go func() {
			defer wg.Done()
			report, err := scanners.NewGitleaks().Scan(context.Background(), plugin.RepositoryTarget{URL: repo}, plugin.Config{})
			if err != nil {
				t.Errorf("%s: %v", name, err)
				return
			}
			mu.Lock()
			found[name] = ruleAndPath(report)
			mu.Unlock()
		}()
	}
	wg.Wait()

	want := map[string][]string{
		"with": {
			"draugr-ingest-token token.env",
			"private-key id_rsa",
			"repo-own-rule own-rule.txt",
		},
		"without": {
			"draugr-ingest-token token.env",
			"private-key id_rsa",
		},
	}
	for name, w := range want {
		if got := strings.Join(found[name], "\n"); got != strings.Join(w, "\n") {
			t.Errorf("%s a .gitleaks.toml: found\n%s\nwant\n%s", name, got, strings.Join(w, "\n"))
		}
	}
}

// ruleAndPath lists a report's unsuppressed results as "rule path", sorted.
func ruleAndPath(report sarif.Report) []string {
	var out []string
	for _, r := range report.Results {
		if r.Suppressed() {
			continue
		}
		out = append(out, r.RuleID+" "+r.Location.URI)
	}
	sort.Strings(out)
	return out
}
