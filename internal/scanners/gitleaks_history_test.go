package scanners

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/git"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// leak is one result as Gitleaks writes it in SARIF, with the secret in the region's snippet.
type leak struct {
	rule, uri string
	line      int
	secret    string
}

func gitleaksReport(leaks ...leak) string {
	parts := make([]string, 0, len(leaks))
	for _, l := range leaks {
		snippet := ""
		if l.secret != "" {
			snippet = `,"snippet":{"text":"` + l.secret + `"}`
		}
		parts = append(parts, `{"ruleId":"`+l.rule+`","level":"error","message":{"text":"`+l.rule+
			` detected"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"`+l.uri+
			`"},"region":{"startLine":`+strconv.Itoa(l.line)+snippet+`}}}]}`)
	}
	return `{"runs":[{"tool":{"driver":{"name":"gitleaks"}},"results":[` + strings.Join(parts, ",") + `]}]}`
}

// A secret committed and never removed is found by the tree pass and the history pass. Counting
// both puts two credentials to rotate at the gate where there is one, so the history copy goes and
// the tree copy, at the path the file has now, stays. Two repositories, because each is scanned on
// its own and a secret in one says nothing about the other.
func TestGitleaksReportsASecretStillInTheTreeOnce(t *testing.T) {
	scanner := func(dir string, tree, history string) repoScanner {
		s := NewGitleaks().(repoScanner)
		s.checkout = func(_ context.Context, _, _ string, _ git.Scope) (git.Tree, func(), error) {
			return git.Tree{Dir: dir}, func() {}, nil
		}
		s.cacheVersion = nil
		// Gitleaks writes its report to the path it is given rather than to stdout.
		s.run = func(_ context.Context, _ string, argv []string) ([]byte, error) {
			out := tree
			if argv[1] == "git" {
				out = history
			}
			path := argv[slices.Index(argv, "--report-path")+1]
			return nil, os.WriteFile(path, []byte(out), 0o600)
		}
		return s
	}
	type want struct {
		uri        string
		line       int
		historical bool
	}
	cases := []struct {
		repo    string
		tree    func(dir string) string
		history string
		want    []want
	}{{
		repo: "./api",
		// The tree pass writes absolute paths under the checkout; the history pass writes paths
		// relative to the repository. The two are compared once both are repository-relative.
		tree: func(dir string) string {
			return gitleaksReport(
				leak{"generic-api-key", filepath.Join(dir, "settings.py"), 3, "live-key"},
				leak{"generic-api-key", filepath.Join(dir, "unknown.py"), 1, ""},
			)
		},
		history: gitleaksReport(
			// The same credential, introduced two lines higher than it sits now: one finding.
			leak{"generic-api-key", "settings.py", 1, "live-key"},
			// The value it replaced in place, still readable in history.
			leak{"generic-api-key", "settings.py", 3, "old-key"},
			// The same value at another path is not folded into the tree finding.
			leak{"generic-api-key", "copy/settings.py", 3, "live-key"},
			// A secret neither pass can name is never matched.
			leak{"generic-api-key", "unknown.py", 1, ""},
			leak{"aws-access-token", "old/aws.env", 1, "AKIAIOSFODNN7EXAMPLE"},
		),
		want: []want{
			{"copy/settings.py", 3, true},
			{"old/aws.env", 1, true},
			{"settings.py", 3, false},
			{"settings.py", 3, true},
			{"unknown.py", 1, false},
			{"unknown.py", 1, true},
		},
	}, {
		repo: "./web",
		tree: func(dir string) string {
			return gitleaksReport(leak{"github-pat", filepath.Join(dir, "deploy.sh"), 7, "ghp-web"})
		},
		history: gitleaksReport(
			leak{"github-pat", "deploy.sh", 7, "ghp-web"},
			// Another repository's credential at the same path is not this one's.
			leak{"generic-api-key", "settings.py", 1, "live-key"},
		),
		want: []want{
			{"deploy.sh", 7, false},
			{"settings.py", 1, true},
		},
	}}
	for _, c := range cases {
		dir := t.TempDir()
		s := scanner(dir, c.tree(dir), c.history)
		got, err := s.Scan(context.Background(), plugin.RepositoryTarget{URL: c.repo},
			plugin.Config{"history": true})
		if err != nil {
			t.Fatal(err)
		}
		var have []want
		for _, r := range got.Results {
			if r.Repository != c.repo {
				t.Errorf("%s: a finding from repository %q", c.repo, r.Repository)
			}
			have = append(have, want{r.Location.URI, r.Location.StartLine, r.Historical})
		}
		slices.SortFunc(have, func(a, b want) int {
			if a.uri != b.uri {
				return strings.Compare(a.uri, b.uri)
			}
			if a.historical != b.historical {
				if a.historical {
					return 1
				}
				return -1
			}
			return a.line - b.line
		})
		if !slices.Equal(have, c.want) {
			t.Errorf("%s:\n got %v\nwant %v", c.repo, have, c.want)
		}
	}
}

func TestGitleaksSecretsReadsTheSnippetInOrder(t *testing.T) {
	out := gitleaksReport(
		leak{"a", "x", 1, "first"},
		leak{"b", "y", 2, ""},
		leak{"c", "z", 3, "third"},
	)
	if got := gitleaksSecrets([]byte(out)); !slices.Equal(got, []string{"first", "", "third"}) {
		t.Errorf("secrets = %q", got)
	}
	// A result with no location has no secret either.
	noLocation := `{"runs":[{"results":[{"ruleId":"a","message":{"text":"m"}}]}]}`
	if got := gitleaksSecrets([]byte(noLocation)); !slices.Equal(got, []string{""}) {
		t.Errorf("secrets = %q, want one empty", got)
	}
	if got := gitleaksSecrets([]byte("not json")); got != nil {
		t.Errorf("secrets = %q, want nil for output that does not decode", got)
	}
}

// Secrets that do not line up with the results cannot say which result is which, and a guess
// could drop a credential as a duplicate of a different one. Every history finding is kept.
func TestDropStillInTreeKeepsEverythingWhenTheSecretsDoNotLineUp(t *testing.T) {
	r := sarif.Result{RuleID: "generic-api-key", Location: sarif.Location{URI: "settings.py", StartLine: 3}}
	hist := []sarif.Result{r}
	if got := dropStillInTree("/src", []sarif.Result{r}, nil, hist, []string{"k"}); len(got) != 1 {
		t.Errorf("tree secrets missing: kept %d, want 1", len(got))
	}
	if got := dropStillInTree("/src", []sarif.Result{r}, []string{"k"}, hist, nil); len(got) != 1 {
		t.Errorf("history secrets missing: kept %d, want 1", len(got))
	}
	if got := dropStillInTree("/src", []sarif.Result{r}, []string{"k"}, hist, []string{"k"}); len(got) != 0 {
		t.Errorf("a matched duplicate was kept: %v", got)
	}
}
