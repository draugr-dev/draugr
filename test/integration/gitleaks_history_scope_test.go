//go:build integration

package integration

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/scanners"
	"github.com/draugr-dev/draugr/pkg/plugin"
)

// Git history cannot be narrowed to a component's paths, so a history scan walks every commit in
// the repository. Two components sharing one must each see only the secrets committed under their
// own paths, or each reports the other's, and a secret its owner rotated stays open under a team
// that cannot fix it.
//
// Both secrets are removed from the tree before the scan, so every finding here comes from the
// history pass: a tree pass is already narrowed by the checkout and would pass this test alone.
func TestGitleaksHistoryStaysInsideEachComponentsPaths(t *testing.T) {
	requireTool(t, "gitleaks", "the history pass is what this test is about")
	requireTool(t, "git", "the fixture is a repository with history")

	repo := newTwoComponentHistoryRepo(t)

	for _, own := range []string{"services/api", "services/web"} {
		target := plugin.RepositoryTarget{URL: repo, Paths: []string{own}}
		report, err := scanners.NewGitleaks().Scan(context.Background(), target, plugin.Config{"history": true})
		if err != nil {
			t.Fatalf("%s: %v", own, err)
		}
		if len(report.Results) == 0 {
			t.Fatalf("%s: no findings, want the secret committed under its own paths", own)
		}
		for _, r := range report.Results {
			if !strings.HasPrefix(r.Location.URI, own+"/") {
				t.Errorf("%s: reported %s, which another component owns", own, r.Location.URI)
			}
			if !r.Historical {
				t.Errorf("%s: %s is not marked historical, though the tree no longer holds it", own, r.Location.URI)
			}
		}
	}
}

// newTwoComponentHistoryRepo commits a private key under each of two services, then removes both.
func newTwoComponentHistoryRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	git := func(args ...string) {
		t.Helper()
		// #nosec G204 -- a fixed binary; every argument list is a literal in this function.
		c := exec.Command("git", args...)
		c.Dir = dir
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	git("init", "--quiet")
	git("config", "user.email", "test@draugr.dev")
	git("config", "user.name", "test")
	for _, svc := range []string{"services/api", "services/web"} {
		if err := os.MkdirAll(filepath.Join(dir, svc), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, svc, "id_rsa"), []byte(fakePrivateKey), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, svc, "main.go"), []byte("package main\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	git("add", "services")
	git("commit", "--quiet", "-m", "services")
	git("rm", "--quiet", "services/api/id_rsa", "services/web/id_rsa")
	git("commit", "--quiet", "-m", "remove keys")
	return dir
}
