package sagafetch

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/netpolicy"
)

// repo makes a git repository holding one fragment, and returns its path and HEAD.
func repo(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	write := func(rel, body string) {
		full := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("components/api/draugr.saga-fragment.yaml",
		"components:\n  - name: api\n    repositories: [{ url: \".\" }]\n")
	for _, args := range [][]string{
		{"init", "-q", "."}, {"add", "-A"},
		{"-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "-m", "fragment"},
		{"tag", "v1.0.0"},
	} {
		cmd := exec.Command("git", args...) //nolint:gosec // fixed argv, test-local repo
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Skipf("git unavailable: %v %s", err, out)
		}
	}
	//nolint:gosec // fixed argv against the temp dir this test just made
	sha, err := exec.Command("git", "-C", dir, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatal(err)
	}
	return dir, strings.TrimSpace(string(sha))
}

// The commit a tag resolved to is what makes a moved tag visible after the fact, so it has to
// come back from a real fetch rather than only from the fake in pkg/saga's tests.
func TestFetchReturnsTheResolvedCommit(t *testing.T) {
	dir, sha := repo(t)
	f := New(context.Background())
	defer f.Close()

	got, resolved, cleanup, err := f.Fetch(dir, "v1.0.0")
	defer cleanup()
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if resolved != sha {
		t.Errorf("resolved = %q, want %q", resolved, sha)
	}
	if _, err := os.Stat(filepath.Join(got, "components/api/draugr.saga-fragment.yaml")); err != nil {
		t.Errorf("the fragment is not in the checkout: %v", err)
	}
}

// A descriptor naming several fragments from one repository should clone it once. Both calls must
// still report the commit, including the one served from the pool.
func TestFetchSharesOneCheckoutPerRevision(t *testing.T) {
	dir, sha := repo(t)
	f := New(context.Background())
	defer f.Close()

	a, shaA, cleanA, err := f.Fetch(dir, "v1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanA()
	b, shaB, cleanB, err := f.Fetch(dir, "v1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanB()

	if a != b {
		t.Errorf("two references to one revision cloned twice: %q vs %q", a, b)
	}
	if shaA != sha || shaB != sha {
		t.Errorf("commits = %q, %q, want %q from both", shaA, shaB, sha)
	}
}

// Offline must refuse. A fragment that cannot be fetched is scope the descriptor claims and the
// run would not have, and a scan quietly covering less than it says is the failure to avoid.
func TestFetchRefusesWhenOffline(t *testing.T) {
	netpolicy.SetOffline(true)
	defer netpolicy.SetOffline(false)

	f := New(context.Background())
	defer f.Close()

	_, _, cleanup, err := f.Fetch("https://github.com/acme/platform.git", "v2.4.0")
	defer cleanup()
	if err == nil {
		t.Fatal("a remote fragment was fetched while offline")
	}
	if !strings.Contains(err.Error(), "acme/platform") || !strings.Contains(err.Error(), "--resolved") {
		t.Errorf("the error should name the fragment and the way round it: %v", err)
	}
}
