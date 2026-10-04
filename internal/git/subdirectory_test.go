package git

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// A directory in a checkout, two levels down, and the root itself: the root is the same answer
// from both, and only the first has a place in it.
func TestSubdirectoryFindsTheWorkTreeRoot(t *testing.T) {
	repo, _ := initRepo(t)
	nested := filepath.Join(repo, "services", "payments")
	if err := os.MkdirAll(nested, 0o750); err != nil {
		t.Fatal(err)
	}
	want, err := filepath.EvalSymlinks(repo)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ path, rel string }{{nested, "services/payments"}, {repo, ""}} {
		root, rel, ok := Subdirectory(context.Background(), c.path)
		if !ok || root != want || rel != c.rel {
			t.Errorf("Subdirectory(%s) = %q, %q, %v; want %q, %q, true", c.path, root, rel, ok, want, c.rel)
		}
	}
}

func TestSubdirectoryDeclinesWhatHasNoWorkTree(t *testing.T) {
	repo, _ := initRepo(t)
	bare := filepath.Join(t.TempDir(), "bare.git")
	runGit(t, repo, "clone", "-q", "--bare", repo, bare)
	for _, path := range []string{t.TempDir(), bare, "https://github.com/acme/web"} {
		if _, _, ok := Subdirectory(context.Background(), path); ok {
			t.Errorf("Subdirectory(%s) answered for something with no work tree", path)
		}
	}
}

// git's own message for this is that the repository does not exist, about a directory that does.
func TestCheckoutSaysADirectoryIsNotARepository(t *testing.T) {
	if _, _, err := Checkout(context.Background(), t.TempDir(), "", Scope{}); !errors.Is(err, errNotRepository) {
		t.Errorf("err = %v, want %v", err, errNotRepository)
	}
}

// A bare repository is a repository: the check that refuses a plain directory must not refuse it.
func TestCheckoutStillClonesABareRepository(t *testing.T) {
	repo, head := initRepo(t)
	bare := filepath.Join(t.TempDir(), "bare.git")
	runGit(t, repo, "clone", "-q", "--bare", repo, bare)
	tree, cleanup, err := Checkout(context.Background(), bare, "", Scope{})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if tree.Revision != head {
		t.Errorf("revision = %s, want %s", tree.Revision, head)
	}
}
