package git

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func initRepo(t *testing.T) (dir, headSHA string) {
	t.Helper()
	dir = t.TempDir()
	runGit(t, dir, "init", "-q", "-b", "main")
	runGit(t, dir, "config", "user.email", "t@example.com")
	runGit(t, dir, "config", "user.name", "Tester")
	if err := os.WriteFile(filepath.Join(dir, "file.txt"), []byte("hi"), 0o600); err != nil {
		t.Fatal(err)
	}
	runGit(t, dir, "add", ".")
	runGit(t, dir, "commit", "-q", "-m", "init")
	out := runGit(t, dir, "rev-parse", "HEAD")
	return dir, string(out[:len(out)-1]) // strip newline
}

func runGit(t *testing.T, dir string, args ...string) []byte {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...) //nolint:gosec // test helper
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return out
}

func TestCheckoutDefaultBranch(t *testing.T) {
	src, _ := initRepo(t)
	dir, cleanup, err := Checkout(context.Background(), src, "")
	if err != nil {
		t.Fatalf("checkout: %v", err)
	}
	defer cleanup()
	if _, err := os.Stat(filepath.Join(dir, "file.txt")); err != nil {
		t.Fatalf("expected checked-out file: %v", err)
	}
	// cleanup removes the dir
	cleanup()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("cleanup should remove dir")
	}
}

func TestCheckoutRevision(t *testing.T) {
	src, sha := initRepo(t)
	dir, cleanup, err := Checkout(context.Background(), src, sha)
	if err != nil {
		t.Fatalf("checkout revision: %v", err)
	}
	defer cleanup()
	if _, err := os.Stat(filepath.Join(dir, "file.txt")); err != nil {
		t.Fatalf("expected file at revision: %v", err)
	}
}

func TestCheckoutBadURL(t *testing.T) {
	_, _, err := Checkout(context.Background(), filepath.Join(t.TempDir(), "does-not-exist"), "")
	if err == nil {
		t.Fatal("expected clone error for missing repo")
	}
}

func TestCheckoutBadRevision(t *testing.T) {
	src, _ := initRepo(t)
	_, _, err := Checkout(context.Background(), src, "no-such-rev")
	if err == nil {
		t.Fatal("expected checkout error for bad revision")
	}
}
