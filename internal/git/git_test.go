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
	co, cleanup, err := Checkout(context.Background(), src, "", Scope{})
	if err != nil {
		t.Fatalf("checkout: %v", err)
	}
	dir := co.Dir
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
	co, cleanup, err := Checkout(context.Background(), src, sha, Scope{})
	if err != nil {
		t.Fatalf("checkout revision: %v", err)
	}
	dir := co.Dir
	defer cleanup()
	if _, err := os.Stat(filepath.Join(dir, "file.txt")); err != nil {
		t.Fatalf("expected file at revision: %v", err)
	}
}

func TestCheckoutBadURL(t *testing.T) {
	_, _, err := Checkout(context.Background(), filepath.Join(t.TempDir(), "does-not-exist"), "", Scope{})
	if err == nil {
		t.Fatal("expected clone error for missing repo")
	}
}

func TestCheckoutBadRevision(t *testing.T) {
	src, _ := initRepo(t)
	_, _, err := Checkout(context.Background(), src, "no-such-rev", Scope{})
	if err == nil {
		t.Fatal("expected checkout error for bad revision")
	}
}

func TestCheckoutReportsTheRevisionItMaterialised(t *testing.T) {
	// A descriptor usually names no revision, so "the default branch" is what gets scanned — a
	// moving answer. Without resolving it, a report cannot say which commit it describes, which
	// is the entire justification for scanning a committed revision rather than a working tree.
	src, sha := initRepo(t)

	co, cleanup, err := Checkout(context.Background(), src, "", Scope{})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if co.Revision != sha {
		t.Errorf("Revision = %q, want the repository's HEAD %q", co.Revision, sha)
	}
	if co.Dirty != 0 {
		t.Errorf("a clean checkout reported %d uncommitted files", co.Dirty)
	}
}

func TestCheckoutReportsUncommittedWorkItLeftBehind(t *testing.T) {
	// Recorded rather than warned about: a checkout with edits in it is the normal state of
	// somewhere someone is working, and what they need is the report saying which commit it read
	// and how much of the tree it did not.
	src, _ := initRepo(t)
	if err := os.WriteFile(filepath.Join(src, "edited.txt"), []byte("wip"), 0o600); err != nil {
		t.Fatal(err)
	}

	co, cleanup, err := Checkout(context.Background(), src, "", Scope{})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if co.Dirty != 1 {
		t.Errorf("Dirty = %d, want 1", co.Dirty)
	}
	// And it is genuinely absent from what was scanned, which is the fact the count is about.
	if _, err := os.Stat(filepath.Join(co.Dir, "edited.txt")); err == nil {
		t.Error("uncommitted work reached the checkout")
	}
}

func TestCheckoutOfARemoteReportsNoUncommittedWork(t *testing.T) {
	// There is no working copy to compare against, and inventing a 0 from a failed git call is
	// the same answer for a different reason — worth pinning so it stays deliberate.
	src, _ := initRepo(t)
	co, cleanup, err := Checkout(context.Background(), src, "", Scope{})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if UncommittedFiles(context.Background(), "https://example.test/x.git") != 0 {
		t.Error("a remote cannot have uncommitted files")
	}
	if co.Revision == "" {
		t.Error("a local clone should still resolve its revision")
	}
}
