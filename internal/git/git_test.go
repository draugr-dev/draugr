package git

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
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

func TestCheckoutWorkingTreeIncludesUncommittedWork(t *testing.T) {
	// The whole point: the loop of fixing a finding is edit, scan, see whether it went away, and
	// a scan that only reads commits needs one per iteration.
	src, sha := initRepo(t)
	if err := os.WriteFile(filepath.Join(src, "wip.txt"), []byte("not committed"), 0o600); err != nil {
		t.Fatal(err)
	}

	co, cleanup, err := CheckoutWorkingTree(context.Background(), src, Scope{})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if _, err := os.Stat(filepath.Join(co.Dir, "wip.txt")); err != nil {
		t.Errorf("uncommitted work is missing from the copy: %v", err)
	}
	if _, err := os.Stat(filepath.Join(co.Dir, "file.txt")); err != nil {
		t.Errorf("committed work is missing from the copy: %v", err)
	}
	if !co.WorkingTree {
		t.Error("the tree does not know what it is, so the report cannot say")
	}
	if co.Revision != sha {
		t.Errorf("Revision = %q, want the commit the tree sits on (%q) kept plain", co.Revision, sha)
	}
	if co.Dirty != 1 {
		t.Errorf("Dirty = %d, want 1", co.Dirty)
	}
}

func TestCheckoutWorkingTreeLeavesIgnoredFilesBehind(t *testing.T) {
	// The file list is git's own answer to "what is in this working tree", so a build directory
	// or a local .env is left out for the same reason a commit would leave it out — not by a rule
	// Draugr invented and would have to keep in step with .gitignore.
	src, _ := initRepo(t)
	if err := os.WriteFile(filepath.Join(src, ".gitignore"), []byte("secret.env\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "secret.env"), []byte("TOKEN=x"), 0o600); err != nil {
		t.Fatal(err)
	}

	co, cleanup, err := CheckoutWorkingTree(context.Background(), src, Scope{})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if _, err := os.Stat(filepath.Join(co.Dir, "secret.env")); err == nil {
		t.Error("an ignored file was copied into the scan")
	}
	if _, err := os.Stat(filepath.Join(co.Dir, ".gitignore")); err != nil {
		t.Error("the .gitignore itself is tracked and should be there")
	}
}

func TestCheckoutWorkingTreeNeverTouchesTheSource(t *testing.T) {
	// The test that matters. Scoping is applied by deleting what is not wanted; against a real
	// checkout that is not scoping, it is data loss.
	src, _ := initRepo(t)
	for _, d := range []string{"keep", "drop"} {
		if err := os.MkdirAll(filepath.Join(src, d), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(src, d, "f.txt"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	runGit(t, src, "add", ".")
	runGit(t, src, "commit", "-q", "-m", "dirs")

	co, cleanup, err := CheckoutWorkingTree(context.Background(), src, Scope{Paths: []string{"keep"}})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	// Scoped in the copy...
	if _, err := os.Stat(filepath.Join(co.Dir, "drop", "f.txt")); err == nil {
		t.Error("the copy was not scoped")
	}
	// ...and untouched in the original.
	if _, err := os.Stat(filepath.Join(src, "drop", "f.txt")); err != nil {
		t.Fatalf("scoping deleted a file from the real checkout: %v", err)
	}
	if _, err := os.Stat(filepath.Join(src, "keep", "f.txt")); err != nil {
		t.Fatalf("the real checkout lost a file: %v", err)
	}
}

func TestCheckoutWorkingTreeRefusesARemote(t *testing.T) {
	// There is no working tree to read. Falling back to the committed revision would answer a
	// different question while looking like it answered this one.
	if _, _, err := CheckoutWorkingTree(context.Background(), "https://example.test/x.git", Scope{}); err == nil {
		t.Fatal("expected a refusal")
	}
}

func TestCopyIntoRefusesAPathThatEscapes(t *testing.T) {
	// git does not emit paths that leave a repository, but this reads a list from a subprocess
	// and then writes files from it — the one place where being wrong writes outside the
	// temporary directory.
	root := t.TempDir()
	if err := copyInto(root, root, "../escaped.txt"); err == nil {
		t.Error("a path escaping the copy was accepted")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(root), "escaped.txt")); err == nil {
		t.Error("a file was written outside the copy")
	}
	// A normal relative path still works, including one in a subdirectory that does not exist yet.
	src := t.TempDir()
	if err := os.MkdirAll(filepath.Join(src, "a", "b"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "a", "b", "f.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := copyInto(root, src, filepath.Join("a", "b", "f.txt")); err != nil {
		t.Fatalf("a normal path was refused: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "a", "b", "f.txt")); err != nil {
		t.Errorf("the file was not copied: %v", err)
	}
}

func TestCheckoutWorkingTreeSkipsWhatItCannotCopy(t *testing.T) {
	// A tree somebody is actively editing changes underneath the scan. A symlink, a file that
	// vanished between the listing and the read — one of those is not a reason to refuse to scan
	// the rest of it.
	src, _ := initRepo(t)
	if err := os.Symlink("file.txt", filepath.Join(src, "link.txt")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	co, cleanup, err := CheckoutWorkingTree(context.Background(), src, Scope{})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	// The link is not copied — copied as a link it could point outside the copy, which would put
	// a scanner back in the real checkout.
	if _, err := os.Lstat(filepath.Join(co.Dir, "link.txt")); err == nil {
		t.Error("a symlink was copied into the scan")
	}
	if _, err := os.Stat(filepath.Join(co.Dir, "file.txt")); err != nil {
		t.Errorf("the rest of the tree should still be there: %v", err)
	}
}

func TestCheckoutWorkingTreeOnSomethingThatIsNotARepository(t *testing.T) {
	// A path that exists but has no git in it. The error names the listing rather than leaving a
	// bare exit status.
	dir := t.TempDir()
	if _, _, err := CheckoutWorkingTree(context.Background(), dir, Scope{}); err == nil {
		t.Fatal("expected an error for a directory that is not a repository")
	} else if !strings.Contains(err.Error(), "working tree") {
		t.Errorf("error should say what it was doing: %v", err)
	}
}

func TestCheckoutWorkingTreeAppliesIgnore(t *testing.T) {
	src, _ := initRepo(t)
	for _, n := range []string{"keep.txt", "drop.txt"} {
		if err := os.WriteFile(filepath.Join(src, n), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	co, cleanup, err := CheckoutWorkingTree(context.Background(), src, Scope{Ignore: []string{"drop.txt"}})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if _, err := os.Stat(filepath.Join(co.Dir, "drop.txt")); err == nil {
		t.Error("ignore was not applied to the copy")
	}
	if _, err := os.Stat(filepath.Join(co.Dir, "keep.txt")); err != nil {
		t.Errorf("ignore removed too much: %v", err)
	}
	if _, err := os.Stat(filepath.Join(src, "drop.txt")); err != nil {
		t.Error("ignore deleted from the real checkout")
	}
}

// A secret committed and then removed is the case secret detection primarily exists for: it is
// still fetchable by anyone who can clone, so it is still compromised. Finding it needs the
// history to be present, which a shallow clone does not have.
func TestCheckoutWithHistoryKeepsRemovedCommits(t *testing.T) {
	src := t.TempDir()
	runGit(t, src, "init", "-q", "-b", "main")
	runGit(t, src, "config", "user.email", "t@example.com")
	runGit(t, src, "config", "user.name", "Test")
	if err := os.WriteFile(filepath.Join(src, "leak.txt"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	runGit(t, src, "add", "-A")
	runGit(t, src, "commit", "-q", "-m", "add")
	if err := os.Remove(filepath.Join(src, "leak.txt")); err != nil {
		t.Fatal(err)
	}
	runGit(t, src, "add", "-A")
	runGit(t, src, "commit", "-q", "-m", "remove")

	ctx := context.Background()

	// The default clone is not asserted to be shallow here: git ignores --depth for a clone from
	// a local path, so a fixture cannot distinguish the two. What matters and is testable is the
	// guarantee in the other direction — asking for history gets history.
	deep, cleanDeep, err := Checkout(ctx, src, "", Scope{History: true})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanDeep()
	if n := commitCount(t, deep.Dir); n != 2 {
		t.Errorf("a history checkout should hold both commits, got %d", n)
	}
	// And the removed file is reachable from history, which is the whole point.
	out := runGit(t, deep.Dir, "log", "--all", "--name-only", "--format=")
	if !strings.Contains(string(out), "leak.txt") {
		t.Errorf("the removed file should be reachable in history, got:\n%s", out)
	}
}

func commitCount(t *testing.T, dir string) int {
	t.Helper()
	n, err := strconv.Atoi(strings.TrimSpace(string(runGit(t, dir, "rev-list", "--count", "HEAD"))))
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// Sparse checkout is off when history is wanted, so the tree has to be cut down the slow way
// afterwards. Without this the scope silently stops applying the moment somebody asks for
// history, and the scan quietly widens to the whole repository.
func TestCheckoutWithHistoryStillHonoursPaths(t *testing.T) {
	src, _ := initRepo(t)
	for _, d := range []string{"keep", "drop"} {
		if err := os.MkdirAll(filepath.Join(src, d), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(src, d, "f.txt"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	runGit(t, src, "add", ".")
	runGit(t, src, "commit", "-q", "-m", "dirs")

	co, cleanup, err := Checkout(context.Background(), src, "",
		Scope{Paths: []string{"keep"}, History: true})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	if _, err := os.Stat(filepath.Join(co.Dir, "keep", "f.txt")); err != nil {
		t.Errorf("the scoped directory is missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(co.Dir, "drop", "f.txt")); err == nil {
		t.Error("a history checkout ignored the path scope")
	}
	// History is present regardless, which is what the scope cannot narrow: git history is not
	// sparse-checkoutable, so a finding from outside the scope is still a real finding in this
	// repository and belongs in config.exclude rather than being silently dropped.
	if n := commitCount(t, co.Dir); n < 2 {
		t.Errorf("history should still be there, got %d commits", n)
	}
}
