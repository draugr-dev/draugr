package git

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// treeRepo is a repository holding services/web/main.go and go.mod, committed.
func treeRepo(t *testing.T) (dir, head string) {
	t.Helper()
	dir, _ = initRepo(t)
	if err := os.MkdirAll(filepath.Join(dir, "services", "web"), 0o750); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"services/web/main.go", "go.mod"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	runGit(t, dir, "add", ".")
	runGit(t, dir, "commit", "-q", "-m", "tree")
	out := runGit(t, dir, "rev-parse", "HEAD")
	return dir, strings.TrimSpace(string(out))
}

func TestPathsAt(t *testing.T) {
	ctx := context.Background()
	dir, head := treeRepo(t)
	// A directory on disk and not in the commit: present to a look at the disk, absent to a scan.
	if err := os.MkdirAll(filepath.Join(dir, "uncommitted"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "uncommitted", "f"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	// The same repository read in place and fetched as a remote: file:// is not a local path, so
	// it takes the fetch.
	for name, url := range map[string]string{"local": dir, "remote": "file://" + dir} {
		t.Run(name, func(t *testing.T) {
			commit, err := PathsAt(ctx, url, "main", []string{"services/web/**", "go.mod"})
			if err != nil {
				t.Fatalf("paths in the tree: %v", err)
			}
			if commit != head {
				t.Errorf("commit = %s, want %s", commit, head)
			}

			_, err = PathsAt(ctx, url, "main", []string{"services/api", "go.mod", "uncommitted"})
			if err == nil {
				t.Fatal("missing paths passed")
			}
			for _, want := range []string{"services/api", "uncommitted"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not name %s", err, want)
				}
			}
			if strings.Contains(err.Error(), "go.mod") {
				t.Errorf("error %q names a path that exists", err)
			}

			if _, err := PathsAt(ctx, url, head, nil); err != nil {
				t.Errorf("an existing commit with no paths: %v", err)
			}
			if _, err := PathsAt(ctx, url, "no-such-branch", nil); err == nil {
				t.Error("a revision that does not exist passed")
			}
		})
	}

	// A full commit name the repository does not hold: ResolveRevision takes it on trust, PathsAt
	// does not.
	missing := strings.Repeat("0", 40)
	if _, err := PathsAt(ctx, dir, missing, nil); err == nil || !strings.Contains(err.Error(), "not in the repository") {
		t.Errorf("an absent commit: got %v", err)
	}
}

func TestPathsAtDefaultRevision(t *testing.T) {
	dir, head := treeRepo(t)
	commit, err := PathsAt(context.Background(), "file://"+dir, "", []string{"go.mod"})
	if err != nil {
		t.Fatal(err)
	}
	if commit != head {
		t.Errorf("commit = %s, want HEAD %s", commit, head)
	}
}

func TestSelectedAndShortRevision(t *testing.T) {
	if got := Selected([]string{"services/web/**"}); len(got) != 1 || got[0] != "services/web" {
		t.Errorf("Selected = %v, want [services/web]", got)
	}
	if got := Selected(nil); got != nil {
		t.Errorf("Selected(nil) = %v, want nil", got)
	}
	if got := ShortRevision(strings.Repeat("a", 40)); got != strings.Repeat("a", 12) {
		t.Errorf("ShortRevision = %s", got)
	}
}
