package git

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A remote is resolved with one ls-remote against the server a clone would use, and it has to
// agree with what that clone would check out.
func TestResolveRevisionAgainstARemote(t *testing.T) {
	dir, head := initRepo(t)
	url := "file://" + dir

	for _, ref := range []string{"", "main", "HEAD", head} {
		got, err := ResolveRevision(t.Context(), url, ref)
		if err != nil || got != head {
			t.Errorf("resolve %q = %q, %v, want %s", ref, got, err, head)
		}
	}

	// An annotated tag is an object of its own. What a scan reads is the commit it points at, so
	// the tag's object name would key a cache on something no checkout ever holds.
	if err := os.WriteFile(filepath.Join(dir, "file.txt"), []byte("tagged"), 0o600); err != nil {
		t.Fatal(err)
	}
	runGit(t, dir, "commit", "-qam", "tagged")
	tagged := strings.TrimSpace(string(runGit(t, dir, "rev-parse", "HEAD")))
	runGit(t, dir, "tag", "-a", "v1", "-m", "v1")
	tagObject := strings.TrimSpace(string(runGit(t, dir, "rev-parse", "v1")))
	got, err := ResolveRevision(t.Context(), url, "v1")
	if err != nil || got != tagged {
		t.Errorf("resolve an annotated tag = %q, %v, want the commit %s, not the tag %s", got, err, tagged, tagObject)
	}

	if _, err := ResolveRevision(t.Context(), url, "no-such-branch"); err == nil ||
		!strings.Contains(err.Error(), "names no such revision") {
		t.Errorf("a revision the remote does not have = %v, want an error saying so", err)
	}
	if _, err := ResolveRevision(t.Context(), "file://"+filepath.Join(dir, "missing"), "main"); err == nil {
		t.Error("a remote that cannot be reached should be an error, not an answer")
	}
}

// A local path is resolved with rev-parse, and what rev-parse prints is only an answer when it is
// a commit name.
func TestResolveRevisionRefusesWhatIsNotACommit(t *testing.T) {
	dir, _ := initRepo(t)
	// `--short` makes rev-parse print an abbreviation, which is a valid object and not a key.
	if _, err := ResolveRevision(t.Context(), dir, "--short"); err == nil {
		t.Error("an abbreviated name should be refused, since it can grow ambiguous")
	}
}

func TestRemoteURL(t *testing.T) {
	dir, _ := initRepo(t)
	if got := RemoteURL(t.Context(), dir); got != "" {
		t.Errorf("a repository with no remote = %q, want none, so the caller keeps its path", got)
	}

	// With no origin, the first remote by name, so the answer does not depend on the order git
	// happens to list them in.
	runGit(t, dir, "remote", "add", "upstream", "https://example.com/upstream.git")
	runGit(t, dir, "remote", "add", "fork", "https://example.com/fork.git")
	if got := RemoteURL(t.Context(), dir); got != "https://example.com/fork.git" {
		t.Errorf("no origin = %q, want the first remote by name", got)
	}

	runGit(t, dir, "remote", "add", "origin", "https://example.com/origin.git")
	if got := RemoteURL(t.Context(), dir); got != "https://example.com/origin.git" {
		t.Errorf("with an origin = %q, want origin", got)
	}

	if got := RemoteURL(t.Context(), filepath.Join(dir, "missing")); got != "" {
		t.Errorf("a path that is not a repository = %q, want none", got)
	}
}
