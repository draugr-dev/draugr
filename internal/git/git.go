// Package git provides repository checkouts for scanners that operate on source trees.
package git

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Tree is a materialised copy of a repository, and the revision it actually holds.
//
// The resolved revision matters because a descriptor usually does not name one: `revision` is
// empty far more often than not, meaning "the default branch", which is a moving answer. A report
// that cannot say which commit it describes cannot be reproduced or compared, and that is the
// entire justification for scanning a committed revision in the first place.
type Tree struct {
	// Dir is the checkout on disk.
	Dir string
	// Revision is the SHA that was materialised, as `git rev-parse HEAD` reports it. Empty only
	// when git could not be asked, which is not worth failing a scan over.
	Revision string
	// Dirty counts uncommitted files in the source that are *not* in this tree. Always 0 for a
	// clone; set only when the tree was taken from a working copy.
	Dirty int
}

// Checkout clones url into a fresh temporary directory, materialising only what scope allows.
// With an empty revision it does a shallow clone of the default branch; otherwise it clones and
// checks out revision. The returned cleanup removes the directory (call it even on error paths
// that returned a dir).
func Checkout(ctx context.Context, url, revision string, scope Scope) (tree Tree, cleanup func(), err error) {
	dir, err := os.MkdirTemp("", "draugr-repo-")
	if err != nil {
		return Tree{}, nil, err
	}
	cleanup = func() { _ = os.RemoveAll(dir) }

	sparse := len(coneDirs(scope.Paths)) > 0
	cloneArgs := []string{"clone", "--quiet"}
	if revision == "" {
		cloneArgs = append(cloneArgs, "--depth", "1")
	}
	if sparse {
		// --sparse starts the working tree at the root files only, and --filter leaves the
		// blobs under the directories we never ask for unfetched. Together they are the
		// difference between scoping a monorepo and downloading one to delete most of it.
		cloneArgs = append(cloneArgs, "--sparse", "--filter=blob:none")
	}
	cloneArgs = append(cloneArgs, url, dir)

	if err := gitRun(ctx, cloneArgs...); err != nil {
		if !sparse {
			cleanup()
			return Tree{}, nil, fmt.Errorf("git clone: %w", err)
		}
		// Partial clone needs the server's cooperation and sparse checkout needs a recent git.
		// Neither is a reason to refuse to scan: fall back to a full clone and cut the tree down
		// afterwards, which produces the same tree by a slower route.
		if err := retryPlain(ctx, dir, url, revision); err != nil {
			cleanup()
			return Tree{}, nil, err
		}
		if err := prune(dir, scope, true); err != nil {
			cleanup()
			return Tree{}, nil, fmt.Errorf("restrict checkout to paths: %w", err)
		}
		return resolved(ctx, dir, url), cleanup, nil
	}

	if revision != "" {
		if err := gitRun(ctx, "-C", dir, "checkout", "--quiet", revision); err != nil {
			cleanup()
			return Tree{}, nil, fmt.Errorf("git checkout %q: %w", revision, err)
		}
	}
	if sparse {
		// Cone mode is what keeps the root files: it materialises every selected directory, the
		// directories above them, and the repository root — which is where the manifests and the
		// scanners' own configuration live.
		args := append([]string{"-C", dir, "sparse-checkout", "set", "--cone"}, coneDirs(scope.Paths)...)
		if err := gitRun(ctx, args...); err != nil {
			cleanup()
			return Tree{}, nil, fmt.Errorf("git sparse-checkout: %w", err)
		}
	}
	if len(scope.Ignore) > 0 {
		if err := prune(dir, scope, false); err != nil {
			cleanup()
			return Tree{}, nil, fmt.Errorf("apply ignore: %w", err)
		}
	}
	return resolved(ctx, dir, url), cleanup, nil
}

// resolved reports the tree, the commit it holds, and what the scan is therefore not seeing.
//
// A local checkout with edits in it is the normal state of somewhere someone is working. The
// useful form of that fact is the report saying which commit it read and how much of the tree it
// left out — not a warning on every run.
//
// Best effort on both counts: a checkout that cannot be interrogated still scans. Failing a scan
// because `rev-parse` did not answer would trade a whole result for a line of provenance.
//
// Both of Checkout's exit paths go through here, so neither can forget one of the two.
func resolved(ctx context.Context, dir, source string) Tree {
	t := Tree{Dir: dir, Dirty: UncommittedFiles(ctx, source)}
	out, err := exec.CommandContext(ctx, "git", "-C", dir, "rev-parse", "HEAD").Output() //nolint:gosec // Draugr's own temporary checkout
	if err != nil {
		return t
	}
	t.Revision = strings.TrimSpace(string(out))
	return t
}

// retryPlain re-clones url into dir without sparse checkout, for a server or a git that could
// not do it the fast way. dir already exists and may hold a partial clone.
func retryPlain(ctx context.Context, dir, url, revision string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
			return err
		}
	}
	args := []string{"clone", "--quiet"}
	if revision == "" {
		args = append(args, "--depth", "1")
	}
	args = append(args, url, dir)
	if err := gitRun(ctx, args...); err != nil {
		return fmt.Errorf("git clone: %w", err)
	}
	if revision != "" {
		if err := gitRun(ctx, "-C", dir, "checkout", "--quiet", revision); err != nil {
			return fmt.Errorf("git checkout %q: %w", revision, err)
		}
	}
	return nil
}

// gitRun runs git. A var so a test can make one invocation fail — the fallback below is taken
// only when a server refuses a partial clone, which is not something a local fixture can be
// asked to do, and an untested fallback is one that breaks for whoever self-hosts.
var gitRun = func(ctx context.Context, args ...string) error {
	cmd := exec.CommandContext(ctx, "git", args...) //nolint:gosec // args are constructed, not shell-interpreted
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%w: %s", err, out)
	}
	return nil
}

// UncommittedFiles counts a local repository's uncommitted changes, or 0 when there are none,
// the path is not local, or git cannot say.
//
// Exists because a local path is cloned like any other source: the scan sees the *committed*
// state, not the files on disk. That is right — a scan has to describe a revision someone else
// can reproduce — and it is invisible, so a change that introduces a finding passes until it is
// committed. Best-effort: a scan must not fail because git could not answer a courtesy question.
func UncommittedFiles(ctx context.Context, url string) int {
	if !IsLocalPath(url) {
		return 0
	}
	out, err := exec.CommandContext(ctx, "git", "-C", url, "status", "--porcelain").Output() //nolint:gosec // the descriptor's own repository path
	if err != nil {
		return 0 // not a repository, or no git — the clone will say so properly
	}
	n := 0
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if strings.TrimSpace(line) != "" {
			n++
		}
	}
	return n
}

// IsLocalPath reports whether url names a directory on this machine rather than a remote.
//
// Deliberately a filesystem question rather than a URL-parsing one: "." and "../service" and an
// absolute path are all local, and anything with a scheme or an scp-style host is not.
func IsLocalPath(url string) bool {
	if url == "" || strings.Contains(url, "://") {
		return false
	}
	if i := strings.Index(url, ":"); i > 0 && !strings.HasPrefix(url, "/") && !strings.HasPrefix(url, ".") {
		return false // scp-style, e.g. git@github.com:org/repo.git
	}
	info, err := os.Stat(url)
	return err == nil && info.IsDir()
}
