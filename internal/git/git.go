// Package git provides repository checkouts for scanners that operate on source trees.
package git

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// Tree is a materialized copy of a repository, and the revision it actually holds.
//
// The resolved revision matters because a descriptor usually does not name one: `revision` is
// empty far more often than not, meaning "the default branch", which is a moving answer. A report
// that cannot say which commit it describes cannot be reproduced or compared, and that is the
// entire justification for scanning a committed revision in the first place.
type Tree struct {
	// Dir is the checkout on disk.
	Dir string
	// Revision is the SHA that was materialized, as `git rev-parse HEAD` reports it. Empty only
	// when git could not be asked, which is not worth failing a scan over.
	Revision string
	// Dirty counts uncommitted files in the source. For a clone they are what the tree is
	// missing; for a working-tree copy they are what it uniquely contains. WorkingTree says
	// which, so nothing has to infer it from a count.
	Dirty int
	// WorkingTree reports that this copy came from a checkout on disk, uncommitted work included,
	// rather than from a commit — so it is not reproducible.
	WorkingTree bool
}

// Checkout clones url into a fresh temporary directory, materializing only what scope allows.
// With an empty revision it does a shallow clone of the default branch; otherwise it clones and
// checks out revision. The returned cleanup removes the directory (call it even on error paths
// that returned a dir).
func Checkout(ctx context.Context, url, revision string, scope Scope) (tree Tree, cleanup func(), err error) {
	dir, err := os.MkdirTemp("", "draugr-repo-")
	if err != nil {
		return Tree{}, nil, err
	}
	cleanup = func() { _ = os.RemoveAll(dir) }

	// Both optimizations are off when history is wanted. A shallow clone has no history, and a
	// partial one has history whose blobs were never fetched — which walks commits it cannot read
	// and finds nothing in them.
	sparse := len(coneDirs(scope.Paths)) > 0 && !scope.History
	cloneArgs := []string{"clone", "--quiet"}
	if revision == "" && !scope.History {
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
		// Cone mode is what keeps the root files: it materializes every selected directory, the
		// directories above them, and the repository root — which is where the manifests and the
		// scanners' own configuration live.
		args := append([]string{"-C", dir, "sparse-checkout", "set", "--cone"}, coneDirs(scope.Paths)...)
		if err := gitRun(ctx, args...); err != nil {
			cleanup()
			return Tree{}, nil, fmt.Errorf("git sparse-checkout: %w", err)
		}
	}
	if scope.History && len(coneDirs(scope.Paths)) > 0 {
		// Sparse checkout was skipped, so the tree still holds everything. Cut it down the slow
		// way, which produces the same tree.
		if err := prune(dir, scope, true); err != nil {
			cleanup()
			return Tree{}, nil, fmt.Errorf("restrict checkout to paths: %w", err)
		}
	} else if len(scope.Ignore) > 0 {
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
	out, err := exec.CommandContext(ctx, "git", "-C", dir, "rev-parse", "HEAD").Output() // #nosec G204 -- Draugr's own temporary checkout
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
	cmd := exec.CommandContext(ctx, "git", args...) // #nosec G204 -- args are constructed, not shell-interpreted
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
	out, err := exec.CommandContext(ctx, "git", "-C", url, "status", "--porcelain").Output() // #nosec G204 -- the descriptor's own repository path
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

// CheckoutWorkingTree copies a local checkout — including uncommitted work — into a temporary
// directory and scopes it exactly as Checkout does.
//
// A copy rather than the path itself, which is the whole point. Scanning in place would mean a
// tool writing its caches into somebody's repository, and `paths`/`ignore` are applied by deleting
// what is not wanted — against a real checkout that is not scoping, it is data loss.
//
// The file list comes from `git ls-files -co --exclude-standard`: tracked files plus untracked
// ones that are not ignored. That is git's own answer to "what is in this working tree", so a
// build artifact directory or a local .env is left behind for the same reason a commit would leave
// it behind, rather than by a rule Draugr invented.
func CheckoutWorkingTree(ctx context.Context, path string, scope Scope) (Tree, func(), error) {
	if !IsLocalPath(path) {
		return Tree{}, nil, fmt.Errorf("%s is not a local path, so it has no working tree", path)
	}
	dir, err := os.MkdirTemp("", "draugr-worktree-")
	if err != nil {
		return Tree{}, nil, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }

	out, err := exec.CommandContext(ctx, "git", "-C", path, "ls-files", "-co", "--exclude-standard", "-z").Output() // #nosec G204 -- the descriptor's own repository path
	if err != nil {
		cleanup()
		return Tree{}, nil, fmt.Errorf("list working tree of %s: %w", path, err)
	}
	for _, rel := range strings.Split(string(out), "\x00") {
		if rel == "" {
			continue
		}
		if err := copyInto(dir, path, rel); err != nil {
			cleanup()
			return Tree{}, nil, err
		}
	}

	if len(scope.Paths) > 0 || len(scope.Ignore) > 0 {
		if err := prune(dir, scope, len(scope.Paths) > 0); err != nil {
			cleanup()
			return Tree{}, nil, fmt.Errorf("restrict working tree to paths: %w", err)
		}
	}

	t := Tree{Dir: dir, Dirty: UncommittedFiles(ctx, path), WorkingTree: true}
	// The commit the tree sits on, kept plain. Rendering marks it as dirty; storing a "+" in the
	// value would make it something no consumer could compare against a real revision.
	if head, err := exec.CommandContext(ctx, "git", "-C", path, "rev-parse", "HEAD").Output(); err == nil { // #nosec G204 -- the descriptor's own repository path
		t.Revision = strings.TrimSpace(string(head))
	}
	return t, cleanup, nil
}

// copyInto copies one file from a working tree into the temporary copy, creating its parents.
//
// Both ends are checked to stay inside their root. git does not emit paths that escape a
// repository, but this reads a list produced by a subprocess and then writes files from it — the
// one place where being wrong writes outside the temporary directory, so it is checked rather
// than assumed.
func copyInto(dstRoot, srcRoot, rel string) error {
	src, err := containedPath(srcRoot, rel)
	if err != nil {
		return err
	}
	dst, err := containedPath(dstRoot, rel)
	if err != nil {
		return err
	}
	info, err := os.Lstat(src)
	if err != nil {
		// Raced with an edit, or a symlink to nowhere. One missing file is not a reason to refuse
		// to scan the rest of a tree somebody is actively working in.
		return nil //nolint:nilerr // deliberate: a vanished file is not a scan failure
	}
	if !info.Mode().IsRegular() {
		// Directories arrive implicitly, and a symlink copied as a link could point outside the
		// copy — which would put a scanner back in the real checkout.
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
		return err
	}
	data, err := os.ReadFile(src) // #nosec G304 -- checked by containedPath above
	if err != nil {
		return nil //nolint:nilerr // as above
	}
	return os.WriteFile(dst, data, info.Mode().Perm()&0o755) // #nosec G703 -- checked by containedPath above
}

// containedPath joins rel onto root and refuses anything that would land outside it.
func containedPath(root, rel string) (string, error) {
	p := filepath.Join(root, rel)
	inside, err := filepath.Rel(root, p)
	if err != nil || inside == ".." || strings.HasPrefix(inside, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q escapes %s", rel, root)
	}
	return p, nil
}

// RemoteURL returns the canonical remote a local checkout came from, or "" when it has none.
//
// A local path says where a repository sits on one machine; the remote says which repository it
// is. Those are different questions, and only the second belongs in a report, a cache key, or
// anything handed to a third party — the same distinction that keeps credentials out of a
// repository's identity.
//
// Resolving it makes a laptop and a pipeline agree: `draugr scan .` and a CI run against the
// remote become one source at one revision, so they share a cache entry and can be diffed against
// each other. Without it they are two unrelated repositories that happen to hold the same code.
//
// "origin" by convention, then the first remote by name so the answer does not depend on map
// ordering. No remote is not a failure: a repository that exists only on this machine is
// legitimate, and the caller keeps the path.
func RemoteURL(ctx context.Context, path string) string {
	if url := remote(ctx, path, "origin"); url != "" {
		return url
	}
	out, err := exec.CommandContext(ctx, "git", "-C", path, "remote").Output() // #nosec G204 -- the descriptor's own repository path
	if err != nil {
		return ""
	}
	names := strings.Fields(string(out))
	sort.Strings(names)
	for _, n := range names {
		if url := remote(ctx, path, n); url != "" {
			return url
		}
	}
	return ""
}

// remote reads one remote's fetch URL.
func remote(ctx context.Context, path, name string) string {
	out, err := exec.CommandContext(ctx, "git", "-C", path, "remote", "get-url", name).Output() // #nosec G204 -- the descriptor's own repository path
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
