// Package git provides repository checkouts for scanners that operate on source trees.
package git

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// Checkout clones url into a fresh temporary directory, materialising only what scope allows.
// With an empty revision it does a shallow clone of the default branch; otherwise it clones and
// checks out revision. The returned cleanup removes the directory (call it even on error paths
// that returned a dir).
func Checkout(ctx context.Context, url, revision string, scope Scope) (dir string, cleanup func(), err error) {
	dir, err = os.MkdirTemp("", "draugr-repo-")
	if err != nil {
		return "", nil, err
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
			return "", nil, fmt.Errorf("git clone: %w", err)
		}
		// Partial clone needs the server's cooperation and sparse checkout needs a recent git.
		// Neither is a reason to refuse to scan: fall back to a full clone and cut the tree down
		// afterwards, which produces the same tree by a slower route.
		if err := retryPlain(ctx, dir, url, revision); err != nil {
			cleanup()
			return "", nil, err
		}
		if err := prune(dir, scope, true); err != nil {
			cleanup()
			return "", nil, fmt.Errorf("restrict checkout to paths: %w", err)
		}
		return dir, cleanup, nil
	}

	if revision != "" {
		if err := gitRun(ctx, "-C", dir, "checkout", "--quiet", revision); err != nil {
			cleanup()
			return "", nil, fmt.Errorf("git checkout %q: %w", revision, err)
		}
	}
	if sparse {
		// Cone mode is what keeps the root files: it materialises every selected directory, the
		// directories above them, and the repository root — which is where the manifests and the
		// scanners' own configuration live.
		args := append([]string{"-C", dir, "sparse-checkout", "set", "--cone"}, coneDirs(scope.Paths)...)
		if err := gitRun(ctx, args...); err != nil {
			cleanup()
			return "", nil, fmt.Errorf("git sparse-checkout: %w", err)
		}
	}
	if len(scope.Ignore) > 0 {
		if err := prune(dir, scope, false); err != nil {
			cleanup()
			return "", nil, fmt.Errorf("apply ignore: %w", err)
		}
	}
	return dir, cleanup, nil
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
