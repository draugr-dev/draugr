// Package git provides repository checkouts for scanners that operate on source trees.
package git

import (
	"context"
	"fmt"
	"os"
	"os/exec"
)

// Checkout clones url into a fresh temporary directory. With an empty revision it does a
// shallow clone of the default branch; otherwise it clones and checks out revision. The
// returned cleanup removes the directory (call it even on error paths that returned a dir).
func Checkout(ctx context.Context, url, revision string) (dir string, cleanup func(), err error) {
	dir, err = os.MkdirTemp("", "draugr-repo-")
	if err != nil {
		return "", nil, err
	}
	cleanup = func() { _ = os.RemoveAll(dir) }

	cloneArgs := []string{"clone", "--quiet"}
	if revision == "" {
		cloneArgs = append(cloneArgs, "--depth", "1")
	}
	cloneArgs = append(cloneArgs, url, dir)
	if err := gitRun(ctx, cloneArgs...); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("git clone: %w", err)
	}

	if revision != "" {
		if err := gitRun(ctx, "-C", dir, "checkout", "--quiet", revision); err != nil {
			cleanup()
			return "", nil, fmt.Errorf("git checkout %q: %w", revision, err)
		}
	}
	return dir, cleanup, nil
}

func gitRun(ctx context.Context, args ...string) error {
	cmd := exec.CommandContext(ctx, "git", args...) //nolint:gosec // args are constructed, not shell-interpreted
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%w: %s", err, out)
	}
	return nil
}
