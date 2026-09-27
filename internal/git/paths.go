package git

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// PathsAt checks that every entry of paths is in the tree a scan of url at revision would read,
// and returns the commit it read. An error naming the missing entries is the one a scan would
// fail with. With no entries it checks that the commit exists, which ResolveRevision takes on trust
// for a full commit name.
//
// The committed tree rather than the working tree, because that is what a scan clones: a directory
// that exists only on disk passes a look at the disk and fails the scan.
//
// A local repository is read in place and costs nothing. A remote is fetched into a temporary
// repository at depth one with no blobs, the trees a sparse checkout reads first and nothing else,
// so a monorepo is checked without being downloaded.
func PathsAt(ctx context.Context, url, revision string, paths []string) (string, error) {
	keep := selected(paths)
	if IsLocalPath(url) {
		commit, err := ResolveRevision(ctx, url, revision)
		if err != nil {
			return "", err
		}
		if len(keep) == 0 {
			return commit, commitIn(ctx, url, commit)
		}
		return commit, pathsIn(ctx, url, commit, keep)
	}

	dir, err := os.MkdirTemp("", "draugr-tree-")
	if err != nil {
		return "", err
	}
	defer func() { _ = os.RemoveAll(dir) }()

	ref := revision
	if ref == "" {
		ref = "HEAD"
	}
	if err := gitRun(ctx, "init", "--quiet", dir); err != nil {
		return "", fmt.Errorf("git init: %w", err)
	}
	// Without paths only the commit is wanted, and tree:0 leaves even the trees behind.
	filter := "--filter=blob:none"
	if len(keep) == 0 {
		filter = "--filter=tree:0"
	}
	if err := gitRun(ctx, "-C", dir, "fetch", "--quiet", "--depth", "1", filter, "--", url, ref); err != nil {
		return "", fmt.Errorf("git fetch %s: %w", ref, err)
	}
	out, err := exec.CommandContext(ctx, "git", "-C", dir, "rev-parse", "FETCH_HEAD").Output() // #nosec G204 -- Draugr's own temporary repository
	if err != nil {
		return "", fmt.Errorf("read the fetched commit: %w", err)
	}
	commit := strings.TrimSpace(string(out))
	return commit, pathsIn(ctx, dir, commit, keep)
}

// commitIn refuses a commit the repository at dir does not hold.
func commitIn(ctx context.Context, dir, commit string) error {
	if err := gitRun(ctx, "-C", dir, "cat-file", "-e", commit+"^{commit}"); err != nil {
		return fmt.Errorf("commit %s: not in the repository", shortRevision(commit))
	}
	return nil
}

// pathsIn refuses an entry the tree at commit does not hold, in the repository at dir.
func pathsIn(ctx context.Context, dir, commit string, keep []string) error {
	missing := missingPaths(keep, func(rel string) bool {
		return gitRun(ctx, "-C", dir, "rev-parse", "--verify", "--quiet", commit+":"+rel) == nil
	})
	if len(missing) == 0 {
		return nil
	}
	return errMissingPaths(missing, commit)
}

// Selected returns the entries of paths a scoped checkout keeps, normalized, or nil for the whole
// repository. `services/web/**` normalizes to `services/web`.
func Selected(paths []string) []string { return selected(paths) }

// ShortRevision abbreviates a full commit to the twelve characters a report shows.
func ShortRevision(rev string) string { return shortRevision(rev) }
