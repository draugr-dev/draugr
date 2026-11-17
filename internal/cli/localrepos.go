package cli

import (
	"context"
	"errors"
	"path"
	"strings"

	"github.com/draugr-dev/draugr/internal/git"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// rootLocalRepositories points each local repository that names a directory inside a work tree at
// the work tree's root, with that directory as its paths.
//
// `url: services/payments`, the `url: .` that `draugr init` writes in a subdirectory, and
// `draugr scan services/payments` all name a directory in a checkout, and git clones a repository,
// not a directory in one. Scoping the root's clone to the directory is the shape a descriptor
// would spell out by hand, so the checkout, the cache identity and the paths in findings all treat
// it as the repository it is.
//
// The descriptor's own paths and ignore patterns were written relative to the directory, so each
// is moved under it. The model is the run's copy and is never written back.
func rootLocalRepositories(ctx context.Context, m *saga.Model) {
	for ci := range m.Components {
		for ri := range m.Components[ci].Repositories {
			r := &m.Components[ci].Repositories[ri]
			root, rel, ok := git.Subdirectory(ctx, r.URL)
			if !ok || rel == "" {
				continue
			}
			r.URL = root
			if len(r.Paths) == 0 {
				r.Paths = []string{rel}
			} else {
				r.Paths = under(rel, r.Paths)
			}
			r.Ignore = under(rel, r.Ignore)
		}
	}
}

// exclusionTrees returns the trees `config.exclude` paths are matched against: the root of each
// repository the descriptor names that is a directory on this machine, the root of its work tree
// where it is in one, since a finding's path is relative to that root. Each once, in the order the
// descriptor names them.
//
// A repository named by a remote URL adds nothing. Its tree exists only inside the scan's own
// checkout, after the descriptor has been accepted, so its exclusions are checked by the scan's
// report instead, which names one that matched nothing.
func exclusionTrees(ctx context.Context, m *saga.Model) []string {
	var out []string
	seen := map[string]bool{}
	for _, c := range m.Components {
		for _, r := range c.Repositories {
			root, _, ok := git.Subdirectory(ctx, r.URL)
			if !ok {
				if !git.IsLocalPath(r.URL) {
					continue
				}
				root = r.URL
			}
			if !seen[root] {
				seen[root] = true
				out = append(out, root)
			}
		}
	}
	return out
}

// checkExclusionLines refuses an exclusion path that names a line in a file of one of the
// descriptor's local repositories, for validate and scan alike.
func checkExclusionLines(ctx context.Context, m *saga.Model) error {
	if m == nil || len(m.Config.Exclude) == 0 {
		return nil
	}
	return errors.Join(m.ExcludeLineErrors(exclusionTrees(ctx, m))...)
}

// under joins each entry to dir, keeping a trailing slash, which marks a directory pattern.
func under(dir string, entries []string) []string {
	if len(entries) == 0 {
		return entries
	}
	out := make([]string, len(entries))
	for i, e := range entries {
		out[i] = path.Join(dir, e)
		if strings.HasSuffix(e, "/") {
			out[i] += "/"
		}
	}
	return out
}
