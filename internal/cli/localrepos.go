package cli

import (
	"context"
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
