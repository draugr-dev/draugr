// Package sagafetch fetches Saga fragments held in other repositories.
//
// It exists because pkg/saga cannot: fetching means git, git lives in internal/, and pkg/ does
// not import internal/. So pkg/saga declares the seam (saga.Fetcher) and this supplies something
// that can fill it — the same arrangement as sbom.Generator.
package sagafetch

import (
	"context"
	"fmt"
	"sync"

	"github.com/draugr-dev/draugr/internal/git"
	"github.com/draugr-dev/draugr/internal/netpolicy"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// Fetcher materializes remote fragment references, reusing one checkout per repository and
// revision within a run.
//
// Sharing matters more here than it looks. A monorepo's descriptor may name several fragments
// from one platform repository, and each is a `path:` into the same tree — cloning once and
// expanding every pattern against it is the difference between one clone and five.
type Fetcher struct {
	pool *git.Pool
	mu   sync.Mutex
	// resolved remembers the commit each key turned out to be, so the second reference to a
	// repository reports the same commit as the first even though it did not clone.
	resolved map[string]string
	ctx      context.Context
}

// New returns a Fetcher that clones with git. Close releases every checkout it made.
func New(ctx context.Context) *Fetcher {
	return &Fetcher{pool: git.NewPool(), resolved: map[string]string{}, ctx: ctx}
}

// Close removes the checkouts this Fetcher made.
func (f *Fetcher) Close() { f.pool.Close() }

var _ saga.Fetcher = (*Fetcher)(nil)

// Fetch returns a directory holding url at revision, and the commit it resolved to.
//
// Offline is refused rather than skipped. A fragment that cannot be fetched is scope the
// descriptor claims and the run would not have — and a scan that quietly covers less than its
// descriptor says is the failure this tool exists to prevent, so it is worth failing the run.
func (f *Fetcher) Fetch(url, revision string) (string, string, func(), error) {
	if netpolicy.Offline() {
		return "", "", func() {}, fmt.Errorf(
			"cannot fetch the fragment at %s@%s while offline — resolve it on a connected machine "+
				"and scan the flattened descriptor (`draugr validate <saga> --resolved`), or drop "+
				"the entry", url, revision)
	}

	key := url + "@" + revision
	tree, cleanup, err := f.pool.Checkout(f.ctx, key, func(ctx context.Context) (git.Tree, func(), error) {
		// No scope: a fragment names its files with a pattern, and pruning the tree first would
		// hide the ones a later pattern in the same descriptor wants.
		return git.Checkout(ctx, url, revision, git.Scope{})
	})
	if err != nil {
		return "", "", func() {}, err
	}

	f.mu.Lock()
	if tree.Revision != "" {
		f.resolved[key] = tree.Revision
	}
	sha := f.resolved[key]
	f.mu.Unlock()

	return tree.Dir, sha, cleanup, nil
}
