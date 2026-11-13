package git

import (
	"context"
	"fmt"
	"os"
	"sync"
)

// Pool materializes each distinct checkout once per run and shares it between the scanners that
// asked for it.
//
// Every repository scanner checks out for itself, so a five-control scan of one repository used to
// clone it five times. For a local path that costs little; for a remote it is five network fetches,
// and the cost grows with the repository.
//
// The stronger reason is agreement. Independent clones of a moving branch can resolve to different
// commits, so two controls could report against different code while the report named one
// revision. One checkout per run removes the possibility rather than describing it.
//
// The shared tree is made **read-only**. Every scanner Draugr ships only reads what it scans, but
// "only reads" is a property of each tool, and sharing a directory would quietly make one
// scanner's write another's input. A tool that writes now fails where it writes, which is a bug
// report rather than a corrupted neighboring scan.
//
// A checkout is removed when the last use the run declared for it has ended, so a run's disk holds
// the checkouts still in use rather than every one it made. Where the temporary directory is a
// tmpfs, that disk is memory.
type Pool struct {
	mu      sync.Mutex
	entries map[string]*entry
}

type entry struct {
	once sync.Once
	tree Tree
	err  error
	// clean removes this checkout. Held by the pool rather than the caller: several scanners share
	// the directory, so the last one to finish is not the one that knows nobody else needs it.
	clean func()
	// declared is set once a use of this key has been declared with Expect. Only a declared key
	// is removed before Close: without a declaration the pool cannot tell the last user from the
	// first of several still to come.
	declared bool
	// expected counts the declared uses that have not ended.
	expected int
	// inUse counts callers between Checkout and the release it returned. A tree is never removed
	// under one of them, declared or not.
	inUse int
}

// NewPool returns an empty pool. Close it when the run ends.
//
// The first pool a process makes also removes what dead runs left in the temporary directory, so
// a run killed for memory does not leave its checkouts on disk for good.
func NewPool() *Pool {
	sweepOnce.Do(func() { SweepStale(os.TempDir()) })
	return &Pool{entries: map[string]*entry{}}
}

var sweepOnce sync.Once

// Key names one checkout: what is fetched, at which revision, whether it is the working tree, and
// what of it is kept. Every caller sharing a pool spells its keys with this, so the use the engine
// declares and the checkout a scanner asks for are the same entry.
//
// The URL rather than the target's identity, because the identity names a repository by its
// remote, and two local paths with one remote are two different trees on disk.
func Key(url, revision string, workingTree bool, scope Scope) string {
	return fmt.Sprintf("%s@%s worktree=%t history=%t paths=%q ignore=%q",
		url, revision, workingTree, scope.History, scope.Paths, scope.Ignore)
}

// Expect declares one use of key that has not ended yet. Once every declared use has ended with
// Done and no caller holds the tree, the checkout is removed. A key nobody declared stays until
// Close. Safe on a nil pool, which declares nothing.
func (p *Pool) Expect(key string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	e := p.entryLocked(key)
	e.declared = true
	e.expected++
}

// Done ends one use declared with Expect, and removes the checkout if it was the last.
func (p *Pool) Done(key string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	e, ok := p.entries[key]
	if !ok || e.expected == 0 {
		p.mu.Unlock()
		return
	}
	e.expected--
	gone := p.detachIfUnusedLocked(key, e)
	p.mu.Unlock()
	if gone {
		remove(e)
	}
}

// Checkout returns the shared tree for key, materializing it on first request, and a release to
// call when the caller has finished reading it.
//
// Callers that arrive while the first is still cloning wait for it rather than starting their own.
// A failed checkout is remembered too. Five scanners should report one unreachable repository once,
// not attempt it five times over.
func (p *Pool) Checkout(ctx context.Context, key string, materialize func(context.Context) (Tree, func(), error)) (Tree, func(), error) {
	p.mu.Lock()
	e := p.entryLocked(key)
	e.inUse++
	p.mu.Unlock()

	var released sync.Once
	release := func() {
		released.Do(func() {
			p.mu.Lock()
			e.inUse--
			gone := p.detachIfUnusedLocked(key, e)
			p.mu.Unlock()
			if gone {
				remove(e)
			}
		})
	}

	e.once.Do(func() {
		tree, clean, err := materialize(ctx)
		e.tree, e.clean, e.err = tree, clean, err
		if err == nil {
			// Read-only after this point, so a tool that writes into what it is scanning fails
			// visibly instead of changing what the next scanner reads.
			freeze(tree.Dir)
		}
	})
	if e.err != nil {
		release()
		return Tree{}, func() {}, e.err
	}
	return e.tree, release, nil
}

// entryLocked returns key's entry, adding an empty one. Called with p.mu held.
func (p *Pool) entryLocked(key string) *entry {
	e, ok := p.entries[key]
	if !ok {
		e = &entry{}
		p.entries[key] = e
	}
	return e
}

// detachIfUnusedLocked takes e out of the pool when its declared uses have all ended and nobody
// holds it, and reports whether it did. The caller removes it after letting go of p.mu, because
// removing a tree is slow and the other scanners should not wait on it. A later Checkout of the
// same key materializes a new one. Called with p.mu held.
func (p *Pool) detachIfUnusedLocked(key string, e *entry) bool {
	if !e.declared || e.expected > 0 || e.inUse > 0 || p.entries[key] != e {
		return false
	}
	delete(p.entries, key)
	return true
}

// Close removes every checkout the pool still holds.
func (p *Pool) Close() {
	p.mu.Lock()
	entries := p.entries
	p.entries = map[string]*entry{}
	p.mu.Unlock()
	for _, e := range entries {
		remove(e)
	}
}

// remove deletes an entry's checkout. Nobody can reach the entry any longer, so its once has
// either run or never will, and nothing else touches its fields.
func remove(e *entry) {
	if e.clean == nil {
		return
	}
	// Undo the freeze first: a directory without write permission cannot have its entries
	// removed, so cleanup would silently leave the tree on disk.
	thaw(e.tree.Dir)
	e.clean()
}

// freeze makes a tree read-only, best effort.
func freeze(dir string) { chmodTree(dir, 0o555, 0o444) }

// thaw restores write permission so the tree can be removed.
func thaw(dir string) { chmodTree(dir, 0o755, 0o644) }

func chmodTree(dir string, dirMode, fileMode os.FileMode) {
	if dir == "" {
		return
	}
	// Best effort throughout: a permission Draugr cannot set is not a reason to fail a scan, and
	// the scan is the thing the user asked for.
	_ = filepathWalk(dir, func(path string, isDir bool) {
		if isDir {
			_ = os.Chmod(path, dirMode)
			return
		}
		_ = os.Chmod(path, fileMode)
	})
}

// filepathWalk visits dir and everything under it, deepest first so a directory's permissions are
// changed only after its children have been.
//
// A symbolic link is never visited. os.Chmod follows one, so changing a link's mode changes its
// target's, and the target is wherever the scanned repository points it: a file outside the
// checkout that the scanning user owns, or a directory inside it, which a file mode leaves
// untraversable. The link's own mode means nothing on the systems Draugr runs on, so skipping it
// loses nothing.
func filepathWalk(dir string, fn func(path string, isDir bool)) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		path := dir + string(os.PathSeparator) + e.Name()
		if e.Type()&os.ModeSymlink != 0 {
			continue
		}
		if e.IsDir() {
			_ = filepathWalk(path, fn)
			fn(path, true)
			continue
		}
		fn(path, false)
	}
	fn(dir, true)
	return nil
}

// poolKey is the context key under which a run's Pool travels.
type poolKey struct{}

// WithPool returns a context carrying p, so the scanners a run drives share its checkouts.
//
// Context rather than a parameter because the alternative is a new argument on the Scanner
// interface, public API, and one every third-party scanner would have to accept for a housekeeping
// detail it has no opinion about. A scanner that is handed no pool clones for itself, which is what
// makes a scanner runnable on its own and in a test.
func WithPool(ctx context.Context, p *Pool) context.Context {
	return context.WithValue(ctx, poolKey{}, p)
}

// PoolFrom returns the run's pool, or nil.
func PoolFrom(ctx context.Context) *Pool {
	p, _ := ctx.Value(poolKey{}).(*Pool)
	return p
}
