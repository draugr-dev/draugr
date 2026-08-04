package git

import (
	"context"
	"os"
	"sync"
)

// Pool materialises each distinct checkout once per run and shares it between the scanners that
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
// report rather than a corrupted neighbouring scan.
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
}

// NewPool returns an empty pool. Close it when the run ends.
func NewPool() *Pool { return &Pool{entries: map[string]*entry{}} }

// Checkout returns the shared tree for key, materialising it on first request.
//
// Callers that arrive while the first is still cloning wait for it rather than starting their own.
// A failed checkout is remembered too — five scanners should report one unreachable repository
// once, not attempt it five times over.
//
// The returned cleanup is a no-op: the pool owns the directory until Close.
func (p *Pool) Checkout(ctx context.Context, key string, materialise func(context.Context) (Tree, func(), error)) (Tree, func(), error) {
	p.mu.Lock()
	e, ok := p.entries[key]
	if !ok {
		e = &entry{}
		p.entries[key] = e
	}
	p.mu.Unlock()

	e.once.Do(func() {
		tree, clean, err := materialise(ctx)
		e.tree, e.clean, e.err = tree, clean, err
		if err == nil {
			// Read-only after this point, so a tool that writes into what it is scanning fails
			// visibly instead of changing what the next scanner reads.
			freeze(tree.Dir)
		}
	})
	if e.err != nil {
		return Tree{}, func() {}, e.err
	}
	return e.tree, func() {}, nil
}

// Close removes every checkout the pool materialised.
func (p *Pool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, e := range p.entries {
		if e.clean == nil {
			continue
		}
		// Undo the freeze first: a directory without write permission cannot have its entries
		// removed, so cleanup would silently leave the tree on disk.
		thaw(e.tree.Dir)
		e.clean()
	}
	p.entries = map[string]*entry{}
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
func filepathWalk(dir string, fn func(path string, isDir bool)) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		path := dir + string(os.PathSeparator) + e.Name()
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
// interface — public API, and one every third-party scanner would have to accept for a
// housekeeping detail it has no opinion about. A scanner that is handed no pool clones for
// itself, which is what makes a scanner runnable on its own and in a test.
func WithPool(ctx context.Context, p *Pool) context.Context {
	return context.WithValue(ctx, poolKey{}, p)
}

// PoolFrom returns the run's pool, or nil.
func PoolFrom(ctx context.Context) *Pool {
	p, _ := ctx.Value(poolKey{}).(*Pool)
	return p
}
