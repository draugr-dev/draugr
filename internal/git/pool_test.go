package git

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
)

// fakeTree stands in for a checkout: a directory with a file in it, and a cleanup.
func fakeTree(t *testing.T) (Tree, func(), error) {
	t.Helper()
	// Not t.TempDir(): the pool makes the tree read-only, and t.TempDir's own cleanup would fail
	// to remove it and fail the test for a reason that has nothing to do with the test.
	dir, err := os.MkdirTemp("", "pool-")
	if err != nil {
		return Tree{}, nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, "f.txt"), []byte("x"), 0o600); err != nil {
		return Tree{}, nil, err
	}
	return Tree{Dir: dir, Revision: "abc"}, func() { _ = os.RemoveAll(dir) }, nil
}

func TestPoolMaterializesOncePerKey(t *testing.T) {
	// Five controls over one repository is one checkout. Before this, it was five clones — five
	// network fetches for a remote, and five chances to resolve a moving branch differently.
	p := NewPool()
	defer p.Close()

	var calls atomic.Int32
	make1 := func(context.Context) (Tree, func(), error) {
		calls.Add(1)
		return fakeTree(t)
	}
	for range 5 {
		if _, _, err := p.Checkout(context.Background(), "repo@rev", make1); err != nil {
			t.Fatal(err)
		}
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("materialized %d times, want 1", n)
	}
}

func TestPoolMaterializesOncePerKeyUnderConcurrency(t *testing.T) {
	// Scanners run concurrently, so the second caller usually arrives while the first is still
	// cloning. Without single-flight the check above would pass and the real thing would not.
	p := NewPool()
	defer p.Close()

	var calls atomic.Int32
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, _ = p.Checkout(context.Background(), "repo@rev", func(context.Context) (Tree, func(), error) {
				calls.Add(1)
				dir, err := os.MkdirTemp("", "pool-")
				if err != nil {
					return Tree{}, nil, err
				}
				return Tree{Dir: dir}, func() { _ = os.RemoveAll(dir) }, nil
			})
		}()
	}
	wg.Wait()
	if n := calls.Load(); n != 1 {
		t.Errorf("materialized %d times under concurrency, want 1", n)
	}
}

func TestPoolKeepsDistinctKeysApart(t *testing.T) {
	p := NewPool()
	defer p.Close()
	a, _, err := p.Checkout(context.Background(), "repo@one", func(context.Context) (Tree, func(), error) { return fakeTree(t) })
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := p.Checkout(context.Background(), "repo@two", func(context.Context) (Tree, func(), error) { return fakeTree(t) })
	if err != nil {
		t.Fatal(err)
	}
	if a.Dir == b.Dir {
		t.Error("two revisions shared one checkout")
	}
}

func TestPoolRemembersAFailure(t *testing.T) {
	// Five scanners should report one unreachable repository once, not attempt it five times and
	// produce five copies of the same error.
	p := NewPool()
	defer p.Close()

	var calls atomic.Int32
	fail := func(context.Context) (Tree, func(), error) {
		calls.Add(1)
		return Tree{}, nil, errors.New("no such host")
	}
	for range 3 {
		if _, _, err := p.Checkout(context.Background(), "repo@rev", fail); err == nil {
			t.Fatal("expected the failure to be reported")
		}
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("retried %d times, want 1", n)
	}
}

func TestPoolSharedTreeIsReadOnly(t *testing.T) {
	// Every scanner Draugr ships only reads what it scans, but that is a property of each tool.
	// Sharing a directory would make one scanner's write another scanner's input, so a tool that
	// writes fails where it writes instead of corrupting a neighboring scan.
	p := NewPool()
	defer p.Close()

	tree, _, err := p.Checkout(context.Background(), "repo@rev", func(context.Context) (Tree, func(), error) { return fakeTree(t) })
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tree.Dir, "written.txt"), []byte("x"), 0o600); err == nil {
		t.Error("a scanner could write into the shared checkout")
	}
	if err := os.WriteFile(filepath.Join(tree.Dir, "f.txt"), []byte("changed"), 0o600); err == nil {
		t.Error("a scanner could overwrite a file another scanner is reading")
	}
	// Still readable, which is the whole point of having it.
	if _, err := os.ReadFile(filepath.Join(tree.Dir, "f.txt")); err != nil { //nolint:gosec // the test's own temp dir
		t.Errorf("the shared checkout is not readable: %v", err)
	}
}

func TestPoolCloseRemovesEvenAFrozenTree(t *testing.T) {
	// A directory without write permission cannot have its entries removed, so cleanup has to
	// undo the freeze first — otherwise every run leaves its checkouts on disk.
	p := NewPool()
	tree, _, err := p.Checkout(context.Background(), "repo@rev", func(context.Context) (Tree, func(), error) { return fakeTree(t) })
	if err != nil {
		t.Fatal(err)
	}
	p.Close()
	if _, err := os.Stat(tree.Dir); !os.IsNotExist(err) {
		t.Errorf("the checkout survived Close: %v", err)
	}
	// Closing twice is not an error — a deferred Close after an early return should be safe.
	p.Close()
}

func TestPoolFromAContextWithout(t *testing.T) {
	// A scanner used directly, or in a test, clones for itself as it always did.
	if PoolFrom(context.Background()) != nil {
		t.Error("a bare context reported a pool")
	}
	p := NewPool()
	defer p.Close()
	if PoolFrom(WithPool(context.Background(), p)) != p {
		t.Error("the pool did not survive the context")
	}
}
