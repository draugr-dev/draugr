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
	// Five controls over one repository is one checkout. Before this, it was five clones, five
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
	if _, err := os.ReadFile(filepath.Join(tree.Dir, "f.txt")); err != nil {
		t.Errorf("the shared checkout is not readable: %v", err)
	}
}

// A checkout holds whatever symbolic links its repository commits, pointing wherever the
// repository says. Freezing and thawing the tree must change the modes of what is in it and of
// nothing a link reaches: a file outside the checkout keeps its mode, and a directory a link names
// stays one a scanner can enter.
func TestPoolNeverChangesWhatASymlinkPointsAt(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(outside, []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}

	p := NewPool()
	tree, _, err := p.Checkout(context.Background(), "repo@rev", func(context.Context) (Tree, func(), error) {
		tree, clean, err := fakeTree(t)
		if err != nil {
			return tree, clean, err
		}
		linked := filepath.Join(tree.Dir, "gci")
		if err := os.Mkdir(linked, 0o750); err != nil {
			return tree, clean, err
		}
		if err := os.WriteFile(filepath.Join(linked, "OWNERS"), []byte("x"), 0o600); err != nil {
			return tree, clean, err
		}
		for link, target := range map[string]string{"key": outside, "ubuntu": "gci"} {
			if err := os.Symlink(target, filepath.Join(tree.Dir, link)); err != nil {
				return tree, clean, err
			}
		}
		return tree, clean, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// Frozen: the file outside keeps its mode, and the directory is entered through its link.
	if info, err := os.Stat(outside); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("freezing the checkout changed a file outside it through a link: %v, %v", info.Mode(), err)
	}
	if _, err := os.ReadFile(filepath.Join(tree.Dir, "ubuntu", "OWNERS")); err != nil {
		t.Errorf("a directory reached through a link cannot be entered while frozen: %v", err)
	}

	p.Close()

	// Thawed and removed: still the same mode outside, and nothing left behind.
	if info, err := os.Stat(outside); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("thawing the checkout changed a file outside it through a link: %v, %v", info.Mode(), err)
	}
	if _, err := os.Stat(tree.Dir); !os.IsNotExist(err) {
		t.Errorf("a checkout holding links survived Close: %v", err)
	}
}

func TestPoolCloseRemovesEvenAFrozenTree(t *testing.T) {
	// A directory without write permission cannot have its entries removed, so cleanup has to
	// undo the freeze first. Otherwise every run leaves its checkouts on disk.
	p := NewPool()
	tree, _, err := p.Checkout(context.Background(), "repo@rev", func(context.Context) (Tree, func(), error) { return fakeTree(t) })
	if err != nil {
		t.Fatal(err)
	}
	p.Close()
	if _, err := os.Stat(tree.Dir); !os.IsNotExist(err) {
		t.Errorf("the checkout survived Close: %v", err)
	}
	// Closing twice is not an error, a deferred Close after an early return should be safe.
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

// exists reports whether a checkout is still on disk.
func exists(dir string) bool {
	_, err := os.Stat(dir)
	return err == nil
}

func TestPoolRemovesACheckoutWhenItsLastDeclaredUseEnds(t *testing.T) {
	// Two scanners will read one checkout. The first finishing must not take it from the second,
	// and the second finishing must not leave it on disk for the rest of the run.
	p := NewPool()
	defer p.Close()
	p.Expect("repo@rev")
	p.Expect("repo@rev")

	tree, release, err := p.Checkout(context.Background(), "repo@rev", func(context.Context) (Tree, func(), error) { return fakeTree(t) })
	if err != nil {
		t.Fatal(err)
	}
	release()
	p.Done("repo@rev")
	if !exists(tree.Dir) {
		t.Fatal("removed while a second declared use had not ended")
	}
	again, release2, err := p.Checkout(context.Background(), "repo@rev", func(context.Context) (Tree, func(), error) {
		t.Error("materialized again while the first checkout was still declared")
		return fakeTree(t)
	})
	if err != nil {
		t.Fatal(err)
	}
	if again.Dir != tree.Dir {
		t.Error("the second use got a different checkout")
	}
	release2()
	p.Done("repo@rev")
	if exists(tree.Dir) {
		t.Error("still on disk after its last declared use ended")
	}
}

func TestPoolNeverRemovesATreeSomebodyIsReading(t *testing.T) {
	// The declared uses can end before a reader lets go, when the reader was not one of them. The
	// tree goes when the reader releases it, not under it.
	p := NewPool()
	defer p.Close()
	p.Expect("repo@rev")

	tree, release, err := p.Checkout(context.Background(), "repo@rev", func(context.Context) (Tree, func(), error) { return fakeTree(t) })
	if err != nil {
		t.Fatal(err)
	}
	p.Done("repo@rev")
	if !exists(tree.Dir) {
		t.Fatal("removed while a caller still held it")
	}
	release()
	release() // a second call is harmless
	if exists(tree.Dir) {
		t.Error("still on disk once nobody declared or held it")
	}
}

func TestPoolKeepsAnUndeclaredCheckoutUntilClose(t *testing.T) {
	// Without a declaration the pool cannot tell the last reader from the first of several, so it
	// keeps the tree for the run, as it always did.
	p := NewPool()
	tree, release, err := p.Checkout(context.Background(), "repo@rev", func(context.Context) (Tree, func(), error) { return fakeTree(t) })
	if err != nil {
		t.Fatal(err)
	}
	release()
	p.Done("repo@rev") // nothing was declared, so nothing ends
	if !exists(tree.Dir) {
		t.Fatal("an undeclared checkout was removed before Close")
	}
	p.Close()
	if exists(tree.Dir) {
		t.Error("Close left the checkout on disk")
	}
}

func TestPoolMaterializesAgainAfterRemoving(t *testing.T) {
	// A reader that arrives after the declared ones have gone gets a tree of its own rather than a
	// path that no longer exists.
	p := NewPool()
	defer p.Close()
	p.Expect("repo@rev")
	first, release, err := p.Checkout(context.Background(), "repo@rev", func(context.Context) (Tree, func(), error) { return fakeTree(t) })
	if err != nil {
		t.Fatal(err)
	}
	release()
	p.Done("repo@rev")

	second, release, err := p.Checkout(context.Background(), "repo@rev", func(context.Context) (Tree, func(), error) { return fakeTree(t) })
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if second.Dir == first.Dir || !exists(second.Dir) {
		t.Errorf("got %s after %s was removed, want a new checkout on disk", second.Dir, first.Dir)
	}
}

func TestPoolEndsADeclaredUseThatNeverCheckedOut(t *testing.T) {
	// A job answered from the cache declares a use and never reads the tree. Ending it removes
	// nothing and leaves nothing behind for a reader that comes later.
	p := NewPool()
	defer p.Close()
	p.Expect("repo@rev")
	p.Done("repo@rev")
	p.Done("repo@rev") // more ends than uses is ignored

	var calls atomic.Int32
	_, release, err := p.Checkout(context.Background(), "repo@rev", func(context.Context) (Tree, func(), error) {
		calls.Add(1)
		return fakeTree(t)
	})
	if err != nil {
		t.Fatal(err)
	}
	release()
	if calls.Load() != 1 {
		t.Errorf("materialized %d times, want 1", calls.Load())
	}
}

func TestPoolReleasesAFailedCheckout(t *testing.T) {
	p := NewPool()
	defer p.Close()
	p.Expect("repo@rev")
	if _, _, err := p.Checkout(context.Background(), "repo@rev", func(context.Context) (Tree, func(), error) {
		return Tree{}, nil, errors.New("no such host")
	}); err == nil {
		t.Fatal("expected the failure to be reported")
	}
	p.Done("repo@rev")
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.entries) != 0 {
		t.Errorf("entries left after the only declared use ended: %d", len(p.entries))
	}
}

func TestANilPoolDeclaresNothing(_ *testing.T) {
	var p *Pool
	p.Expect("repo@rev")
	p.Done("repo@rev")
}

func TestKeySeparatesWhatChangesTheTree(t *testing.T) {
	base := Key("/src/web", "main", false, Scope{})
	for name, other := range map[string]string{
		"another path with the same remote": Key("/src/web-copy", "main", false, Scope{}),
		"another revision":                  Key("/src/web", "v1", false, Scope{}),
		"the working tree":                  Key("/src/web", "main", true, Scope{}),
		"history":                           Key("/src/web", "main", false, Scope{History: true}),
		"paths":                             Key("/src/web", "main", false, Scope{Paths: []string{"api"}}),
		"ignore":                            Key("/src/web", "main", false, Scope{Ignore: []string{"vendor"}}),
	} {
		if other == base {
			t.Errorf("%s shares a key with the plain checkout: %s", name, base)
		}
	}
	if Key("/src/web", "main", false, Scope{}) != base {
		t.Error("the same checkout spelled two keys")
	}
}
