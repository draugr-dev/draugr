package sbom

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/git"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
)

func TestGenerateReadsTheRunsSharedCheckout(t *testing.T) {
	// A scanner has already checked the repository out under the run's pool. The SBOM reads that
	// tree rather than cloning the repository a further time.
	dir, err := os.MkdirTemp("", "sbom-pool-")
	if err != nil {
		t.Fatal(err)
	}
	pool := git.NewPool()
	defer pool.Close()
	ctx := git.WithPool(context.Background(), pool)
	target := plugin.RepositoryTarget{URL: "/src/web", Revision: "abc"}
	key := git.Key(target.URL, target.Revision, false, git.Scope{})
	_, release, err := pool.Checkout(ctx, key, func(context.Context) (git.Tree, func(), error) {
		return git.Tree{Dir: dir}, func() { _ = os.RemoveAll(dir) }, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer release()

	r := &recorder{out: []byte(`{}`)}
	if _, err := newTestGenerator(r).Generate(ctx, "web", target, saga.SBOMSPDXJSON); err != nil {
		t.Fatal(err)
	}
	if r.checkout != 0 {
		t.Errorf("cloned %d times with the run's checkout already on disk", r.checkout)
	}
	if !strings.Contains(strings.Join(r.argv, " "), "dir:"+dir) {
		t.Errorf("syft read %v, want the shared checkout %s", r.argv, dir)
	}
}

func TestGenerateUnderWorkingTreeReadsTheWorkingTree(t *testing.T) {
	// Under --working-tree every scanner reads the repository as it is on disk, and the inventory
	// has to list the same files, not the commit underneath them.
	r := &recorder{out: []byte(`{}`)}
	g := newTestGenerator(r)
	var copied string
	g.workingTree = func(_ context.Context, path string, _ git.Scope) (git.Tree, func(), error) {
		copied = path
		return git.Tree{Dir: "/tmp/worktree", WorkingTree: true}, func() {}, nil
	}
	target := plugin.RepositoryTarget{URL: "/src/web", WorkingTree: true}
	if _, err := g.Generate(context.Background(), "web", target, saga.SBOMSPDXJSON); err != nil {
		t.Fatal(err)
	}
	if copied != "/src/web" || r.checkout != 0 {
		t.Errorf("working tree copied from %q, %d clones; want the working tree of /src/web and no clone", copied, r.checkout)
	}
	if !strings.Contains(strings.Join(r.argv, " "), "dir:/tmp/worktree") {
		t.Errorf("syft read %v, want the working tree copy", r.argv)
	}
}
