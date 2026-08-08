package git

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"

	"github.com/draugr-dev/draugr/pkg/saga"
)

// scopedRepo builds a repository shaped like the monorepo the scope exists for: manifests and
// tool configuration at the root, two services, and a vendored tree nobody wants scanned.
func scopedRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	files := []string{
		"go.mod", ".trivyignore", "Dockerfile",
		"services/web/main.go", "services/web/testdata/fixture.go",
		"services/api/main.go",
		"vendor/lib/lib.go",
	}
	for _, f := range files {
		p := filepath.Join(dir, filepath.FromSlash(f))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("package x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, args := range [][]string{
		{"init", "-q", "-b", "main"}, {"add", "-A"},
		{"-c", "user.email=t@example.test", "-c", "user.name=t", "commit", "-q", "-m", "init"},
	} {
		//nolint:gosec // a fixture repository in the test's own temp dir
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	return dir
}

// tree lists the repository-relative files in dir, ignoring git's own metadata.
func tree(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	err := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		rel = filepath.ToSlash(rel)
		if len(rel) >= 5 && rel[:5] == ".git/" {
			return nil
		}
		out = append(out, rel)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(out)
	return out
}

func TestCheckoutPathsKeepsTheRootAndTheSelectedSubtree(t *testing.T) {
	// The reason paths has to keep the root: go.mod, .trivyignore and the Dockerfile are how a
	// scanner knows what it is looking at. Without them Trivy finds no dependencies to check and
	// reports nothing, which is indistinguishable from a repository that has no vulnerabilities.
	co, cleanup, err := Checkout(context.Background(), scopedRepo(t), "",
		Scope{Paths: []string{"services/web"}})
	if err != nil {
		t.Fatalf("checkout: %v", err)
	}
	dir := co.Dir
	defer cleanup()

	got := tree(t, dir)
	for _, want := range []string{"go.mod", ".trivyignore", "Dockerfile", "services/web/main.go"} {
		if !slices.Contains(got, want) {
			t.Errorf("missing %q from the scoped checkout: %v", want, got)
		}
	}
	for _, unwanted := range []string{"services/api/main.go", "vendor/lib/lib.go"} {
		if slices.Contains(got, unwanted) {
			t.Errorf("%q should not have been checked out: %v", unwanted, got)
		}
	}
}

func TestCheckoutAcceptsAGlobSuffixOnPaths(t *testing.T) {
	// `services/web/**` is what the example descriptor taught for as long as the field did
	// nothing. Rejecting it now would break descriptors that were written in good faith.
	co, cleanup, err := Checkout(context.Background(), scopedRepo(t), "",
		Scope{Paths: []string{"services/web/**"}})
	if err != nil {
		t.Fatalf("checkout: %v", err)
	}
	dir := co.Dir
	defer cleanup()
	if got := tree(t, dir); !slices.Contains(got, "services/web/main.go") ||
		slices.Contains(got, "services/api/main.go") {
		t.Errorf("glob suffix should scope the same as the bare directory: %v", got)
	}
}

func TestCheckoutIgnoreRemovesMatchingPaths(t *testing.T) {
	co, cleanup, err := Checkout(context.Background(), scopedRepo(t), "",
		Scope{Ignore: []string{"vendor/", "**/testdata/**"}})
	if err != nil {
		t.Fatalf("checkout: %v", err)
	}
	dir := co.Dir
	defer cleanup()

	got := tree(t, dir)
	for _, unwanted := range []string{"vendor/lib/lib.go", "services/web/testdata/fixture.go"} {
		if slices.Contains(got, unwanted) {
			t.Errorf("%q should have been ignored: %v", unwanted, got)
		}
	}
	for _, want := range []string{"go.mod", "services/web/main.go", "services/api/main.go"} {
		if !slices.Contains(got, want) {
			t.Errorf("missing %q — ignore took too much: %v", want, got)
		}
	}
}

func TestCheckoutIgnoreAppliesInsidePaths(t *testing.T) {
	// Ignore runs last so it can carve out of a selected subtree — the common shape being "this
	// service, but not its fixtures".
	co, cleanup, err := Checkout(context.Background(), scopedRepo(t), "",
		Scope{Paths: []string{"services/web"}, Ignore: []string{"services/web/testdata/"}})
	if err != nil {
		t.Fatalf("checkout: %v", err)
	}
	dir := co.Dir
	defer cleanup()

	got := tree(t, dir)
	if slices.Contains(got, "services/web/testdata/fixture.go") {
		t.Errorf("ignore should apply within paths: %v", got)
	}
	if !slices.Contains(got, "services/web/main.go") {
		t.Errorf("the rest of the subtree should survive: %v", got)
	}
}

func TestCheckoutUnscopedTakesEverything(t *testing.T) {
	co, cleanup, err := Checkout(context.Background(), scopedRepo(t), "", Scope{})
	if err != nil {
		t.Fatalf("checkout: %v", err)
	}
	dir := co.Dir
	defer cleanup()
	if got := len(tree(t, dir)); got != 7 {
		t.Errorf("files = %d, want all 7: %v", got, tree(t, dir))
	}
}

func TestScopeKeyDistinguishesSubtrees(t *testing.T) {
	// The bug behind the identity change: two components on different subtrees of one repository
	// shared a cache entry, so one scan ran and both received its findings.
	a := Scope{Paths: []string{"services/web"}}
	b := Scope{Paths: []string{"services/api"}}
	if a.Key() == b.Key() {
		t.Errorf("different subtrees must not share a key: %q", a.Key())
	}
	if (Scope{}).Key() != "" {
		t.Errorf("an unscoped target must keep the identity it always had, got %q", Scope{}.Key())
	}
	if !(Scope{}).Empty() || a.Empty() {
		t.Error("Empty should report only the unrestricted scope")
	}
}

func TestConeDirsNormalises(t *testing.T) {
	got := coneDirs([]string{"services/web/**", "/api/", " ", ".", "lib/*"})
	want := []string{"services/web", "api", "lib"}
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestGlobMatch(t *testing.T) {
	cases := []struct {
		pattern, path string
		want          bool
	}{
		{"vendor/**", "vendor/lib/lib.go", true},
		{"vendor/**", "vendors/lib.go", false},
		{"**/testdata/**", "a/b/testdata/x.go", true},
		{"**/testdata/**", "testdata/x.go", true},
		{"**/testdata/**", "a/testdataish/x.go", false},
		{"*.md", "README.md", true},
		{"*.md", "docs/README.md", false},
		{"docs/*.md", "docs/README.md", true},
	}
	for _, c := range cases {
		if got := saga.GlobMatch(c.pattern, c.path); got != c.want {
			t.Errorf("saga.GlobMatch(%q, %q) = %v, want %v", c.pattern, c.path, got, c.want)
		}
	}
}

func TestMatchesAnyTreatsABareNameAsADirectory(t *testing.T) {
	// Someone writing `vendor` rather than `vendor/` means the directory. Matching only the
	// literal path would ignore everything inside it, which is the opposite of what they asked.
	if !matchesAny([]string{"vendor"}, "vendor/lib/lib.go", false) {
		t.Error("a bare directory name should take what is beneath it")
	}
	if matchesAny([]string{"vendor"}, "vendored/lib.go", false) {
		t.Error("it must not match a different directory that starts the same way")
	}
	if matchesAny([]string{"", "  "}, "a.go", false) {
		t.Error("blank patterns must match nothing")
	}
}

func TestPruneEnforcesPathsForTheFallback(t *testing.T) {
	// The path taken when the server cannot do a partial clone or git is too old to do sparse
	// checkout. It has to produce the same tree as the fast one, or a scan's scope would depend
	// on where the repository is hosted.
	src := scopedRepo(t)
	co, cleanup, err := Checkout(context.Background(), src, "", Scope{})
	if err != nil {
		t.Fatalf("checkout: %v", err)
	}
	dir := co.Dir
	defer cleanup()

	if err := prune(dir, Scope{Paths: []string{"services/web"}, Ignore: []string{"**/testdata/**"}}, true); err != nil {
		t.Fatalf("prune: %v", err)
	}
	got := tree(t, dir)
	want := []string{".trivyignore", "Dockerfile", "go.mod", "services/web/main.go"}
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestRetryPlainReclonesOverAPartialTree(t *testing.T) {
	// The fallback runs against a directory the failed sparse clone may already have written
	// into, so it has to clear it first — git refuses to clone into a non-empty directory.
	src := scopedRepo(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "leftover"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := retryPlain(context.Background(), dir, src, ""); err != nil {
		t.Fatalf("retryPlain: %v", err)
	}
	got := tree(t, dir)
	if slices.Contains(got, "leftover") {
		t.Errorf("the partial clone should have been cleared: %v", got)
	}
	if !slices.Contains(got, "services/api/main.go") {
		t.Errorf("the fallback should fetch the whole tree: %v", got)
	}
}

func TestRetryPlainReportsABadRevision(t *testing.T) {
	err := retryPlain(context.Background(), t.TempDir(), scopedRepo(t), "no-such-rev")
	if err == nil {
		t.Fatal("expected an error for an unknown revision")
	}
}

func TestCheckoutScopedAtARevision(t *testing.T) {
	// Scope and revision together: the checkout happens before the sparse set, so getting the
	// order wrong would scope the default branch and then move off it.
	src := scopedRepo(t)
	//nolint:gosec // src is the fixture repository created above
	sha, err := exec.Command("git", "-C", src, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatal(err)
	}
	co, cleanup, err := Checkout(context.Background(), src, string(sha[:len(sha)-1]),
		Scope{Paths: []string{"services/api"}})
	if err != nil {
		t.Fatalf("checkout: %v", err)
	}
	dir := co.Dir
	defer cleanup()
	got := tree(t, dir)
	if !slices.Contains(got, "services/api/main.go") || slices.Contains(got, "services/web/main.go") {
		t.Errorf("scope should hold at a pinned revision: %v", got)
	}
}

func TestCheckoutFallsBackWhenSparseCloneIsRefused(t *testing.T) {
	// Partial clone needs the server's cooperation and sparse checkout needs a recent git.
	// Neither is a reason to refuse to scan, and the tree the slow route produces has to be the
	// same one — otherwise a scan's scope would depend on where the repository is hosted.
	orig := gitRun
	t.Cleanup(func() { gitRun = orig })
	gitRun = func(ctx context.Context, args ...string) error {
		if slices.Contains(args, "--sparse") {
			return errors.New("server does not support --filter")
		}
		return orig(ctx, args...)
	}

	co, cleanup, err := Checkout(context.Background(), scopedRepo(t), "",
		Scope{Paths: []string{"services/web"}, Ignore: []string{"**/testdata/**"}})
	if err != nil {
		t.Fatalf("checkout: %v", err)
	}
	dir := co.Dir
	defer cleanup()

	got := tree(t, dir)
	want := []string{".trivyignore", "Dockerfile", "go.mod", "services/web/main.go"}
	if !slices.Equal(got, want) {
		t.Errorf("the fallback must produce the same tree as sparse checkout\n got %v\nwant %v", got, want)
	}
}

func TestCheckoutReportsAFallbackFailure(t *testing.T) {
	orig := gitRun
	t.Cleanup(func() { gitRun = orig })
	gitRun = func(context.Context, ...string) error { return errors.New("no network") }

	if _, _, err := Checkout(context.Background(), "https://git/x", "",
		Scope{Paths: []string{"a"}}); err == nil {
		t.Fatal("expected the fallback's own failure to surface")
	}
}

// Two scans of one repository, one wanting history and one not, are different scans. A key that
// cannot tell them apart lets the shallow one serve the deep one's answer.
func TestScopeKeyDistinguishesHistory(t *testing.T) {
	shallow := Scope{Paths: []string{"a"}}
	deep := Scope{Paths: []string{"a"}, History: true}
	if shallow.Key() == deep.Key() {
		t.Errorf("history must change the key, both are %q", shallow.Key())
	}
	if (Scope{History: true}).Empty() {
		t.Error("a history scope restricts what the checkout must contain, so it is not empty")
	}
}
