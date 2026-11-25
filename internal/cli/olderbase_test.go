package cli

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/git"
	"github.com/draugr-dev/draugr/pkg/diff"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/skald"
)

// commitFile writes content to rel in repo, commits it and returns the commit's id.
func commitFile(t *testing.T, repo, rel, content string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(repo, filepath.Dir(rel)), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, rel), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"add", rel},
		{"-c", "user.email=t@example.com", "-c", "user.name=T", "commit", "-q", "-m", "write " + rel},
	} {
		if out, err := exec.Command("git", append([]string{"-C", repo}, args...)...).CombinedOutput(); err != nil { // #nosec G204 -- test fixture
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	return headOf(t, repo)
}

// headOf is repo's HEAD commit.
func headOf(t *testing.T, repo string) string {
	t.Helper()
	out, err := exec.Command("git", "-C", repo, "rev-parse", "HEAD").Output() // #nosec G204 -- test fixture
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out))
}

// baseReport is a report written by version whose repository scanner read repository at each of
// revisions, with extra fields on each read.
func baseReport(version, repository string, revisions []string, extra ...sarif.Field) sarif.Report {
	r := sarif.Report{ToolVersion: version}
	for _, rev := range revisions {
		fields := []sarif.Field{{Key: "repository", Value: repository}, {Key: "revision", Value: rev}}
		r.Provenance = append(r.Provenance, sarif.Provenance{Tool: "semgrep", Fields: append(fields, extra...)})
	}
	return r
}

// A base report from a release that recorded no scanner's file below a checkout's root says nothing
// about src/.semgrepignore, so the file is read at the base's commit from the checkout the comparison
// runs in and recorded as the base's. Where that commit is not there, or the base names no commit it
// can stand on, the file is left unrecorded and named, so it is held as added.
func TestAnOlderBaseIsReadAtItsCommit(t *testing.T) {
	ctx := context.Background()
	repo := gitRepo(t)
	before := headOf(t, repo)
	rev := commitFile(t, repo, "src/.semgrepignore", "vendor/\n")
	identity := identityOf(ctx, repo, repo)
	nested := engine.DeclaredFile{Kind: engine.FileScanner, Repository: repo, Path: "src/.semgrepignore",
		Digests: []string{git.ContentDigest([]byte("vendor/\n"))}}
	head := engine.Declarations{Files: []engine.DeclaredFile{nested}}

	read := func(t *testing.T, base sarif.Report, head engine.Declarations) (engine.Declarations, olderBase) {
		t.Helper()
		return readOlderBase(ctx, repo, base, engine.Declarations{}, head)
	}
	unreadOf := func(ob olderBase) diff.Unread { return ob.unread[[2]string{repo, "src/.semgrepignore"}] }

	t.Run("the base's commit holds it", func(t *testing.T) {
		got, ob := read(t, baseReport("0.189.3", identity, []string{rev}), head)
		if len(got.Files) != 1 || !slices.Equal(got.Files[0].Digests, nested.Digests) || unreadOf(ob) != "" {
			t.Errorf("files = %+v, unread = %v", got.Files, ob.unread)
		}
		// Compared as a report from this release would be: unchanged passes.
		r := diff.Compare(sarif.Report{}, sarif.Report{}).HoldToBase(got, head, true, nil)
		if len(r.Held.Files) != 0 {
			t.Errorf("held = %+v", r.Held.Files)
		}
	})
	t.Run("the change edits it", func(t *testing.T) {
		edited := nested
		edited.Digests = []string{git.ContentDigest([]byte("vendor/\nsrc/\n"))}
		editedHead := engine.Declarations{Files: []engine.DeclaredFile{edited}}
		got, _ := read(t, baseReport("0.189.3", identity, []string{rev}), editedHead)
		r := diff.Compare(sarif.Report{}, sarif.Report{}).HoldToBase(got, editedHead, true, nil)
		if len(r.Held.Files) != 1 || r.Held.Files[0].Added {
			t.Errorf("held = %+v, want src/.semgrepignore changed", r.Held.Files)
		}
	})
	t.Run("the base's commit does not hold it", func(t *testing.T) {
		got, ob := read(t, baseReport("0.189.3", identity, []string{before}), head)
		if len(got.Files) != 0 || unreadOf(ob) != "" {
			t.Errorf("files = %+v, unread = %v; want it added and read", got.Files, ob.unread)
		}
	})
	for name, c := range map[string]struct {
		base sarif.Report
		why  diff.Unread
	}{
		"the checkout lacks the commit": {baseReport("0.189.3", identity, []string{strings.Repeat("0123456789", 4)}), diff.CommitMissing},
		"the base read uncommitted changes": {baseReport("0.189.3", identity, []string{rev},
			sarif.Field{Key: "uncommitted", Value: "1"}), diff.CommitUnknown},
		"the base names no commit":            {baseReport("0.189.3", identity, []string{"main"}), diff.CommitUnknown},
		"the base read another repository":    {baseReport("0.189.3", "https://example.com/other.git", []string{rev}), diff.CommitUnknown},
		"one of two commits is not available": {baseReport("0.189.3", identity, []string{rev, strings.Repeat("f", 40)}), diff.CommitMissing},
	} {
		t.Run(name, func(t *testing.T) {
			got, ob := read(t, c.base, head)
			if len(got.Files) != 0 || unreadOf(ob) != c.why || ob.version != "0.189.3" {
				t.Errorf("files = %+v, unread = %v, version = %q; want %q", got.Files, ob.unread, ob.version, c.why)
			}
			r := diff.Compare(sarif.Report{}, sarif.Report{}).HoldToBase(got, head, true, nil)
			ob.markUnread(&r.Held)
			if len(r.Held.Files) != 1 || r.Held.Files[0].BaseUnread != c.why || r.Held.BaseVersion != "0.189.3" {
				t.Errorf("held = %+v, version %q", r.Held.Files, r.Held.BaseVersion)
			}
		})
	}
	// A release that records the files, and a version that cannot be read, are taken at their word:
	// the base had no such file.
	for _, version := range []string{"0.189.4", "0.190.0", "dev", ""} {
		t.Run("written by "+version, func(t *testing.T) {
			got, ob := read(t, baseReport(version, identity, []string{rev}), head)
			if len(got.Files) != 0 || len(ob.unread) != 0 {
				t.Errorf("files = %+v, unread = %v", got.Files, ob.unread)
			}
		})
	}
	t.Run("a file at the root is left to the base's record", func(t *testing.T) {
		root := engine.DeclaredFile{Kind: engine.FileScanner, Repository: repo, Path: ".semgrepignore", Digests: []string{"1111111111111111"}}
		got, ob := read(t, baseReport("0.189.3", identity, []string{rev}), engine.Declarations{Files: []engine.DeclaredFile{root}})
		if len(got.Files) != 0 || len(ob.unread) != 0 {
			t.Errorf("files = %+v, unread = %v", got.Files, ob.unread)
		}
	})
	t.Run("a file the base recorded is left as recorded", func(t *testing.T) {
		recorded := nested
		recorded.Digests = []string{"2222222222222222"}
		got, _ := readOlderBase(ctx, repo, baseReport("0.189.3", identity, []string{rev}),
			engine.Declarations{Files: []engine.DeclaredFile{recorded}}, head)
		if len(got.Files) != 1 || got.Files[0].Digests[0] != "2222222222222222" {
			t.Errorf("files = %+v", got.Files)
		}
	})
}

// A repository the descriptor names by URL is read from the checkout the comparison runs in, and one
// named by a relative path from that checkout, by its remote where it has one.
func TestAnOlderBaseIsReadFromTheCheckoutItRunsIn(t *testing.T) {
	ctx := context.Background()
	repo := gitRepo(t)
	rev := commitFile(t, repo, "src/.semgrepignore", "vendor/\n")
	digest := git.ContentDigest([]byte("vendor/\n"))
	const url = "https://example.com/api.git"
	if out, err := exec.Command("git", "-C", repo, "remote", "add", "origin", url).CombinedOutput(); err != nil { // #nosec G204 -- test fixture
		t.Fatalf("%v\n%s", err, out)
	}
	for _, repository := range []string{url, "."} {
		t.Run(repository, func(t *testing.T) {
			head := engine.Declarations{Files: []engine.DeclaredFile{{Kind: engine.FileScanner, Repository: repository,
				Path: "src/.semgrepignore", Digests: []string{digest}}}}
			base := baseReport("0.189.3", identityOf(ctx, repo, url), []string{rev})
			got, ob := readOlderBase(ctx, repo, base, engine.Declarations{}, head)
			if len(got.Files) != 1 || got.Files[0].Digests[0] != digest || len(ob.unread) != 0 {
				t.Errorf("files = %+v, unread = %v", got.Files, ob.unread)
			}
		})
	}
	// Run from a directory that is not a checkout, there is nothing to fetch the URL's commit into.
	head := engine.Declarations{Files: []engine.DeclaredFile{{Kind: engine.FileScanner, Repository: url,
		Path: "src/.semgrepignore", Digests: []string{digest}}}}
	if _, ob := readOlderBase(ctx, t.TempDir(), baseReport("0.189.3", identityOf(ctx, repo, url), []string{rev}),
		engine.Declarations{}, head); ob.unread[[2]string{url, "src/.semgrepignore"}] != diff.CommitUnknown {
		t.Errorf("unread = %v outside the checkout", ob.unread)
	}
}

// The comparison `draugr diff` and `scan --base` make reads the base's commit from the directory it
// runs in.
func TestCompareWithBaseReadsAnOlderBaseFromTheWorkingDirectory(t *testing.T) {
	repo := gitRepo(t)
	rev := commitFile(t, repo, "src/.semgrepignore", "vendor/\n")
	t.Chdir(repo)
	if workingDir() != repo {
		t.Fatalf("working directory = %q, want %q", workingDir(), repo)
	}
	declared := func(files ...engine.DeclaredFile) sarif.Report {
		return sarif.Report{Provenance: skald.DeclaredProvenance(engine.Declarations{
			Components: []engine.ComponentDeclaration{{Name: "api", Repositories: []string{"."}}}, Files: files})}
	}
	nested := engine.DeclaredFile{Kind: engine.FileScanner, Repository: ".", Path: "src/.semgrepignore",
		Digests: []string{git.ContentDigest([]byte("vendor/\n"))}}
	base := declared()
	base.ToolVersion = "0.189.3"
	base.Provenance = append(base.Provenance, baseReport("", identityOf(context.Background(), repo, "."), []string{rev}).Provenance...)
	head := declared(nested)
	compared, err := compareWithBase("base", base, "head", head, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(compared.Held.Files) != 0 {
		t.Errorf("held = %+v for a file the base's commit holds unchanged", compared.Held.Files)
	}
	base.Provenance[len(base.Provenance)-1].Fields[1].Value = strings.Repeat("a", 40)
	if compared, err = compareWithBase("base", base, "head", head, ""); err != nil {
		t.Fatal(err)
	}
	if len(compared.Held.Files) != 1 || compared.Held.Files[0].BaseUnread != diff.CommitMissing || compared.Held.BaseVersion != "0.189.3" {
		t.Errorf("held = %+v, version %q", compared.Held.Files, compared.Held.BaseVersion)
	}
}
