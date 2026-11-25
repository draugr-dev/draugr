package cli

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/mod/semver"

	"github.com/draugr-dev/draugr/internal/git"
	"github.com/draugr-dev/draugr/pkg/diff"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// nestedFilesFrom is the first release whose reports record a scanner's file below the root of a
// checkout, such as a .semgrepignore in a subdirectory. A report from an earlier release recorded
// only the files at the root.
const nestedFilesFrom = "0.189.4"

// olderBase is what a comparison learned about the scanners' files below a checkout's root that its
// base report's release did not record.
type olderBase struct {
	// version is the release that wrote the base report.
	version string
	// unread are the files that could not be read at the base's commit, keyed as Held's Files are,
	// by repository and path, each with why.
	unread map[[2]string]diff.Unread
}

// readOlderBase settles, from the checkout the comparison runs in, the scanners' files below a
// checkout's root that the head records and a base report from an earlier release could not have.
//
// An earlier release recorded only the files at the root, so its silence about src/.semgrepignore
// says nothing about whether the base held one, and reading it as "the base had none" holds every
// pull request in a repository that already does. The base report records the commit each
// repository was read at, so the file is read at that commit, `git cat-file` in the checkout, and
// recorded as the base's read of it with its digest. A change that leaves it alone then passes, and
// one that edits it is held as changing it, which is the decision a report from this release would
// have given. The base still decides: the content comes from its own commit, which the change cannot
// alter.
//
// A file stays unrecorded, and is held as added, where the base's commit is not in the checkout, as
// in a shallow clone, where the base report names no commit for the repository or read it with
// uncommitted changes, and where git cannot be run. Those are returned in unread for the run to name.
func readOlderBase(ctx context.Context, dir string, base sarif.Report, baseDeclared, headDeclared engine.Declarations) (engine.Declarations, olderBase) {
	ob := olderBase{version: base.ToolVersion}
	if !olderThanNestedFiles(base.ToolVersion) {
		return baseDeclared, ob
	}
	type key struct {
		repository, path string
	}
	recorded := map[key]bool{}
	for _, f := range baseDeclared.Files {
		if f.Kind == engine.FileScanner {
			recorded[key{f.Repository, f.Path}] = true
		}
	}
	files := slices.Clone(baseDeclared.Files)
	for _, f := range headDeclared.Files {
		if f.Kind != engine.FileScanner || slices.Contains(git.RootConfig(), f.Path) || recorded[key{f.Repository, f.Path}] {
			continue
		}
		digests, why := readAtBase(ctx, dir, base, f)
		switch {
		case why != "":
			if ob.unread == nil {
				ob.unread = map[[2]string]diff.Unread{}
			}
			ob.unread[[2]string{f.Repository, f.Path}] = why
		case len(digests) > 0:
			files = append(files, engine.DeclaredFile{Kind: engine.FileScanner, Repository: f.Repository, Path: f.Path, Digests: digests})
		}
	}
	baseDeclared.Files = files
	return baseDeclared, ob
}

// olderThanNestedFiles reports whether a report written by version predates nestedFilesFrom. A
// version semver cannot read, such as a development build's, is not taken as older: the file is
// then held as added, as it would be without this.
func olderThanNestedFiles(version string) bool {
	v := "v" + strings.TrimPrefix(version, "v")
	return semver.IsValid(v) && semver.Compare(v, "v"+nestedFilesFrom) < 0
}

// readAtBase is the digest of f at each commit the base report read f's repository at, as a
// checkout of that commit holds it. None where no such commit held the file. why says what stopped
// a read: diff.CommitMissing for a commit the checkout does not hold, diff.CommitUnknown where the
// base names none it can be read at or git cannot read the checkout.
func readAtBase(ctx context.Context, dir string, base sarif.Report, f engine.DeclaredFile) (digests []string, why diff.Unread) {
	revisions, ok := baseRevisions(ctx, dir, base, f.Repository)
	if !ok {
		return nil, diff.CommitUnknown
	}
	repo := dir
	if git.IsLocalPath(f.Repository) {
		repo = f.Repository
		if !filepath.IsAbs(repo) {
			repo = filepath.Join(dir, repo)
		}
	}
	// A directory git cannot read is no checkout to fetch into.
	if exec.CommandContext(ctx, "git", "-C", repo, "rev-parse", "--git-dir").Run() != nil { // #nosec G204 -- the descriptor's own repository path or the working directory
		return nil, diff.CommitUnknown
	}
	for _, rev := range revisions {
		// The commit itself first: a missing commit and a file the commit does not hold are two answers.
		if exec.CommandContext(ctx, "git", "-C", repo, "cat-file", "-e", rev+"^{commit}").Run() != nil { // #nosec G204 -- a commit id from the base report, checked as one
			return nil, diff.CommitMissing
		}
		// --filters converts the content as a checkout would, line endings included, which is what
		// the base's scanner read.
		out, err := exec.CommandContext(ctx, "git", "-C", repo, "cat-file", "--filters", rev+":"+f.Path).Output() // #nosec G204 -- a commit id from the base report and a path the head report recorded
		if err != nil {
			continue
		}
		if d := git.ContentDigest(out); !slices.Contains(digests, d) {
			digests = append(digests, d)
		}
	}
	slices.Sort(digests)
	return digests, ""
}

// baseRevisions are the commits the base report's repository scanners read repository at. ok is
// false where it names none, names something other than a commit id, or read the repository with
// uncommitted changes, whose content no commit holds.
func baseRevisions(ctx context.Context, dir string, base sarif.Report, repository string) (revisions []string, ok bool) {
	want := identityOf(ctx, dir, repository)
	for _, p := range base.Provenance {
		var repo, rev string
		dirty := false
		for _, fl := range p.Fields {
			switch fl.Key {
			case "repository":
				repo = fl.Value
			case "revision":
				rev = fl.Value
			case "uncommitted":
				dirty = true
			}
		}
		if repo == "" || repo != want {
			continue
		}
		if dirty || !git.IsCommitSHA(rev) {
			return nil, false
		}
		if !slices.Contains(revisions, rev) {
			revisions = append(revisions, rev)
		}
	}
	return revisions, len(revisions) > 0
}

// identityOf is repository as a repository scanner's provenance names it: its remote for a local
// checkout that has one, as plugin.RepositoryTarget.Source spells it.
func identityOf(ctx context.Context, dir, repository string) string {
	t := plugin.RepositoryTarget{URL: repository}
	if git.IsLocalPath(repository) {
		path := repository
		if !filepath.IsAbs(path) {
			path = filepath.Join(dir, path)
		}
		t.Remote = git.RemoteURL(ctx, path)
	}
	return t.Source()
}

// markUnread marks the held files the base could not have recorded and the checkout could not read,
// and names the release that wrote the base.
func (ob olderBase) markUnread(h *diff.Held) {
	for i, f := range h.Files {
		if why := ob.unread[[2]string{f.Repository, f.Path}]; why != "" {
			h.Files[i].BaseUnread = why
			h.BaseVersion = ob.version
		}
	}
}

// workingDir is the directory a comparison reads the checkout from, empty where it cannot be told.
func workingDir() string {
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}
	return dir
}
