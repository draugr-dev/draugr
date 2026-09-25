package git

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"

	"github.com/draugr-dev/draugr/pkg/saga"
)

// Scope restricts which of a repository's files a checkout materializes.
//
// Shaping the tree rather than passing flags to each tool is deliberate. Every repository
// scanner is handed the checkout directory and points its tool at it, Trivy, Semgrep, Gitleaks
// and gosec all take a root and walk it. Translating a descriptor's scope into each tool's own
// include and exclude syntax would be a mapping per tool, wrong in a different way for each, and
// absent for the next scanner someone adds. A tree that already contains what was asked for
// needs no translation and cannot be forgotten.
type Scope struct {
	// Paths restricts the checkout to these directories. Empty means the whole repository.
	//
	// Directory prefixes, not general globs: `services/web` and `services/web/**` both mean the
	// same subtree. That is what sparse checkout can express, and expressing it any other way
	// would mean downloading the repository to throw most of it away.
	Paths []string

	// Ignore removes matching paths after checkout, applied last so it can carve out of Paths.
	// Gitignore-style: a trailing `/` matches a directory and everything under it, `*` matches
	// within a path segment, `**` matches across them.
	Ignore []string

	// History asks for the repository's commit history, not only the tree at one revision.
	//
	// A checkout is shallow by default because that is what makes a scan fast, and every scanner
	// but one reads the tree. Secret detection is the exception: a credential committed and later
	// removed is still fetchable by anyone who can clone the repository, so it is still
	// compromised and still needs rotating. Finding it means having the history to look at.
	//
	// It also turns off the sparse and partial-clone optimizations. Those leave historical blobs
	// unfetched, so a history scan over them would walk commits whose contents are not present and
	// report clean, the most dangerous kind of wrong answer.
	History bool
}

// Empty reports whether the scope restricts anything.
func (s Scope) Empty() bool { return len(s.Paths) == 0 && len(s.Ignore) == 0 && !s.History }

// Key renders the scope for a cache or dedup identity. Two components scoped to different
// subtrees of one repository are different scans, and a key that cannot tell them apart lets
// the second silently receive the first's findings.
func (s Scope) Key() string {
	if s.Empty() {
		return ""
	}
	key := "paths=" + strings.Join(s.Paths, ",") + ";ignore=" + strings.Join(s.Ignore, ",")
	if s.History {
		key += ";history"
	}
	return key
}

// coneDirs normalizes Paths into the directory list `git sparse-checkout set --cone` accepts.
//
// A trailing `/**` or `/*` is what a descriptor written against the old documentation says, and
// it means the same subtree, so it is accepted rather than rejected.
func coneDirs(paths []string) []string {
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		p = strings.TrimSpace(p)
		p = strings.TrimSuffix(strings.TrimSuffix(p, "/**"), "/*")
		p = strings.Trim(p, "/")
		if p == "" || p == "." {
			continue
		}
		out = append(out, p)
	}
	return out
}

// entryKind is what a `paths:` entry names in the tree being scanned.
type entryKind int

const (
	entryMissing entryKind = iota
	entryDir
	entryFile
)

// sparseDirs checks every `paths:` entry against the tree and returns the directories among them,
// for sparse checkout.
//
// An entry that names nothing is refused, naming it. `paths: [services/wbe]` otherwise narrows the
// checkout to the root files alone and the scan reports on those, which reads exactly like a clean
// result for a component whose code was never read. The lookup is git's, so it is exact about case:
// a filesystem that ignores case would accept `services/Web` here and the same descriptor would
// match nothing on the runner.
//
// A file at the repository root is accepted and left out of the result. Naming one claims it for
// the component, so its findings are reported there rather than under every component sharing
// the repository, and the checkout already holds every root file.
//
// where names what was looked in, for the refusal: "at the revision scanned" for a clone, "in the
// working tree" for a copy of one, which has no revision.
func sparseDirs(paths []string, source, where string, lookup func(entry string) entryKind) ([]string, error) {
	var dirs []string
	for _, entry := range coneDirs(paths) {
		switch lookup(entry) {
		case entryDir:
			dirs = append(dirs, entry)
		case entryFile:
			if strings.Contains(entry, "/") {
				return nil, fmt.Errorf("paths entry %q in %s is a file below the root: name its directory (%s), or a file at the repository root",
					entry, source, path.Dir(entry))
			}
		default:
			return nil, fmt.Errorf("paths entry %q matches nothing in %s: no such directory or root file %s", entry, source, where)
		}
	}
	return dirs, nil
}

// treeLookup answers what an entry is at HEAD of a clone, from the tree alone, so a partial clone
// fetches no blob to answer it.
func treeLookup(ctx context.Context, dir string) func(string) entryKind {
	return func(entry string) entryKind {
		// #nosec G204 -- Draugr's own temporary checkout, and an entry from the descriptor passed after --
		out, err := exec.CommandContext(ctx, "git", "-C", dir, "ls-tree", "HEAD", "--", entry).Output()
		if err != nil {
			return entryMissing
		}
		for line := range strings.SplitSeq(strings.TrimSpace(string(out)), "\n") {
			meta, name, ok := strings.Cut(line, "\t")
			if !ok || name != entry {
				continue
			}
			switch fields := strings.Fields(meta); {
			case len(fields) == 3 && fields[1] == "tree":
				return entryDir
			case len(fields) == 3 && fields[1] == "blob":
				return entryFile
			}
		}
		return entryMissing
	}
}

// listLookup answers what an entry is from a list of the files in a tree.
func listLookup(files []string) func(string) entryKind {
	return func(entry string) entryKind {
		for _, f := range files {
			if f == entry {
				return entryFile
			}
			if strings.HasPrefix(f, entry+"/") {
				return entryDir
			}
		}
		return entryMissing
	}
}

// prune removes everything under dir that the scope excludes.
//
// Two jobs. Where sparse checkout was unavailable it enforces Paths, so the fallback tree is the
// same tree; and it always enforces Ignore, which sparse checkout cannot express. Safe to be
// destructive: dir is a temporary clone this package created and will delete.
func prune(dir string, scope Scope, enforcePaths bool) error {
	keep := coneDirs(scope.Paths)

	var doomed []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, relErr := filepath.Rel(dir, p)
		if relErr != nil || rel == "." {
			return relErr
		}
		rel = filepath.ToSlash(rel)
		if rel == ".git" {
			return fs.SkipDir // the clone's own metadata is not part of the tree being scanned
		}

		if enforcePaths && len(keep) > 0 && !withinPaths(rel, keep, d.IsDir()) {
			doomed = append(doomed, p)
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if matchesAny(scope.Ignore, rel, d.IsDir()) {
			doomed = append(doomed, p)
			if d.IsDir() {
				return fs.SkipDir
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	for _, p := range doomed {
		if err := os.RemoveAll(p); err != nil {
			return err
		}
	}
	return nil
}

// withinPaths reports whether rel should survive a Paths restriction.
//
// Three things survive: anything inside a selected directory, the directories leading down to
// one, and every file at the repository root. The last is the part that is easy to get wrong and
// expensive to get wrong, go.mod, package.json, Dockerfile, .semgrepignore, .trivyignore and
// their kin live there, and a scanner that cannot see them does not fail. It reports fewer
// findings against a tree it could not fully understand, which reads exactly like a clean scan.
func withinPaths(rel string, keep []string, isDir bool) bool {
	if !isDir && !strings.Contains(rel, "/") {
		return true // a file at the repository root
	}
	for _, k := range keep {
		if rel == k || strings.HasPrefix(rel, k+"/") {
			return true
		}
		if isDir && strings.HasPrefix(k+"/", rel+"/") {
			return true // a parent of something selected
		}
	}
	return false
}

// matchesAny reports whether rel is covered by any ignore pattern.
func matchesAny(patterns []string, rel string, isDir bool) bool {
	for _, p := range patterns {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if strings.HasSuffix(p, "/") {
			if isDir && (rel == strings.TrimSuffix(p, "/") || strings.HasPrefix(rel, p)) {
				return true
			}
			continue
		}
		if saga.GlobMatch(p, rel) {
			return true
		}
		// A directory pattern also takes everything beneath it, which is what someone writing
		// `vendor` rather than `vendor/` means.
		if saga.GlobMatch(p, firstSegments(rel, strings.Count(p, "/")+1)) {
			return true
		}
	}
	return false
}

// firstSegments returns the first n slash-separated segments of rel.
func firstSegments(rel string, n int) string {
	seg := strings.Split(rel, "/")
	if len(seg) <= n {
		return rel
	}
	return strings.Join(seg[:n], "/")
}
