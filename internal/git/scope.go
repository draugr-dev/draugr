package git

import (
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// Scope restricts which of a repository's files a checkout materialises.
//
// Shaping the tree rather than passing flags to each tool is deliberate. Every repository
// scanner is handed the checkout directory and points its tool at it — Trivy, Semgrep, Gitleaks
// and gosec all take a root and walk it. Translating a descriptor's scope into each tool's own
// include and exclude syntax would be a mapping per tool, wrong in a different way for each,
// and absent for the next scanner someone adds. A tree that already contains what was asked for
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
}

// Empty reports whether the scope restricts anything.
func (s Scope) Empty() bool { return len(s.Paths) == 0 && len(s.Ignore) == 0 }

// Key renders the scope for a cache or dedup identity. Two components scoped to different
// subtrees of one repository are different scans, and a key that cannot tell them apart lets
// the second silently receive the first's findings.
func (s Scope) Key() string {
	if s.Empty() {
		return ""
	}
	return "paths=" + strings.Join(s.Paths, ",") + ";ignore=" + strings.Join(s.Ignore, ",")
}

// coneDirs normalises Paths into the directory list `git sparse-checkout set --cone` accepts.
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
// expensive to get wrong — go.mod, package.json, Dockerfile, .semgrepignore, .trivyignore and
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
		if globMatch(p, rel) {
			return true
		}
		// A directory pattern also takes everything beneath it, which is what someone writing
		// `vendor` rather than `vendor/` means.
		if globMatch(p, firstSegments(rel, strings.Count(p, "/")+1)) {
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

// globMatch reports whether rel matches pattern, with `**` crossing separators.
//
// path.Match handles a single segment; `**` is split on and each side matched around it, so
// `**/testdata/**` and `vendor/**` both behave the way the person writing them expects.
func globMatch(pattern, rel string) bool {
	if !strings.Contains(pattern, "**") {
		ok, err := path.Match(pattern, rel)
		return err == nil && ok
	}
	head, tail, _ := strings.Cut(pattern, "**")
	head, tail = strings.TrimSuffix(head, "/"), strings.TrimPrefix(tail, "/")

	if head != "" {
		if !strings.HasPrefix(rel, head+"/") && rel != head {
			return false
		}
		rel = strings.TrimPrefix(strings.TrimPrefix(rel, head), "/")
	}
	if tail == "" {
		return true // `prefix/**` takes everything below prefix
	}
	// The remainder of the pattern may start at any depth.
	for {
		if globMatch(tail, rel) {
			return true
		}
		_, rest, found := strings.Cut(rel, "/")
		if !found {
			return false
		}
		rel = rest
	}
}
