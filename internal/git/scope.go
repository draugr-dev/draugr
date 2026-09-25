package git

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
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
	// Paths restricts the checkout to these directories and files. Empty, or an entry naming the
	// root, means the whole repository.
	//
	// Prefixes, not general globs: `services/web` and `services/web/**` both mean the same subtree,
	// and `go.mod` means that one file. That is what sparse checkout can express, and expressing it
	// any other way would mean downloading the repository to throw most of it away.
	//
	// A file at the repository root is in the checkout only when an entry names it, apart from the
	// scanners' own configuration (see rootConfig). Components sharing a repository would otherwise
	// each receive the root lockfile, Dockerfile and any secret committed beside them, and report
	// every finding in them once per component.
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

// Contains reports whether the file at rel, a repository-relative path, is one this scope checks
// out.
//
// It answers with the helpers prune uses, so a file is inside the scope exactly when a checkout
// would have kept it. A finding reported against the repository rather than the tree, such as a
// secret found in commit history, is then held to the same boundary as the tree every other
// scanner reads. A second matcher would be a second answer to where a component ends, and the
// two would drift apart.
func (s Scope) Contains(rel string) bool {
	rel = strings.Trim(path.Clean(filepath.ToSlash(rel)), "/")
	if rel == "" || rel == "." || rel == ".." || strings.HasPrefix(rel, "../") {
		return false
	}
	if keep := selected(s.Paths); len(keep) > 0 && !withinPaths(rel, keep, false) {
		return false
	}
	// prune removes a matching directory with everything under it, so every directory above the
	// file is tested as a directory, the way the walk would have met it.
	segs := strings.Split(rel, "/")
	for i := 1; i < len(segs); i++ {
		if matchesAny(s.Ignore, strings.Join(segs[:i], "/"), true) {
			return false
		}
	}
	return !matchesAny(s.Ignore, rel, false)
}

// rootConfig is the scanners' own configuration: the root files every scoped checkout keeps,
// whatever Paths names.
//
// Each tool reads its file from the root of the tree it is handed. They configure how a component
// is scanned rather than being part of one, so dropping them from a scoped checkout would bring
// back findings the repository already suppressed.
var rootConfig = []string{
	".gitleaks.toml", ".gitleaksignore", ".grype.yaml", ".semgrepignore",
	".trivyignore", ".trivyignore.yaml", "trivy.yaml",
}

// selected normalizes Paths into the repository-relative entries a scoped checkout keeps. Nil
// means the whole repository: no entries, or an entry naming the root.
//
// A trailing `/**` or `/*` is what a descriptor written against the old documentation says, and
// it means the same subtree, so it is accepted rather than rejected.
func selected(paths []string) []string {
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		p = strings.TrimSpace(p)
		p = strings.TrimSuffix(strings.TrimSuffix(p, "/**"), "/*")
		p = strings.Trim(p, "/")
		if p == "" || p == "." {
			return nil
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// sparsePatterns renders the selected entries and the root configuration as the patterns
// `git sparse-checkout set --no-cone` takes.
//
// Not cone mode, which takes directories only and always materializes every root file. Anchored
// with a leading `/`, a pattern names one path, and one that names a directory takes everything
// beneath it.
func sparsePatterns(keep []string) []string {
	out := make([]string, 0, len(keep)+len(rootConfig))
	for _, k := range keep {
		out = append(out, "/"+k)
	}
	for _, c := range rootConfig {
		out = append(out, "/"+c)
	}
	return out
}

// missingPaths returns the selected entries absent from a tree, in the order given.
//
// A mistyped entry would otherwise narrow the scan to the root configuration alone. The run that
// follows reports nothing from a tree it never looked at, which is the same shape as a clean
// result.
func missingPaths(keep []string, present func(string) bool) []string {
	var out []string
	for _, k := range keep {
		if !present(k) {
			out = append(out, k)
		}
	}
	return out
}

// errMissingPaths names the entries missing from the tree at revision.
func errMissingPaths(missing []string, revision string) error {
	at := "in the working tree"
	if revision != "" {
		at = "at " + shortRevision(revision)
	}
	return fmt.Errorf("paths %s: not in the repository %s", strings.Join(quoteAll(missing), ", "), at)
}

func quoteAll(ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = strconv.Quote(s)
	}
	return out
}

func shortRevision(rev string) string {
	if len(rev) == 40 {
		return rev[:12]
	}
	return rev
}

// prune removes everything under dir that the scope excludes.
//
// Two jobs. Where sparse checkout was unavailable it enforces Paths, so the fallback tree is the
// same tree; and it always enforces Ignore, which sparse checkout cannot express. Safe to be
// destructive: dir is a temporary clone this package created and will delete.
func prune(dir string, scope Scope, enforcePaths bool) error {
	keep := selected(scope.Paths)

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
// Four things survive: a selected file, anything inside a selected directory, the directories
// leading down to one, and the scanners' configuration at the root. It is the same tree sparse
// checkout materializes from sparsePatterns, so the slow route cannot disagree with the fast one.
func withinPaths(rel string, keep []string, isDir bool) bool {
	if !isDir && slices.Contains(rootConfig, rel) {
		return true
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
