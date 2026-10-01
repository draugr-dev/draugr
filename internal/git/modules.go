package git

import (
	"context"
	"os/exec"
	"path"
	"slices"
	"strings"
)

// ModuleRoots lists the module directories a job scoped to paths has to analyze whole, or nil where
// the scope needs no widening or the layout cannot be read without fetching the repository.
//
// A module is a directory holding manifest, `go.mod` for Go. An analyzer that type-checks a package
// needs every package it imports, and a scope that holds `cmd/admin` without the `internal/store`
// it imports leaves nothing that compiles. So a scope selects the modules its files belong to:
//
//   - the module a selected `.go` file belongs to, which is the innermost module directory holding
//     it, whether the file is selected by name or inside a selected directory;
//   - the module whose manifest a path names.
//
// A path holding neither, a frontend directory in a repository whose root is a Go module, selects
// nothing, so a component with no Go code is not handed the whole module to analyze.
//
// Vendored trees and testdata are not modules, as the scanners that walk a checkout treat them.
//
// Read at revision from git, or from the files on disk for a working-tree scan, and only for a
// local checkout. A remote is read with ls-remote, which knows refs and not trees, and fetching
// one to plan a scan would cost more than the scan; the caller keeps the scope as written.
func ModuleRoots(ctx context.Context, url, revision string, workingTree bool, manifest string, paths []string) ([]string, error) {
	keep := selected(paths)
	if len(keep) == 0 || manifest == "" || !IsLocalPath(url) {
		return nil, nil
	}
	var cmd *exec.Cmd
	if workingTree {
		// #nosec G204 -- the descriptor's own repository path
		cmd = exec.CommandContext(ctx, "git", "-C", url, "ls-files", "-co", "--exclude-standard", "-z")
	} else {
		rev := revision
		if rev == "" {
			rev = "HEAD"
		}
		// #nosec G204 -- the descriptor's own repository path and revision
		cmd = exec.CommandContext(ctx, "git", "-C", url, "ls-tree", "-r", "--full-tree", "--name-only", "-z", rev)
	}
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	return moduleRootsIn(strings.Split(string(out), "\x00"), manifest, keep), nil
}

// moduleRootsIn is ModuleRoots over a repository's file list, with keep already normalized.
func moduleRootsIn(files []string, manifest string, keep []string) []string {
	var modules, sources []string
	for _, f := range files {
		if f == "" || outsideBuild(f) {
			continue
		}
		switch {
		case path.Base(f) == manifest:
			modules = append(modules, path.Dir(f))
		case strings.HasSuffix(f, ".go"):
			sources = append(sources, f)
		}
	}
	if len(modules) == 0 {
		return nil
	}
	var roots []string
	for _, p := range keep {
		if path.Base(p) == manifest && slices.Contains(modules, path.Dir(p)) {
			roots = append(roots, path.Dir(p))
		}
	}
	for _, f := range sources {
		if !slices.ContainsFunc(keep, func(p string) bool { return f == p || strings.HasPrefix(f, p+"/") }) {
			continue
		}
		if m, ok := InnermostModule(f, modules); ok {
			roots = append(roots, m)
		}
	}
	slices.Sort(roots)
	return slices.Compact(roots)
}

// InnermostModule returns the deepest of modules holding file, "." for the repository root.
//
// The deepest, because a module nested inside another is its own build: the outer module's
// packages stop at the nested module's directory.
func InnermostModule(file string, modules []string) (string, bool) {
	best, found := "", false
	for _, m := range modules {
		if m != "." && file != m && !strings.HasPrefix(file, m+"/") {
			continue
		}
		if !found || depth(m) > depth(best) {
			best, found = m, true
		}
	}
	return best, found
}

// depth counts a repository-relative directory's segments, zero for the root.
func depth(dir string) int {
	if dir == "." {
		return 0
	}
	return strings.Count(dir, "/") + 1
}

// outsideBuild reports whether a file sits under a vendored tree or testdata, which no module
// builds.
func outsideBuild(f string) bool {
	for _, seg := range strings.Split(path.Dir(f), "/") {
		if seg == "vendor" || seg == "testdata" {
			return true
		}
	}
	return false
}
