// Package manifests recognizes the files in a tree that declare or pin dependencies, and accounts
// for the ones a dependency scan did not read.
//
// One list for every reader: a scanner deciding whether resolving nothing was a real answer, a scan
// reporting what it left unread, and `draugr init` deciding what a tree needs. Kept apart they
// disagree about what counts as a manifest, and each disagreement is a file one of them is silent
// about.
package manifests

import (
	"bufio"
	"bytes"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
)

// Kind separates a file that names dependencies from one that pins them.
type Kind int

const (
	// Pinned lists exact versions, and a scanner reads packages from it directly: a lockfile,
	// requirements.txt, go.mod, pom.xml.
	Pinned Kind = iota
	// Declared names dependencies without resolving them, so a scanner needs the lockfile beside
	// it: package.json, pyproject.toml, Cargo.toml, a .csproj.
	Declared
)

// File is one dependency file found in a tree.
type File struct {
	// Path is slash-separated and relative to the root that was searched.
	Path      string
	Ecosystem string
	Kind      Kind
}

// Reason is why a dependency file contributed no packages to a scan.
type Reason string

const (
	// NoLockfile is a declared manifest with no lockfile beside it or above it.
	NoLockfile Reason = "no lockfile"
	// Unpinned is a requirements file whose entries name no exact version.
	Unpinned Reason = "no pinned versions"
	// NotRead is a file the scan read no packages from: a name its scanner does not read, or a
	// format it does not support.
	NotRead Reason = "no packages read"
)

// Unread is a dependency file a scan did not read, and why.
type Unread struct {
	Path   string
	Reason Reason
}

// rule recognizes one kind of dependency file.
type rule struct {
	ecosystem string
	kind      Kind
	// match reports whether a file, by its slash-separated path, is this kind.
	match func(rel string) bool
	// locks are the lockfile names that resolve a declared manifest, looked for in its own
	// directory and then each directory above it, because a workspace keeps one lockfile at its
	// root for every member.
	locks []string
	// sameDirLocks resolve a manifest only from its own directory: a .csproj's packages.lock.json
	// belongs to that project and no other.
	sameDirLocks []string
	// declares reports whether the content names any dependency at all. A go.mod with no require
	// and a pyproject.toml holding only tool settings pin nothing, and reporting them unread would
	// be a warning about a file with nothing in it to read. Nil means every such file declares.
	declares func(content []byte) bool
}

func named(names ...string) func(string) bool {
	return func(rel string) bool { return slices.Contains(names, path.Base(rel)) }
}

func suffixed(suffixes ...string) func(string) bool {
	return func(rel string) bool {
		base := path.Base(rel)
		for _, s := range suffixes {
			if strings.HasSuffix(base, s) && base != s {
				return true
			}
		}
		return false
	}
}

func containsAny(words ...string) func([]byte) bool {
	return func(content []byte) bool {
		for _, w := range words {
			if bytes.Contains(content, []byte(w)) {
				return true
			}
		}
		return false
	}
}

// packageBlocks reports whether a TOML lockfile holds at least n [[package]] entries.
func packageBlocks(n int) func([]byte) bool {
	return func(content []byte) bool { return bytes.Count(content, []byte("[[package]]")) >= n }
}

// isRequirements matches pip's requirements files by the names projects give them:
// requirements.txt, requirements-dev.txt, dev-requirements.txt, and any .txt under a directory
// named requirements.
func isRequirements(rel string) bool {
	base := path.Base(rel)
	if !strings.HasSuffix(base, ".txt") {
		return false
	}
	if strings.Contains(base, "requirements") {
		return true
	}
	return path.Base(path.Dir(rel)) == "requirements"
}

func isPylock(rel string) bool {
	base := path.Base(rel)
	return base == "pylock.toml" || (strings.HasPrefix(base, "pylock.") && strings.HasSuffix(base, ".toml"))
}

var pythonLocks = []string{"poetry.lock", "uv.lock", "pdm.lock", "pylock.toml", "Pipfile.lock"}

var rules = []rule{
	{ecosystem: "python", kind: Pinned, match: isRequirements, declares: hasRequirement},
	{ecosystem: "python", kind: Pinned, match: named("Pipfile.lock"), declares: containsAny("\"version\"")},
	{ecosystem: "python", kind: Pinned, match: named("poetry.lock", "pdm.lock"), declares: packageBlocks(1)},
	// uv records the project itself as a package, so one entry is a lockfile with nothing in it.
	{ecosystem: "python", kind: Pinned, match: named("uv.lock"), declares: packageBlocks(2)},
	{ecosystem: "python", kind: Pinned, match: isPylock},
	{ecosystem: "python", kind: Pinned, match: named("setup.py", "setup.cfg"),
		declares: containsAny("install_requires")},
	{ecosystem: "python", kind: Declared, match: named("pyproject.toml"), locks: pythonLocks,
		sameDirLocks: []string{"requirements.txt"},
		declares:     containsAny("dependencies", "[tool.poetry")},
	{ecosystem: "python", kind: Declared, match: named("Pipfile"), locks: []string{"Pipfile.lock"},
		declares: containsAny("[packages]", "[dev-packages]")},
	{ecosystem: "conda", kind: Pinned, match: named("environment.yml", "environment.yaml"),
		declares: containsAny("dependencies")},

	// A lockfile of version 2 or later keys every package by its node_modules path; version 1 has
	// a dependencies map instead.
	{ecosystem: "npm", kind: Pinned, match: named("package-lock.json", "npm-shrinkwrap.json"),
		declares: containsAny("\"node_modules/", "\"dependencies\"")},
	{ecosystem: "npm", kind: Pinned, match: named("yarn.lock", "pnpm-lock.yaml", "bun.lock"),
		declares: containsAny("version")},
	{ecosystem: "npm", kind: Declared, match: named("package.json"),
		locks:    []string{"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb"},
		declares: containsAny("ependencies\"")},

	{ecosystem: "go", kind: Pinned, match: named("go.mod"), declares: containsAny("require")},

	{ecosystem: "maven", kind: Pinned, match: named("pom.xml"), declares: containsAny("<dependenc", "<parent>")},
	{ecosystem: "gradle", kind: Pinned, match: named("gradle.lockfile")},
	{ecosystem: "gradle", kind: Declared, match: named("build.gradle", "build.gradle.kts"),
		locks: []string{"gradle.lockfile"}, declares: containsAny("dependencies")},

	{ecosystem: "nuget", kind: Pinned, match: named("packages.lock.json", "packages.config")},
	{ecosystem: "nuget", kind: Declared, match: suffixed(".csproj", ".fsproj", ".vbproj"),
		sameDirLocks: []string{"packages.lock.json", "packages.config"},
		declares:     containsAny("PackageReference")},

	{ecosystem: "ruby", kind: Pinned, match: named("Gemfile.lock", "gems.locked")},
	{ecosystem: "ruby", kind: Declared, match: named("Gemfile", "gems.rb"),
		locks: []string{"Gemfile.lock", "gems.locked"}, declares: containsAny("gem ")},

	// Cargo records the crate itself, so one entry is a lockfile with nothing in it.
	{ecosystem: "rust", kind: Pinned, match: named("Cargo.lock"), declares: packageBlocks(2)},
	{ecosystem: "rust", kind: Declared, match: named("Cargo.toml"), locks: []string{"Cargo.lock"},
		declares: containsAny("dependencies]", "dependencies.")},

	{ecosystem: "php", kind: Pinned, match: named("composer.lock"), declares: containsAny("\"version\"")},
	{ecosystem: "php", kind: Declared, match: named("composer.json"), locks: []string{"composer.lock"},
		declares: containsAny("\"require")},
}

// skipDirs hold installed or vendored copies of somebody else's dependencies, whose manifests are
// theirs rather than the project's.
var skipDirs = []string{".git", "node_modules", "vendor", ".venv", "venv", "site-packages", "__pycache__", ".tox"}

// found is a file matched by a rule.
type found struct {
	File
	rule rule
}

// Find returns the dependency files under root, in path order. A file whose content names no
// dependency is left out.
func Find(root string) []File {
	all := find(root)
	out := make([]File, len(all))
	for i, f := range all {
		out[i] = f.File
	}
	return out
}

func find(root string) []found {
	var out []found
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // an unreadable subtree is reported by the scanner, not here
		}
		if d.IsDir() {
			if p != root && slices.Contains(skipDirs, d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return nil //nolint:nilerr // outside the root cannot happen under WalkDir
		}
		rel = filepath.ToSlash(rel)
		for _, r := range rules {
			if !r.match(rel) {
				continue
			}
			if r.declares != nil {
				content, err := os.ReadFile(p) // #nosec G304 G122 -- a file under the tree being scanned
				if err != nil || !r.declares(content) {
					break
				}
			}
			out = append(out, found{File: File{Path: rel, Ecosystem: r.ecosystem, Kind: r.kind}, rule: r})
			break
		}
		return nil
	})
	slices.SortFunc(out, func(a, b found) int { return strings.Compare(a.Path, b.Path) })
	return out
}

// Account returns the dependency files under root that are not in read, each with the reason it
// contributed nothing.
//
// read holds slash-separated paths relative to root, as a scanner names the files it took packages
// from. A declared manifest resolved by a lockfile is not unread: the lockfile is what a scanner
// reads for it, and reporting both would warn about every project that is set up correctly.
func Account(root string, read map[string]bool) []Unread {
	all := find(root)
	present := map[string]bool{}
	for _, f := range all {
		present[f.Path] = true
	}
	var out []Unread
	for _, f := range all {
		if read[f.Path] {
			continue
		}
		switch {
		case f.Kind == Declared:
			if resolved(root, f, present) {
				continue
			}
			out = append(out, Unread{Path: f.Path, Reason: NoLockfile})
		case isRequirements(f.Path) && !hasPin(root, f.Path):
			out = append(out, Unread{Path: f.Path, Reason: Unpinned})
		default:
			out = append(out, Unread{Path: f.Path, Reason: NotRead})
		}
	}
	return out
}

// resolved reports whether a declared manifest has a lockfile a scanner reads for it.
func resolved(root string, f found, present map[string]bool) bool {
	dir := path.Dir(f.Path)
	for _, lock := range f.rule.sameDirLocks {
		if exists(root, path.Join(dir, lock), present) {
			return true
		}
	}
	for {
		for _, lock := range f.rule.locks {
			if exists(root, path.Join(dir, lock), present) {
				return true
			}
		}
		if dir == "." || dir == "/" {
			return false
		}
		dir = path.Dir(dir)
	}
}

// exists asks the walk first and the disk second: a lockfile that declares nothing is not in the
// walk's results, and it still resolves its manifest.
func exists(root, rel string, present map[string]bool) bool {
	if present[rel] {
		return true
	}
	info, err := os.Stat(filepath.Join(root, filepath.FromSlash(rel)))
	return err == nil && info.Mode().IsRegular()
}

// requirementLines yields the entries of a requirements file: not blank, not a comment, not an
// option such as -r or --index-url.
func requirementLines(content []byte) []string {
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(content))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if i := strings.Index(line, " #"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		out = append(out, line)
	}
	return out
}

func hasRequirement(content []byte) bool { return len(requirementLines(content)) > 0 }

// hasPin reports whether any entry in a requirements file names an exact version.
func hasPin(root, rel string) bool {
	content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel))) // #nosec G304 -- under the scanned tree
	if err != nil {
		return false
	}
	for _, line := range requirementLines(content) {
		if strings.Contains(line, "==") {
			return true
		}
	}
	return false
}
