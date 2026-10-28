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
	"encoding/json"
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
	// formats are the file names the rule recognizes, as Formats lists them: an exact base name, or
	// `*` followed by a suffix, as in `*.csproj`.
	formats []string
	// match, where set, recognizes a family of names formats spells with one member:
	// requirements-dev.txt is a requirements.txt, and pylock.dev.toml a pylock.toml. Nil matches
	// formats exactly.
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
	//
	// A lockfile it rejects is left out of the walk and still resolves the manifests naming it, so
	// for a lockfile it returns false only on content that is the format and pins nothing. Content
	// it cannot place in the format declares, which keeps the file in the walk and reported when no
	// scanner reads it.
	declares func(content []byte) bool
}

// matches reports whether a file, by its slash-separated path, is this kind.
func (r rule) matches(rel string) bool {
	if r.match != nil {
		return r.match(rel)
	}
	return r.format(rel) != ""
}

// format is the entry in formats a path matches exactly, or "" for none.
func (r rule) format(rel string) string {
	base := path.Base(rel)
	for _, f := range r.formats {
		if suffix, ok := strings.CutPrefix(f, "*"); ok {
			if strings.HasSuffix(base, suffix) && base != suffix {
				return f
			}
		} else if base == f {
			return f
		}
	}
	return ""
}

// Format is one name of dependency file Draugr recognizes.
type Format struct {
	// Name is the file's base name, or `*` and a suffix for a family such as `*.csproj`.
	Name      string
	Ecosystem string
	Kind      Kind
}

// Formats lists every name of dependency file the rules recognize, in rule order.
func Formats() []Format {
	var out []Format
	for _, r := range rules {
		for _, f := range r.formats {
			out = append(out, Format{Name: f, Ecosystem: r.ecosystem, Kind: r.kind})
		}
	}
	return out
}

// lockfiles are the formats a package manager writes from a manifest: every dependency resolved and
// pinned. A change to a dependency is made in the manifest and the lockfile follows.
var lockfiles = map[string]bool{
	"Pipfile.lock": true, "poetry.lock": true, "pdm.lock": true, "uv.lock": true, "pylock.toml": true,
	"package-lock.json": true, "npm-shrinkwrap.json": true, "yarn.lock": true, "pnpm-lock.yaml": true,
	"bun.lock": true, "bun.lockb": true, "gradle.lockfile": true, "packages.lock.json": true,
	"Gemfile.lock": true, "gems.locked": true, "Cargo.lock": true, "composer.lock": true,
}

// IsLockfile reports whether a path is a lockfile, by the format FormatOf names for it.
func IsLockfile(rel string) bool { return lockfiles[FormatOf(rel)] }

// FormatOf names the format a path is, as Formats lists it, or "" for a path no rule recognizes.
// A member of a family named by one entry, requirements-dev.txt or pylock.dev.toml, is that entry.
// Content is not read, so a file that declares nothing still has a format.
func FormatOf(rel string) string {
	for _, r := range rules {
		if !r.matches(rel) {
			continue
		}
		if f := r.format(rel); f != "" {
			return f
		}
		return r.formats[0]
	}
	return ""
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

// sourcedPackages reports whether a Cargo.lock or uv.lock pins a package from outside the project.
// Both tools write a [[package]] entry for the project and for every workspace member as well as
// for each dependency, so counting entries takes a workspace for a project with dependencies. Only
// a dependency's entry has a source naming where it was fetched from: a registry, a git repository,
// a URL. local are the sources that name one of the project's own directories instead, which Cargo
// leaves out and uv writes. A file with no entry at all is not that tool's lockfile.
func sourcedPackages(local ...string) func([]byte) bool {
	return func(content []byte) bool {
		if !bytes.Contains(content, []byte("[[package]]")) {
			return true
		}
		for line := range bytes.Lines(content) {
			src, ok := bytes.CutPrefix(line, []byte("source = "))
			if ok && !slices.ContainsFunc(local, func(l string) bool { return bytes.HasPrefix(src, []byte(l)) }) {
				return true
			}
		}
		return false
	}
}

// metadataPackages reports whether a Poetry or PDM lockfile holds a [[package]] entry. A file with
// none pins nothing only when it carries the [metadata] table both tools write.
func metadataPackages(content []byte) bool {
	return bytes.Contains(content, []byte("[[package]]")) || !bytes.Contains(content, []byte("[metadata]"))
}

// yarnLockPins reports whether a yarn.lock pins a package. Yarn 1 writes an entry only for a
// package and gives each a version, so a file with its header and no version pins nothing. Berry
// writes an entry for the project and for each workspace as well, resolved under the workspace:
// protocol, so a Berry file pins a package when an entry resolves to anything else.
func yarnLockPins(content []byte) bool {
	if bytes.HasPrefix(content, []byte("__metadata:")) || bytes.Contains(content, []byte("\n__metadata:")) {
		return berryLockPins(content)
	}
	return bytes.Contains(content, []byte("version")) || !bytes.Contains(content, []byte("# yarn lockfile v1"))
}

// berryLockPins reports whether a Berry yarn.lock holds an entry resolved outside the project's
// workspaces. Berry always writes the root workspace, so a file resolving no entry at all is not
// one it wrote.
func berryLockPins(content []byte) bool {
	workspaces := 0
	for line := range bytes.Lines(content) {
		resolution, ok := bytes.CutPrefix(bytes.TrimSpace(line), []byte("resolution: "))
		if !ok {
			continue
		}
		if !bytes.Contains(resolution, []byte("@workspace:")) {
			return true
		}
		workspaces++
	}
	return workspaces == 0
}

// pnpmLockPins reports whether a pnpm-lock.yaml pins a package. Lockfile versions 5 to 9 keep
// resolved packages under a top-level packages key, which pnpm leaves out of a lockfile holding
// workspace links and nothing else.
func pnpmLockPins(content []byte) bool {
	return bytes.HasPrefix(content, []byte("packages:")) || bytes.Contains(content, []byte("\npackages:")) ||
		!bytes.Contains(content, []byte("lockfileVersion:"))
}

// jsonObject decodes the top-level members of a JSON object, accepting the comments and trailing
// commas of the JSONC that bun.lock is written in. ok is false for anything but an object.
func jsonObject(content []byte) (top map[string]json.RawMessage, ok bool) {
	if err := json.Unmarshal(stripJSONC(content), &top); err != nil || top == nil {
		return nil, false
	}
	return top, true
}

// stripJSONC removes comments, and each comma followed by a closing bracket, outside strings.
func stripJSONC(in []byte) []byte {
	out := make([]byte, 0, len(in))
	for i := 0; i < len(in); {
		switch {
		case in[i] == '"':
			end := stringEnd(in, i)
			out = append(out, in[i:end]...)
			i = end
		case bytes.HasPrefix(in[i:], []byte("//")), bytes.HasPrefix(in[i:], []byte("/*")):
			i = commentEnd(in, i)
		case in[i] == ',' && closes(in, i+1):
			i++
		default:
			out = append(out, in[i])
			i++
		}
	}
	return out
}

// stringEnd is the index after the string opening at i, or len(in) for one never closed.
func stringEnd(in []byte, i int) int {
	for j := i + 1; j < len(in); j++ {
		switch in[j] {
		case '\\':
			j++
		case '"':
			return j + 1
		}
	}
	return len(in)
}

// commentEnd is the index after the comment opening at i: the end of the line for //, past the
// closing */ for a block, or len(in) for a block never closed.
func commentEnd(in []byte, i int) int {
	if in[i+1] == '/' {
		if n := bytes.IndexByte(in[i:], '\n'); n >= 0 {
			return i + n
		}
		return len(in)
	}
	if n := bytes.Index(in[i+2:], []byte("*/")); n >= 0 {
		return i + 2 + n + 2
	}
	return len(in)
}

// closes reports whether the next token from i, past whitespace and comments, closes an object or
// an array.
func closes(in []byte, i int) bool {
	for i < len(in) {
		switch {
		case in[i] == ' ', in[i] == '\t', in[i] == '\r', in[i] == '\n':
			i++
		case bytes.HasPrefix(in[i:], []byte("//")), bytes.HasPrefix(in[i:], []byte("/*")):
			i = commentEnd(in, i)
		default:
			return in[i] == '}' || in[i] == ']'
		}
	}
	return false
}

// members is the number of members in a JSON object or array, or -1 for any other value.
func members(raw json.RawMessage) int {
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) == nil && obj != nil {
		return len(obj)
	}
	var arr []json.RawMessage
	if json.Unmarshal(raw, &arr) == nil && arr != nil {
		return len(arr)
	}
	return -1
}

// bunLockPins reports whether a text bun.lock pins a package that is not one of the project's own
// workspaces. Each entry under packages is an array whose first member is the package and its
// resolution: `lodash@4.17.21`, `lodash@github:lodash/lodash#ded9bc6`, `a@workspace:packages/a`.
// Bun deletes a lockfile that would hold no package, so the one that pins nothing holds workspaces.
func bunLockPins(content []byte) bool {
	top, ok := jsonObject(content)
	if !ok || top["lockfileVersion"] == nil {
		return true
	}
	var packages map[string][]json.RawMessage
	if err := json.Unmarshal(top["packages"], &packages); err != nil {
		return true
	}
	for _, entry := range packages {
		var id string
		if len(entry) == 0 || json.Unmarshal(entry[0], &id) != nil || !strings.Contains(id, "@workspace:") {
			return true
		}
	}
	return false
}

// npmLockPins reports whether a package-lock.json or npm-shrinkwrap.json pins a package: one
// installed under packages (lockfile version 2 and later), or an entry under dependencies (version
// 1). A version 2 file repeats its tree under dependencies for npm 6, with each workspace member as
// a file: entry, so where packages is present it decides alone.
func npmLockPins(content []byte) bool {
	top, ok := jsonObject(content)
	if !ok || top["lockfileVersion"] == nil {
		return true
	}
	if raw := top["packages"]; raw != nil {
		return npmPackagesPin(raw)
	}
	return top["dependencies"] != nil && members(top["dependencies"]) != 0
}

// npmPackagesPin reports whether the packages of a lockfile version 2 or later hold an installed
// package. An installed package is keyed by its path under node_modules. The project's own folders
// are keyed by their path alone, "" for the root and packages/a for a workspace member, and a member
// installed into node_modules is a link to its folder, so a workspace whose members depend on
// nothing outside it holds no installed package.
func npmPackagesPin(raw json.RawMessage) bool {
	var packages map[string]json.RawMessage
	if json.Unmarshal(raw, &packages) != nil {
		return true
	}
	for key, entry := range packages {
		var pkg struct {
			Link bool `json:"link"`
		}
		if json.Unmarshal(entry, &pkg) != nil {
			return true
		}
		if !pkg.Link && strings.Contains("/"+key, "/node_modules/") {
			return true
		}
	}
	return false
}

// pipfileLockPins reports whether a Pipfile.lock pins a package in any group: default, develop,
// or a named category. Every member but _meta is a group.
func pipfileLockPins(content []byte) bool {
	top, ok := jsonObject(content)
	if !ok || top["_meta"] == nil {
		return true
	}
	for name, group := range top {
		if name != "_meta" && members(group) != 0 {
			return true
		}
	}
	return false
}

// composerLockPins reports whether a composer.lock pins a package in packages or packages-dev.
func composerLockPins(content []byte) bool {
	top, ok := jsonObject(content)
	if !ok || top["packages"] == nil {
		return true
	}
	return members(top["packages"]) != 0 || (top["packages-dev"] != nil && members(top["packages-dev"]) != 0)
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
	{ecosystem: "python", kind: Pinned, formats: []string{"requirements.txt"}, match: isRequirements, declares: hasRequirement},
	{ecosystem: "python", kind: Pinned, formats: []string{"Pipfile.lock"}, declares: pipfileLockPins},
	{ecosystem: "python", kind: Pinned, formats: []string{"poetry.lock", "pdm.lock"}, declares: metadataPackages},
	// uv gives the project and each workspace member a source naming its directory: virtual for a
	// project with no build system, editable for one with, and directory for a path dependency.
	{ecosystem: "python", kind: Pinned, formats: []string{"uv.lock"},
		declares: sourcedPackages("{ virtual = ", "{ editable = ", "{ directory = ")},
	{ecosystem: "python", kind: Pinned, formats: []string{"pylock.toml"}, match: isPylock},
	{ecosystem: "python", kind: Pinned, formats: []string{"setup.py", "setup.cfg"},
		declares: containsAny("install_requires")},
	{ecosystem: "python", kind: Declared, formats: []string{"pyproject.toml"}, locks: pythonLocks,
		sameDirLocks: []string{"requirements.txt"},
		declares:     containsAny("dependencies", "[tool.poetry")},
	{ecosystem: "python", kind: Declared, formats: []string{"Pipfile"}, locks: []string{"Pipfile.lock"},
		declares: containsAny("[packages]", "[dev-packages]")},
	{ecosystem: "conda", kind: Pinned, formats: []string{"environment.yml", "environment.yaml"},
		declares: containsAny("dependencies")},

	{ecosystem: "npm", kind: Pinned, formats: []string{"package-lock.json", "npm-shrinkwrap.json"},
		declares: npmLockPins},
	{ecosystem: "npm", kind: Pinned, formats: []string{"yarn.lock"}, declares: yarnLockPins},
	{ecosystem: "npm", kind: Pinned, formats: []string{"pnpm-lock.yaml"}, declares: pnpmLockPins},
	{ecosystem: "npm", kind: Pinned, formats: []string{"bun.lock"}, declares: bunLockPins},
	// Bun's binary lockfile, which Bun 1.2 replaced with the text bun.lock. It pins a package.json
	// as well as any lockfile does, so the manifest is resolved; recognized in its own right so that
	// a scanner reading nothing from it is reported rather than passed over.
	{ecosystem: "npm", kind: Pinned, formats: []string{"bun.lockb"}},
	{ecosystem: "npm", kind: Declared, formats: []string{"package.json"},
		locks:    []string{"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb"},
		declares: containsAny("ependencies\"")},

	{ecosystem: "go", kind: Pinned, formats: []string{"go.mod"}, declares: containsAny("require")},

	{ecosystem: "maven", kind: Pinned, formats: []string{"pom.xml"}, declares: containsAny("<dependenc", "<parent>")},
	{ecosystem: "gradle", kind: Pinned, formats: []string{"gradle.lockfile"}},
	{ecosystem: "gradle", kind: Declared, formats: []string{"build.gradle", "build.gradle.kts"},
		locks: []string{"gradle.lockfile"}, declares: containsAny("dependencies")},

	{ecosystem: "nuget", kind: Pinned, formats: []string{"packages.lock.json", "packages.config"}},
	{ecosystem: "nuget", kind: Declared, formats: []string{"*.csproj", "*.fsproj", "*.vbproj"},
		sameDirLocks: []string{"packages.lock.json", "packages.config"},
		declares:     containsAny("PackageReference")},

	{ecosystem: "ruby", kind: Pinned, formats: []string{"Gemfile.lock", "gems.locked"}},
	{ecosystem: "ruby", kind: Declared, formats: []string{"Gemfile", "gems.rb"},
		locks: []string{"Gemfile.lock", "gems.locked"}, declares: containsAny("gem ")},

	// Cargo gives a crate built from a path, the project and each workspace member, no source.
	{ecosystem: "rust", kind: Pinned, formats: []string{"Cargo.lock"}, declares: sourcedPackages()},
	{ecosystem: "rust", kind: Declared, formats: []string{"Cargo.toml"}, locks: []string{"Cargo.lock"},
		declares: containsAny("dependencies]", "dependencies.")},

	{ecosystem: "php", kind: Pinned, formats: []string{"composer.lock"}, declares: composerLockPins},
	{ecosystem: "php", kind: Declared, formats: []string{"composer.json"}, locks: []string{"composer.lock"},
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
	all, _ := find(root)
	out := make([]File, len(all))
	for i, f := range all {
		out[i] = f.File
	}
	return out
}

// find returns the dependency files under root, in path order, and the paths it left out because
// their content is the format and names no dependency.
//
// A file that cannot be read is kept: nothing shows it names no dependency, and a scanner that
// cannot read it either is then reported rather than passed over.
func find(root string) (out []found, empty map[string]bool) {
	empty = map[string]bool{}
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
			if !r.matches(rel) {
				continue
			}
			if r.declares != nil {
				content, err := os.ReadFile(p) // #nosec G304 G122 -- a file under the tree being scanned
				if err == nil && !r.declares(content) {
					empty[rel] = true
					break
				}
			}
			out = append(out, found{File: File{Path: rel, Ecosystem: r.ecosystem, Kind: r.kind}, rule: r})
			break
		}
		return nil
	})
	slices.SortFunc(out, func(a, b found) int { return strings.Compare(a.Path, b.Path) })
	return out, empty
}

// Account returns the dependency files under root that are not in read, each with the reason it
// contributed nothing.
//
// read holds slash-separated paths relative to root, as a scanner names the files it took packages
// from. A declared manifest resolved by a lockfile is not unread: the lockfile is what a scanner
// reads for it, and reporting both would warn about every project that is set up correctly.
//
// A lockfile resolves its manifest when the walk holds it, so that it is reported itself if no
// scanner reads it, or when the walk left it out as the format with nothing in it. A file merely
// named like a lockfile does neither, because resolving on the name alone would leave the manifest
// and the lockfile both unreported with nothing read from either.
func Account(root string, read map[string]bool) []Unread {
	all, locks := find(root)
	for _, f := range all {
		locks[f.Path] = true
	}
	var out []Unread
	for _, f := range all {
		if read[f.Path] {
			continue
		}
		switch {
		case f.Kind == Declared:
			if resolved(f, locks) {
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

// resolved reports whether a declared manifest has a lockfile among locks, the paths Account found
// to resolve one.
func resolved(f found, locks map[string]bool) bool {
	dir := path.Dir(f.Path)
	for _, lock := range f.rule.sameDirLocks {
		if locks[path.Join(dir, lock)] {
			return true
		}
	}
	for {
		for _, lock := range f.rule.locks {
			if locks[path.Join(dir, lock)] {
				return true
			}
		}
		if dir == "." || dir == "/" {
			return false
		}
		dir = path.Dir(dir)
	}
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
