package manifests

import (
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// tree writes files under a fresh directory, keyed by slash-separated path.
func tree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, content := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

const (
	npmLock   = `{"lockfileVersion":3,"packages":{"node_modules/lodash":{"version":"4.17.20"}}}`
	npmPkg    = `{"name":"web","dependencies":{"lodash":"4.17.20"}}`
	pyproject = "[project]\nname = \"api\"\ndependencies = [\"flask\"]\n"
	cargoLock = "[[package]]\nname = \"app\"\n\n[[package]]\nname = \"serde\"\n" +
		"source = \"registry+https://github.com/rust-lang/crates.io-index\"\n"
	cargoToml = "[package]\nname = \"app\"\n\n[dependencies]\nserde = \"1\"\n"
	csproj    = `<Project><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.1" /></ItemGroup></Project>`
)

func paths(files []File) []string {
	out := make([]string, len(files))
	for i, f := range files {
		out[i] = f.Path
	}
	return out
}

func TestFindRecognizesDependencyFilesAndSkipsInstalledCopies(t *testing.T) {
	root := tree(t, map[string]string{
		"requirements.txt":                "flask==2.0.0\n",
		"requirements/base.txt":           "django==4.2\n",
		"dev-requirements.txt":            "pytest\n",
		"notes.txt":                       "flask==2.0.0\n",
		"pylock.dev.toml":                 "[[packages]]\n",
		"web/package.json":                npmPkg,
		"web/package-lock.json":           npmLock,
		"web/node_modules/x/package.json": npmPkg,
		"vendor/github.com/y/go.mod":      "module y\nrequire z v1.0.0\n",
		"svc/App.csproj":                  csproj,
		".venv/lib/requirements.txt":      "six==1.0\n",
		"go.mod":                          "module app\n\nrequire golang.org/x/net v0.1.0\n",
	})
	want := []string{
		"dev-requirements.txt", "go.mod", "pylock.dev.toml", "requirements.txt", "requirements/base.txt",
		"svc/App.csproj", "web/package-lock.json", "web/package.json",
	}
	if got := paths(Find(root)); !reflect.DeepEqual(got, want) {
		t.Errorf("Find = %v, want %v", got, want)
	}
}

// A file with nothing in it to read is not a manifest anybody left unread, and reporting it would
// warn about every project with no dependencies. Lockfiles are held to the same rule by
// TestRealLockfilesAreClassifiedByWhatTheyPin.
func TestFindLeavesOutFilesThatDeclareNothing(t *testing.T) {
	root := tree(t, map[string]string{
		"go.mod":           "module app\n\ngo 1.26\n",
		"pyproject.toml":   "[tool.ruff]\nline-length = 100\n",
		"requirements.txt": "# nothing yet\n-r base.txt\n",
		"package.json":     `{"name":"x","scripts":{"test":"jest"}}`,
		"App.csproj":       `<Project Sdk="Microsoft.NET.Sdk"></Project>`,
	})
	if got := Find(root); len(got) != 0 {
		t.Errorf("Find = %v, want nothing", paths(got))
	}
}

func TestFindReadsEachEcosystem(t *testing.T) {
	root := tree(t, map[string]string{
		"py/setup.py":           "setup(install_requires=['flask'])\n",
		"py/Pipfile":            "[packages]\nflask = \"*\"\n",
		"conda/environment.yml": "dependencies:\n  - numpy\n",
		"jvm/pom.xml":           "<project><dependencies/></project>",
		"jvm/build.gradle.kts":  "dependencies { implementation(\"a:b:1\") }\n",
		"jvm/gradle.lockfile":   "a:b:1=runtimeClasspath\n",
		"rb/Gemfile":            "gem 'rails'\n",
		"rb/Gemfile.lock":       "GEM\n  specs:\n    rails (7.0)\n",
		"rs/Cargo.toml":         cargoToml,
		"php/composer.json":     `{"require": {"monolog/monolog": "^3"}}`,
		"php/composer.lock":     `{"packages": [{"name": "monolog/monolog", "version": "3.0.0"}]}`,
		"net/packages.config":   `<packages><package id="x" version="1"/></packages>`,
		"js/yarn.lock":          "lodash@^4:\n  version \"4.17.21\"\n",
		"bun/bun.lockb":         "#!/usr/bin/env bun\nbun-lockfile-format-v0\n",
		"py2/poetry.lock":       "[[package]]\nname = \"flask\"\n",
		"py2/pyproject.toml":    "[tool.poetry]\nname = \"x\"\n",
	})
	got := map[string]File{}
	for _, f := range Find(root) {
		got[f.Path] = f
	}
	for rel, want := range map[string]struct {
		ecosystem string
		kind      Kind
	}{
		"py/setup.py": {"python", Pinned}, "py/Pipfile": {"python", Declared},
		"conda/environment.yml": {"conda", Pinned}, "jvm/pom.xml": {"maven", Pinned},
		"jvm/build.gradle.kts": {"gradle", Declared}, "jvm/gradle.lockfile": {"gradle", Pinned},
		"rb/Gemfile": {"ruby", Declared}, "rb/Gemfile.lock": {"ruby", Pinned},
		"rs/Cargo.toml": {"rust", Declared}, "php/composer.json": {"php", Declared},
		"php/composer.lock": {"php", Pinned}, "net/packages.config": {"nuget", Pinned},
		"js/yarn.lock": {"npm", Pinned}, "bun/bun.lockb": {"npm", Pinned},
		"py2/poetry.lock":    {"python", Pinned},
		"py2/pyproject.toml": {"python", Declared},
	} {
		f, ok := got[rel]
		if !ok {
			t.Errorf("%s not found", rel)
			continue
		}
		if f.Ecosystem != want.ecosystem || f.Kind != want.kind {
			t.Errorf("%s = %s/%d, want %s/%d", rel, f.Ecosystem, f.Kind, want.ecosystem, want.kind)
		}
	}
}

func TestAccountNamesWhatWasNotReadAndWhy(t *testing.T) {
	root := tree(t, map[string]string{
		"api/pyproject.toml":       pyproject,
		"api/requirements-dev.txt": "pytest==8.0.0\n",
		"api/requirements.txt":     "flask\nrequests>=2\n",
		"web/package.json":         npmPkg,
		"svc/App.csproj":           csproj,
		"lib/package.json":         npmPkg,
		"lib/package-lock.json":    npmLock,
		"crate/Cargo.toml":         cargoToml,
		"crate/Cargo.lock":         cargoLock,
		"go.mod":                   "module app\nrequire golang.org/x/net v0.1.0\n",
	})
	read := map[string]bool{"lib/package-lock.json": true, "crate/Cargo.lock": true, "go.mod": true}
	// The pyproject.toml is resolved by the requirements.txt beside it, which is reported for
	// itself: one problem, stated once.
	want := []Unread{
		{Path: "api/requirements-dev.txt", Reason: NotRead},
		{Path: "api/requirements.txt", Reason: Unpinned},
		{Path: "svc/App.csproj", Reason: NoLockfile},
		{Path: "web/package.json", Reason: NoLockfile},
	}
	if got := Account(root, read); !reflect.DeepEqual(got, want) {
		t.Errorf("Account =\n%v\nwant\n%v", got, want)
	}
}

func TestAccountReportsNothingWhenEveryFileWasRead(t *testing.T) {
	root := tree(t, map[string]string{
		"web/package.json":      npmPkg,
		"web/package-lock.json": npmLock,
		"requirements.txt":      "flask==2.0.0\n",
	})
	read := map[string]bool{"web/package-lock.json": true, "requirements.txt": true}
	if got := Account(root, read); len(got) != 0 {
		t.Errorf("Account = %v, want nothing", got)
	}
}

// A workspace keeps one lockfile at its root for every member, so a member's manifest is resolved
// from above. A .csproj's lockfile is its own and resolves nothing but it.
func TestAccountResolvesFromAncestorsExceptWhereTheLockIsPerProject(t *testing.T) {
	root := tree(t, map[string]string{
		"package.json":            npmPkg,
		"package-lock.json":       npmLock,
		"packages/a/package.json": npmPkg,
		"packages.lock.json":      `{"version":1,"dependencies":{}}`,
		"src/Api/Api.csproj":      csproj,
		"py/pyproject.toml":       pyproject,
		"py/requirements.txt":     "flask==2.0.0\n",
		"py/sub/pyproject.toml":   pyproject,
	})
	read := map[string]bool{
		"package-lock.json": true, "packages.lock.json": true, "py/requirements.txt": true,
	}
	want := []Unread{
		{Path: "py/sub/pyproject.toml", Reason: NoLockfile},
		{Path: "src/Api/Api.csproj", Reason: NoLockfile},
	}
	if got := Account(root, read); !reflect.DeepEqual(got, want) {
		t.Errorf("Account =\n%v\nwant\n%v", got, want)
	}
}

// The bun.lock files below are what `bun install --lockfile-only` writes, from Bun 1.4.2 (the
// oven/bun:1 image the js-bun scenario pins), for a registry dependency, a dependency on a git
// repository, and a workspace with no dependency outside itself. Bun deletes a lockfile that would
// hold no package, so the third is the emptiest one it writes.
const (
	bunPkg      = `{"name":"web","version":"1.0.0","private":true,"dependencies":{"lodash":"4.17.20"}}`
	bunRegistry = `{
  "lockfileVersion": 2,
  "configVersion": 1,
  "workspaces": {
    "": {
      "name": "web",
      "dependencies": {
        "lodash": "4.17.20",
      },
    },
  },
  "packages": {
    "lodash": ["lodash@4.17.20", "", {}, "sha512-PlhdFcillOINfeV7Ni6oF1TAEayyZBoZ8bcshTHqOYJYlrqzRK5hagpagky5o4HfCzzd1TRkXPMFq6cKk9rGmA=="],
  }
}
`
	bunGit = `{
  "lockfileVersion": 2,
  "configVersion": 1,
  "workspaces": {
    "": {
      "name": "gitdep",
      "dependencies": {
        "lodash": "github:lodash/lodash#4.17.20",
      },
    },
  },
  "packages": {
    "lodash": ["lodash@github:lodash/lodash#ded9bc6", {}, "lodash-lodash-ded9bc6", "sha512-tKO08eF6CJR9P1zB6cAHcq+1srktfxCnE4SNKllWI/+Dtm9g/kq6BdGzwKRCvCcWd3XFuw1noOT7XgxJ4WWyfg=="],
  }
}
`
	bunWorkspaces = `{
  "lockfileVersion": 2,
  "configVersion": 1,
  "workspaces": {
    "": {
      "name": "mono",
    },
    "packages/a": {
      "name": "a",
      "version": "1.0.0",
    },
  },
  "packages": {
    "a": ["a@workspace:packages/a"],
  }
}
`
)

// A bun.lock is recognized by the packages it pins, whatever they resolve from, and none of the
// three carries a "version" key at its root.
func TestFindRecognizesTheBunLockBunWrites(t *testing.T) {
	root := tree(t, map[string]string{
		"registry/bun.lock":            bunRegistry,
		"remote/bun.lock":              bunGit,
		"mono/bun.lock":                bunWorkspaces,
		"mono/package.json":            `{"name":"mono","workspaces":["packages/*"]}`,
		"mono/packages/a/package.json": `{"name":"a","version":"1.0.0"}`,
	})
	want := []string{"registry/bun.lock", "remote/bun.lock"}
	if got := paths(Find(root)); !reflect.DeepEqual(got, want) {
		t.Errorf("Find = %v, want %v", got, want)
	}
}

// A bun.lock nothing was read from is reported, and the package.json it resolves is not: the lock
// is what a scanner reads for it.
func TestAccountReportsABunLockNoScannerRead(t *testing.T) {
	root := tree(t, map[string]string{
		"remote/package.json":   `{"name":"gitdep","dependencies":{"lodash":"github:lodash/lodash#4.17.20"}}`,
		"remote/bun.lock":       bunGit,
		"registry/package.json": bunPkg,
		"registry/bun.lock":     bunRegistry,
	})
	want := []Unread{{Path: "remote/bun.lock", Reason: NotRead}}
	if got := Account(root, map[string]bool{"registry/bun.lock": true}); !reflect.DeepEqual(got, want) {
		t.Errorf("Account =\n%v\nwant\n%v", got, want)
	}
}

// realLockfiles are lockfiles written by the tools themselves, under testdata/lockfiles, each in a
// directory named for the tool and version that wrote it and stored with the manifests it was
// written from. Every file ends in .fixture so that no scanner reading this repository takes them
// for its own dependencies; realFiles restores the names.
//
// Each was written in the tool's own image, as the calling user, from the manifests beside it:
//
//   - npm 11.6.1 (lockfile version 3) in node:24.11.0, npm 8.19.4 (version 2) in node:16.20.2,
//     and npm 6.14.18 (version 1) in node:14.21.3: npm install --package-lock-only, then
//     npm shrinkwrap for the shrinkwrap cases.
//   - pnpm 12.15.0 (lockfile version 9.0) and pnpm 7.33.7 (version 5.4) in node:24.11.0:
//     pnpm install --lockfile-only. pnpm 7 writes no lockfile for a project with no dependency.
//   - Yarn 1.22.22 in node:24.11.0: yarn install. Yarn 4.10.3 through Corepack in node:24.11.0:
//     yarn install --mode=update-lockfile.
//   - Pipenv 2026.10.3, Poetry 2.5.1 and PDM 2.29.4 in python:3.13.7: pipenv lock, poetry lock,
//     pdm lock.
//   - uv 0.9.5 in ghcr.io/astral-sh/uv:0.9.5-python3.13-bookworm: uv lock.
//   - Cargo 1.90.0 in rust:1.90.0: cargo generate-lockfile.
//   - Composer 2.8.12 in composer:2.8.12: composer update --no-install.
//
// The cases: empty has no dependency, registry one from the ecosystem's registry, vcs one from a
// git repository and nothing else, and workspace two members, one depending on the other, with
// nothing from outside the project.
var realLockfiles = []struct {
	dir, lock string
	pins      bool
}{
	{"npm-11.6.1/empty", "package-lock.json", false},
	{"npm-11.6.1/registry", "package-lock.json", true},
	{"npm-11.6.1/vcs", "package-lock.json", true},
	{"npm-11.6.1/workspace", "package-lock.json", false},
	{"npm-11.6.1/shrinkwrap-empty", "npm-shrinkwrap.json", false},
	{"npm-11.6.1/shrinkwrap-registry", "npm-shrinkwrap.json", true},
	{"npm-8.19.4/empty", "package-lock.json", false},
	{"npm-8.19.4/registry", "package-lock.json", true},
	{"npm-8.19.4/vcs", "package-lock.json", true},
	{"npm-8.19.4/workspace", "package-lock.json", false},
	{"npm-6.14.18/empty", "package-lock.json", false},
	{"npm-6.14.18/registry", "package-lock.json", true},
	{"npm-6.14.18/vcs", "package-lock.json", true},
	{"pnpm-12.15.0/empty", "pnpm-lock.yaml", false},
	{"pnpm-12.15.0/registry", "pnpm-lock.yaml", true},
	{"pnpm-12.15.0/vcs", "pnpm-lock.yaml", true},
	{"pnpm-12.15.0/workspace", "pnpm-lock.yaml", false},
	{"pnpm-7.33.7/registry", "pnpm-lock.yaml", true},
	{"pnpm-7.33.7/vcs", "pnpm-lock.yaml", true},
	{"pnpm-7.33.7/workspace", "pnpm-lock.yaml", false},
	{"yarn-1.22.22/empty", "yarn.lock", false},
	{"yarn-1.22.22/registry", "yarn.lock", true},
	{"yarn-1.22.22/vcs", "yarn.lock", true},
	{"yarn-1.22.22/workspace", "yarn.lock", false},
	{"yarn-4.10.3/empty", "yarn.lock", false},
	{"yarn-4.10.3/registry", "yarn.lock", true},
	{"yarn-4.10.3/vcs", "yarn.lock", true},
	{"yarn-4.10.3/workspace", "yarn.lock", false},
	{"pipenv-2026.10.3/empty", "Pipfile.lock", false},
	{"pipenv-2026.10.3/registry", "Pipfile.lock", true},
	{"pipenv-2026.10.3/vcs", "Pipfile.lock", true},
	{"poetry-2.5.1/empty", "poetry.lock", false},
	{"poetry-2.5.1/registry", "poetry.lock", true},
	{"poetry-2.5.1/vcs", "poetry.lock", true},
	{"pdm-2.29.4/empty", "pdm.lock", false},
	{"pdm-2.29.4/registry", "pdm.lock", true},
	{"pdm-2.29.4/vcs", "pdm.lock", true},
	{"uv-0.9.5/empty", "uv.lock", false},
	{"uv-0.9.5/registry", "uv.lock", true},
	{"uv-0.9.5/vcs", "uv.lock", true},
	{"uv-0.9.5/workspace", "uv.lock", false},
	{"cargo-1.90.0/empty", "Cargo.lock", false},
	{"cargo-1.90.0/registry", "Cargo.lock", true},
	{"cargo-1.90.0/vcs", "Cargo.lock", true},
	{"cargo-1.90.0/workspace", "Cargo.lock", false},
	{"composer-2.8.12/empty", "composer.lock", false},
	{"composer-2.8.12/registry", "composer.lock", true},
	{"composer-2.8.12/vcs", "composer.lock", true},
}

// realFiles reads one case under testdata/lockfiles, keyed by the slash-separated path the tool
// wrote each file at.
func realFiles(t *testing.T, dir string) map[string]string {
	t.Helper()
	src := filepath.Join("testdata", "lockfiles", filepath.FromSlash(dir))
	files := map[string]string{}
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		content, err := os.ReadFile(p) // #nosec G304 G122 -- a fixture under testdata
		if err != nil {
			return err
		}
		files[strings.TrimSuffix(filepath.ToSlash(rel), ".fixture")] = string(content)
		return nil
	})
	if err != nil || len(files) == 0 {
		t.Fatalf("reading %s: %v (%d files)", src, err, len(files))
	}
	return files
}

// A lockfile a package manager wrote stays in the walk when it pins a package, from a registry or
// from a git repository, and is left out when it holds nothing but the project: no dependency, or
// workspace members linked to each other. Either way the project's manifests are accounted for,
// by the lockfile a scanner read or by the one with nothing in it to read.
func TestRealLockfilesAreClassifiedByWhatTheyPin(t *testing.T) {
	for _, c := range realLockfiles {
		t.Run(c.dir, func(t *testing.T) {
			root := tree(t, realFiles(t, c.dir))
			if _, err := os.Stat(filepath.Join(root, c.lock)); err != nil {
				t.Fatalf("the case holds no %s: %v", c.lock, err)
			}
			kept := slices.Contains(paths(Find(root)), c.lock)
			if kept != c.pins {
				t.Errorf("%s kept in the walk = %v, want %v", c.lock, kept, c.pins)
			}
			read := map[string]bool{}
			if c.pins {
				read[c.lock] = true
			}
			if got := Account(root, read); len(got) != 0 {
				t.Errorf("Account = %v, want nothing", got)
			}
		})
	}
}

// emptyLocks are the real lockfiles that pin nothing, each with the manifests it was written from,
// and the bun.lock of a workspace, which is the emptiest one Bun writes.
func emptyLocks(t *testing.T) map[string]map[string]string {
	t.Helper()
	out := map[string]map[string]string{
		"bun workspace": {
			"package.json":            `{"name":"mono","workspaces":["packages/*"],"devDependencies":{}}`,
			"packages/a/package.json": `{"name":"a","version":"1.0.0","dependencies":{}}`,
			"bun.lock":                bunWorkspaces,
		},
	}
	for _, c := range realLockfiles {
		if !c.pins {
			out[c.dir] = realFiles(t, c.dir)
		}
	}
	return out
}

// A file named for a lockfile, with content that is not the format, would otherwise resolve its
// manifest while left out of the walk, and a scan reading nothing from either would say nothing.
// Each is reported instead.
func TestAccountReportsALockfileItCannotRecognize(t *testing.T) {
	for name, files := range emptyLocks(t) {
		for rel := range files {
			if !IsLockfile(rel) {
				continue
			}
			for _, content := range []string{"", "not a lockfile\n", `{"packages": "x"}`, `[1]`,
				`{"lockfileVersion": 1, "packages": [1]}`, `{"lockfileVersion": 1, "packages": {"x": []}}`,
				`{"lockfileVersion": 1, "packages": {"x": [1]}}`, "__metadata:\n  version: 8\n",
			} {
				broken := maps.Clone(files)
				broken[rel] = content
				want := []Unread{{Path: rel, Reason: NotRead}}
				if got := Account(tree(t, broken), nil); !reflect.DeepEqual(got, want) {
					t.Errorf("%s holding %q: Account = %v, want %v", name, content, got, want)
				}
			}
		}
	}
}

// A lockfile that cannot be read shows nothing about what it pins, so it is kept and reported
// rather than taken as empty.
func TestAccountReportsALockfileItCannotRead(t *testing.T) {
	root := tree(t, map[string]string{"package.json": bunPkg, "bun.lock": bunRegistry})
	lock := filepath.Join(root, "bun.lock")
	if err := os.Chmod(lock, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(lock, 0o600) })
	if _, err := os.ReadFile(lock); err == nil { // #nosec G304 -- a file this test wrote
		t.Skip("running as a user who can read a file with no permissions")
	}
	want := []Unread{{Path: "bun.lock", Reason: NotRead}}
	if got := Account(root, nil); !reflect.DeepEqual(got, want) {
		t.Errorf("Account = %v, want %v", got, want)
	}
}

func TestStripJSONCKeepsStringsAndDropsWhatJSONRefuses(t *testing.T) {
	for in, want := range map[string]string{
		`{"a": [1, 2,], "b": {"c": 1,},}`:        `{"a": [1, 2], "b": {"c": 1}}`,
		"{\"a\": 1, // note\n}":                  "{\"a\": 1 \n}",
		`{"a": 1, /* note */ }`:                  `{"a": 1  }`,
		`{"a": "x,}", "b": "// not a comment",}`: `{"a": "x,}", "b": "// not a comment"}`,
		`{"a": "say \"hi\",]", "b": 2,}`:         `{"a": "say \"hi\",]", "b": 2}`,
		`{"a": 1, "b": 2}`:                       `{"a": 1, "b": 2}`,
		`{"a": "never closed`:                    `{"a": "never closed`,
		`{"a": 1} /* never closed`:               `{"a": 1} `,
		"{\"a\": 1} // to the end":               `{"a": 1} `,
		`[1, /* x */ ,]`:                         `[1,  ]`,
		`{"a": 1, /* never closed`:               `{"a": 1, `,
	} {
		if got := string(stripJSONC([]byte(in))); got != want {
			t.Errorf("stripJSONC(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRequirementLinesSkipOptionsAndComments(t *testing.T) {
	got := requirementLines([]byte("# top\n\n-r base.txt\n--index-url https://x\nflask==2.0 # web\n  requests\n"))
	want := []string{"flask==2.0", "requests"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("requirementLines = %v, want %v", got, want)
	}
}

func TestHasPinOnAMissingFile(t *testing.T) {
	if hasPin(t.TempDir(), "requirements.txt") {
		t.Error("a missing file has no pin")
	}
}

func TestFormatOfNamesTheEntryFormatsLists(t *testing.T) {
	for rel, want := range map[string]string{
		"requirements.txt":         "requirements.txt",
		"api/requirements-dev.txt": "requirements.txt",
		"pylock.dev.toml":          "pylock.toml",
		"svc/App.csproj":           "*.csproj",
		"lib/Lib.fsproj":           "*.fsproj",
		"web/npm-shrinkwrap.json":  "npm-shrinkwrap.json",
		"gems.locked":              "gems.locked",
		".csproj":                  "",
		"notes.txt":                "",
		"README.md":                "",
	} {
		if got := FormatOf(rel); got != want {
			t.Errorf("FormatOf(%q) = %q, want %q", rel, got, want)
		}
	}
}

// Every format Formats lists is one FormatOf gives back, so a guard counting scenarios by format
// can reach each entry.
func TestEveryFormatIsOneFormatOfReturns(t *testing.T) {
	seen := map[string]bool{}
	for _, f := range Formats() {
		if seen[f.Name] {
			t.Errorf("%s is listed twice", f.Name)
		}
		seen[f.Name] = true
		rel := "dir/" + strings.Replace(f.Name, "*", "Name", 1)
		if got := FormatOf(rel); got != f.Name {
			t.Errorf("FormatOf(%q) = %q, want %q", rel, got, f.Name)
		}
		if f.Ecosystem == "" {
			t.Errorf("%s has no ecosystem", f.Name)
		}
	}
}

// TestEveryLockfileIsAFormat: a lockfile name no rule recognizes would never match, and the path
// carrying it would be called a manifest.
func TestEveryLockfileIsAFormat(t *testing.T) {
	known := map[string]bool{}
	for _, f := range Formats() {
		known[f.Name] = true
	}
	for name := range lockfiles {
		if !known[name] {
			t.Errorf("lockfile %q is not a format any rule recognizes", name)
		}
	}
}

func TestIsLockfile(t *testing.T) {
	for rel, want := range map[string]bool{
		"web/package-lock.json": true, "pylock.dev.toml": true, "src/App/packages.lock.json": true,
		"package.json": false, "requirements.txt": false, "go.mod": false, "packages.config": false,
		"static/js/jquery.min.js": false,
	} {
		if got := IsLockfile(rel); got != want {
			t.Errorf("IsLockfile(%q) = %v, want %v", rel, got, want)
		}
	}
}
