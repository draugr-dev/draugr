package manifests

import (
	"maps"
	"os"
	"path/filepath"
	"reflect"
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
	cargoLock = "[[package]]\nname = \"app\"\n\n[[package]]\nname = \"serde\"\n"
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
// warn about every project with no dependencies.
func TestFindLeavesOutFilesThatDeclareNothing(t *testing.T) {
	root := tree(t, map[string]string{
		"go.mod":            "module app\n\ngo 1.26\n",
		"pyproject.toml":    "[tool.ruff]\nline-length = 100\n",
		"requirements.txt":  "# nothing yet\n-r base.txt\n",
		"package.json":      `{"name":"x","scripts":{"test":"jest"}}`,
		"package-lock.json": `{"lockfileVersion":3,"packages":{"":{"name":"x"}}}`,
		"Cargo.lock":        "[[package]]\nname = \"app\"\n",
		"uv.lock":           "[[package]]\nname = \"app\"\n",
		"composer.lock":     `{"packages": [], "packages-dev": []}`,
		"App.csproj":        `<Project Sdk="Microsoft.NET.Sdk"></Project>`,
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

// A lockfile with nothing in it is left out of the walk and still resolves the manifest beside it.
func TestAccountResolvesAgainstALockfileTheWalkLeftOut(t *testing.T) {
	root := tree(t, map[string]string{
		"Cargo.toml": cargoToml,
		"Cargo.lock": "[[package]]\nname = \"app\"\n",
	})
	if got := Account(root, nil); len(got) != 0 {
		t.Errorf("Account = %v, want nothing", got)
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

// emptyLocks are lockfiles in their own format that pin nothing, each beside a manifest whose
// dependency section is there and empty, as a fresh project's is.
var emptyLocks = map[string]map[string]string{
	"package-lock.json v3": {
		"package.json":      `{"name":"x","dependencies":{}}`,
		"package-lock.json": `{"name":"x","lockfileVersion":3,"requires":true,"packages":{"":{"name":"x"}}}`,
	},
	"package-lock.json v1": {
		"package.json":      `{"name":"x","dependencies":{}}`,
		"package-lock.json": `{"name":"x","lockfileVersion":1,"requires":true}`,
	},
	"npm-shrinkwrap.json": {
		"package.json":        `{"name":"x","dependencies":{}}`,
		"npm-shrinkwrap.json": `{"lockfileVersion":1,"dependencies":{}}`,
	},
	"yarn.lock": {
		"package.json": `{"name":"x","dependencies":{}}`,
		"yarn.lock":    "# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.\n# yarn lockfile v1\n\n\n",
	},
	"pnpm-lock.yaml": {
		"package.json":   `{"name":"x","dependencies":{}}`,
		"pnpm-lock.yaml": "lockfileVersion: '9.0'\n\nsettings:\n  autoInstallPeers: true\n\nimporters:\n\n  .: {}\n",
	},
	"bun.lock": {
		"package.json": `{"name":"mono","workspaces":["packages/*"],"devDependencies":{}}`,
		"bun.lock":     bunWorkspaces,
	},
	"Pipfile.lock": {
		"Pipfile":      "[packages]\n\n[dev-packages]\n",
		"Pipfile.lock": `{"_meta":{"hash":{"sha256":"0"},"pipfile-spec":6},"default":{},"develop":{}}`,
	},
	"poetry.lock": {
		"pyproject.toml": "[tool.poetry]\nname = \"x\"\n",
		"poetry.lock":    "package = []\n\n[metadata]\nlock-version = \"2.0\"\n",
	},
	"uv.lock": {
		"pyproject.toml": "[project]\nname = \"x\"\ndependencies = []\n",
		"uv.lock":        "version = 1\n\n[[package]]\nname = \"x\"\nsource = { virtual = \".\" }\n",
	},
	"Cargo.lock": {
		"Cargo.toml": "[package]\nname = \"x\"\n\n[dependencies]\n",
		"Cargo.lock": "version = 4\n\n[[package]]\nname = \"x\"\nversion = \"0.1.0\"\n",
	},
	"composer.lock": {
		"composer.json": `{"require": {}}`,
		"composer.lock": `{"content-hash": "0", "packages": [], "packages-dev": []}`,
	},
}

// A lockfile that is its format and pins nothing resolves its manifest and is not itself reported:
// a project with no dependencies yet has nothing unread.
func TestAccountReportsNothingForALockfileThatPinsNothing(t *testing.T) {
	for name, files := range emptyLocks {
		root := tree(t, files)
		if got := Account(root, nil); len(got) != 0 {
			t.Errorf("%s: Account = %v, want nothing", name, got)
		}
	}
}

// A file named for a lockfile, with content that is not the format, would otherwise resolve its
// manifest while left out of the walk, and a scan reading nothing from either would say nothing.
// Each is reported instead.
func TestAccountReportsALockfileItCannotRecognize(t *testing.T) {
	for name, files := range emptyLocks {
		for rel := range files {
			if !IsLockfile(rel) {
				continue
			}
			for _, content := range []string{"", "not a lockfile\n", `{"packages": "x"}`, `[1]`,
				`{"lockfileVersion": 1, "packages": [1]}`, `{"lockfileVersion": 1, "packages": {"x": []}}`,
				`{"lockfileVersion": 1, "packages": {"x": [1]}}`,
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

// Lockfiles pinning a package with no "version" key stay in the walk, so a scan that reads nothing
// from one reports it.
func TestFindKeepsLockfilesPinningWithoutAVersionKey(t *testing.T) {
	root := tree(t, map[string]string{
		// pnpm 7 writes lockfile version 5.4, which keys a package by path and gives it no version.
		"pnpm/pnpm-lock.yaml": "lockfileVersion: 5.4\n\nspecifiers:\n  lodash: ^4.17.20\n\ndependencies:\n  lodash: 4.17.20\n\n" +
			"packages:\n\n  /lodash/4.17.20:\n    resolution: {integrity: sha512-x}\n    dev: false\n",
		// A dependency on a git repository is pinned by ref.
		"pipenv/Pipfile.lock":    `{"_meta":{"pipfile-spec":6},"default":{"requests":{"git":"https://github.com/psf/requests.git","ref":"0e322af"}},"develop":{}}`,
		"composer/composer.lock": `{"packages": [{"name": "x/y", "source": {"type": "git"}}]}`,
		"cargo/Cargo.lock":       "[[package]]\nname = \"app\"\n\n[[package]]\nname = \"serde\"\n",
		"uv/uv.lock":             "[[package]]\nname = \"app\"\n\n[[package]]\nname = \"flask\"\n",
		"poetry/poetry.lock":     "[[package]]\nname = \"flask\"\n\n[metadata]\n",
		"npm/package-lock.json":  `{"lockfileVersion":3,"packages":{"":{},"node_modules/x":{"resolved":"git+ssh://x"}}}`,
		"npm1/package-lock.json": `{"lockfileVersion":1,"dependencies":{"x":{"version":"github:a/x#1"}}}`,
		"yarn/yarn.lock":         "# yarn lockfile v1\n\nx@^1:\n  version \"1.0.0\"\n",
	})
	want := []string{
		"cargo/Cargo.lock", "composer/composer.lock", "npm/package-lock.json", "npm1/package-lock.json",
		"pipenv/Pipfile.lock", "pnpm/pnpm-lock.yaml", "poetry/poetry.lock", "uv/uv.lock", "yarn/yarn.lock",
	}
	if got := paths(Find(root)); !reflect.DeepEqual(got, want) {
		t.Errorf("Find = %v, want %v", got, want)
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
