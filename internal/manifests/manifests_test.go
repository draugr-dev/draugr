package manifests

import (
	"os"
	"path/filepath"
	"reflect"
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
		"js/yarn.lock": {"npm", Pinned}, "py2/poetry.lock": {"python", Pinned},
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
