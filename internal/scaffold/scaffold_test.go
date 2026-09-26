package scaffold

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/draugr-dev/draugr/internal/inventory"
	"github.com/draugr-dev/draugr/internal/sagatest"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// layout writes files under root, creating their directories.
func layout(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for rel, content := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// shop is a repository with something for every line the scaffold can write.
var shop = map[string]string{
	"go.mod":                         "module shop\n\nrequire golang.org/x/text v0.3.0\n",
	"main.go":                        "package main\n",
	"Dockerfile":                     "FROM scratch\n",
	"web/package.json":               `{"dependencies": {"left-pad": "1.0.0"}}`,
	"web/static/jquery-1.8.3.min.js": "",
	"ml/setup.py":                    "setup(install_requires=['requests'])\n",
	"deploy/terraform/main.tf":       "",
	"deploy/chart/Chart.yaml":        "apiVersion: v2\nname: shop\n",
	"api/openapi.yaml":               "openapi: 3.0.0\n",
}

// scaffoldIn renders the scaffold for a fresh tree, having checked it is a descriptor Draugr loads
// and an editor accepts.
func scaffoldIn(t *testing.T, files map[string]string, perDirectory bool) string {
	t.Helper()
	dir := t.TempDir()
	layout(t, dir, files)
	got := Saga(inventory.Read(dir), "shop", perDirectory)
	if _, err := saga.Load([]byte(got)); err != nil {
		t.Fatalf("the scaffold is a descriptor Draugr refuses: %v\n%s", err, got)
	}
	sagatest.EditorAccepts(t, []byte(got), false)
	return got
}

func TestSagaNamesTheFilesBehindEachScanner(t *testing.T) {
	t.Parallel()
	got := scaffoldIn(t, shop, false)
	for _, want := range []string{
		"analyzers: [govulncheck]   # ranks a Go finding down when no code calls it · go.mod\n",
		"retirejs:\n        enabled: true     # copied JavaScript, outside any lockfile · web/static/jquery-1.8.3.min.js\n",
		"grypeFs:\n        enabled: true     # Trivy does not read setup.py · ml/setup.py\n",
		"gosec:\n        enabled: true     # Go-specific checks · go.mod\n",
		"# IaC misconfiguration (Trivy config) · deploy/terraform · deploy/chart · Dockerfile\n",
		"    # images:\n    #   enabled: true",
		"    #   - image: myorg/shop:latest\n",
		"    #       path: ./api/openapi.yaml\n",
		"    # Unread · web/package.json no lockfile · its packages are not checked\n",
		"    # Directories with their own dependency files: ml · web\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("descriptor missing %q:\n%s", want, got)
		}
	}
	if strings.Count(got, "\n  - name: ") != 1 {
		t.Errorf("without perDirectory the scaffold has one component:\n%s", got)
	}
}

// Two parts and one nested inside another: each part is scoped to its own directory, and every
// component above a part ignores it, so no file is scanned twice and none is scanned by nobody.
func TestSagaPerDirectoryScopesEachPart(t *testing.T) {
	t.Parallel()
	files := map[string]string{
		"go.mod":                           "module shop\n\nrequire golang.org/x/text v0.3.0\n",
		"services/api/go.mod":              "module api\n\nrequire golang.org/x/net v0.1.0\n",
		"services/api/worker/package.json": `{"dependencies": {"left-pad": "1.0.0"}}`,
		"web/package.json":                 `{"dependencies": {"left-pad": "1.0.0"}}`,
		"web/package-lock.json":            `{"lockfileVersion": 3, "packages": {}}`,
		"Dockerfile":                       "FROM scratch\n",
	}
	got := scaffoldIn(t, files, true)
	want := "components:\n" +
		"  - name: shop\n    repositories:\n      - url: .\n        ignore: [services/api/, web/]\n" +
		"    # images:\n    #   - image: myorg/shop:latest\n" +
		"    # hosts:            # for the headers/DAST controls\n" +
		"    #   - name: api\n    #     url: https://api.example.com\n    #     type: api\n" +
		"  - name: api\n    repositories:\n      - url: .\n        paths: [services/api]\n        ignore: [services/api/worker/]\n" +
		"  - name: worker\n    repositories:\n      - url: .\n        paths: [services/api/worker]\n" +
		"    # Unread · services/api/worker/package.json no lockfile · its packages are not checked\n" +
		"  - name: web\n    repositories:\n      - url: .\n        paths: [web]\n"
	if !strings.HasSuffix(got, want) {
		t.Errorf("components =\n%s\nwant\n%s", got[strings.Index(got, "components:"):], want)
	}
}

// Two npm workspaces, each with one lockfile at its root: every member stays in the component of
// the workspace whose lockfile resolves it, rather than a component of its own with no lockfile.
func TestSagaPerDirectoryKeepsWorkspaceMembersWithTheirRoot(t *testing.T) {
	t.Parallel()
	lock := `{"lockfileVersion": 3, "packages": {"node_modules/minimist": {}}}`
	dep := `{"dependencies": {"minimist": "1.2.5"}}`
	files := map[string]string{
		"web/package.json":               `{"workspaces": ["packages/*"]}`,
		"web/package-lock.json":          lock,
		"web/packages/ui/package.json":   dep,
		"api/package.json":               `{"workspaces": {"packages": ["services/*"]}}`,
		"api/package-lock.json":          lock,
		"api/services/auth/package.json": dep,
	}
	got := scaffoldIn(t, files, true)
	want := "components:\n" +
		"  - name: shop\n    repositories:\n      - url: .\n        ignore: [api/, web/]\n" +
		"    # hosts:            # for the headers/DAST controls\n" +
		"    #   - name: api\n    #     url: https://api.example.com\n    #     type: api\n" +
		"  - name: api\n    repositories:\n      - url: .\n        paths: [api]\n" +
		"  - name: web\n    repositories:\n      - url: .\n        paths: [web]\n"
	if !strings.HasSuffix(got, want) {
		t.Errorf("components =\n%s\nwant\n%s", got[strings.Index(got, "components:"):], want)
	}
}

// A part is named for its directory, and for its whole path where the directory name is taken,
// by another part or by the project, so two components never share a name.
func TestSagaPerDirectoryNamesNeverCollide(t *testing.T) {
	t.Parallel()
	pkg := `{"dependencies": {"left-pad": "1.0.0"}}`
	files := map[string]string{
		"apps/web/package.json":  pkg,
		"tools/web/package.json": pkg,
		"libs/shop/package.json": pkg,
		"docs/package.json":      pkg,
	}
	got := scaffoldIn(t, files, true)
	for _, name := range []string{"apps-web", "tools-web", "libs-shop", "docs"} {
		if !strings.Contains(got, "  - name: "+name+"\n") {
			t.Errorf("missing component %q:\n%s", name, got)
		}
	}
	m, err := saga.Load([]byte(got))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, c := range m.Components {
		if seen[c.Name] {
			t.Errorf("two components named %q", c.Name)
		}
		seen[c.Name] = true
	}
}

// A requirements file named anything but requirements.txt is one Trivy opens only through a file
// pattern, so the scaffold writes the pattern that reaches each way such a file is named.
func TestSagaWritesFilePatternsForRequirementsTrivyDoesNotOpen(t *testing.T) {
	t.Parallel()
	got := scaffoldIn(t, map[string]string{
		"api/dev-requirements.txt":  "black==24.1.0\n",
		"web/requirements/test.txt": "pytest==8.0.0\n",
	}, false)
	want := `filePatterns: ['pip:requirements[^/]*\.txt$', 'pip:(^|/)requirements/[^/]+\.txt$']`
	if !strings.Contains(got, "      trivyFs:\n        "+want) {
		t.Errorf("descriptor missing %q:\n%s", want, got)
	}
}

// The patterns are Go regexes, which is what Trivy compiles them as, matched against the path
// relative to the scan root. Each must reach every requirements file init proposes it for and
// nothing that merely contains the word.
func TestPipFilePatternsReachWhatInitProposesThemFor(t *testing.T) {
	t.Parallel()
	compile := func(p string) *regexp.Regexp {
		return regexp.MustCompile(strings.TrimPrefix(p, "pip:"))
	}
	named, inDir := compile(pipNamedPattern), compile(pipDirPattern)
	for _, rel := range []string{"requirements-dev.txt", "dev-requirements.txt", "svc/api/requirements-test.txt"} {
		if !named.MatchString(rel) {
			t.Errorf("%s does not reach %s", pipNamedPattern, rel)
		}
	}
	for _, rel := range []string{"requirements/test.txt", "svc/requirements/dev.txt"} {
		if !inDir.MatchString(rel) {
			t.Errorf("%s does not reach %s", pipDirPattern, rel)
		}
	}
	for _, rel := range []string{"requirements.txt.bak", "requirements/sub/dev.txt", "myrequirements/dev.txt", "notes.txt"} {
		if named.MatchString(rel) || inDir.MatchString(rel) {
			t.Errorf("a pattern reaches %s, which is no requirements file", rel)
		}
	}
}

func TestPathListCountsWhatItDoesNotShow(t *testing.T) {
	t.Parallel()
	if got := PathList([]string{"a", "b", "c", "d", "e"}); got != "a · b · c · +2" {
		t.Errorf("PathList = %q", got)
	}
	if got := PathList([]string{"a", "b"}); got != "a · b" {
		t.Errorf("PathList = %q", got)
	}
}

// A descriptor Draugr writes must not be one Draugr's own next command warns about.
//
// `draugr init` then `draugr validate` are the first two steps of the quickstart, so the scaffold
// writes the fields the docs tell a new user to write, and no field the deprecation notice tells
// them to stop using.
func TestTheScaffoldWritesTheFieldTheDocsTellPeopleToUse(t *testing.T) {
	t.Parallel()
	out := Saga(inventory.Read(t.TempDir()), "acme-api", false)

	if !strings.Contains(out, "project: acme-api") {
		t.Errorf("scaffold does not name the project:\n%s", out)
	}
	// A version is optional and only the person releasing knows it, so a scaffold that invented one
	// would label every report with a number nobody chose.
	if strings.Contains(out, "release:") {
		t.Errorf("the scaffold writes a release nobody chose:\n%s", out)
	}

	var m saga.Model
	if err := yaml.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("scaffold is not valid YAML: %v", err)
	}
}

// Whatever the scaffold names a project has to load. A capital letter or a dot in a directory name
// is ordinary, and the scaffold this package exists to make has to pass the validation of the very
// next command init suggests.
func TestProjectNameIsOneTheValidatorAccepts(t *testing.T) {
	t.Parallel()
	for _, dir := range []string{
		"My.Service", "payments_api", "Team Alpha", "---", "ok-name", "APP", "a.b.c", "9lives",
		"", ".", "..", "-leading", "trailing-", "ünïcödé",
	} {
		name := ProjectName(dir)
		m := &saga.Model{
			Project:    name,
			Release:    saga.Release{Version: "0.0.0"},
			Components: []saga.Component{{Name: "app"}},
		}
		if err := m.Validate(); err != nil {
			t.Errorf("directory %q became project %q, which does not validate: %v", dir, name, err)
		}
	}
}

// The name is recognizably the directory's where it can be, because somebody reads it back and has
// to see their own project.
func TestProjectNameKeepsTheNameRecognizable(t *testing.T) {
	t.Parallel()
	for dir, want := range map[string]string{
		"My.Service":   "my-service",
		"payments_api": "payments-api",
		"Team Alpha":   "team-alpha",
		"ok-name":      "ok-name",
		"---":          "app",
	} {
		if got := ProjectName(dir); got != want {
			t.Errorf("%q became %q, want %q", dir, got, want)
		}
	}
}

func TestScalarQuotesWhatYAMLWouldNotReadAsTheSameString(t *testing.T) {
	for in, want := range map[string]string{
		"api":          "api",
		"services/api": "services/api",
		"my-app":       "my-app",
		"2024":         `"2024"`,
		"1e3":          `"1e3"`,
		"0x10":         `"0x10"`,
		"0o17":         `"0o17"`,
		"true":         `"true"`,
		"null":         `"null"`,
		"yes":          `"yes"`,
		"off":          `"off"`,
		"a, b/":        `"a, b/"`,
		"[x]":          `"[x]"`,
		"#tmp/":        `"#tmp/"`,
	} {
		if got := Scalar(in); got != want {
			t.Errorf("Scalar(%q) = %s, want %s", in, got, want)
		}
	}
}
