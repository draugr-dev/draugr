package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

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

// shop is a repository with something for every line init can write.
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

// runInitIn runs init in a fresh tree and returns the descriptor and the console output, having
// checked the descriptor is one `draugr validate` accepts.
func runInitIn(t *testing.T, files map[string]string, opts initOptions) (descriptor, console string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "shop")
	layout(t, dir, files)
	opts.output = filepath.Join(dir, "draugr.saga.yaml")
	var buf bytes.Buffer
	if err := runInit(dir, opts, &buf); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(opts.output)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := loadSaga(opts.output); err != nil {
		t.Fatalf("init wrote a descriptor validate refuses: %v\n%s", err, data)
	}
	sagatest.EditorAcceptsFile(t, opts.output, false)
	return string(data), buf.String()
}

func TestInitNamesTheFilesBehindEachScanner(t *testing.T) {
	t.Parallel()
	got, _ := runInitIn(t, shop, initOptions{})
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
		t.Errorf("without --per-directory init writes one component:\n%s", got)
	}
}

// A tree holding none of what adds a scanner gets the four controls that are always on, and no
// line claiming a file behind it.
func TestInitOnAnEmptyTreeWritesTheBaseline(t *testing.T) {
	t.Parallel()
	got, console := runInitIn(t, map[string]string{"README.md": "shop\n"}, initOptions{})
	for _, absent := range []string{"reachability", "retirejs", "grypeFs", "trivyFs", "gosec", "images", "spec:", "Unread", "Directories", " · "} {
		if strings.Contains(got, absent) {
			t.Errorf("empty tree wrote %q:\n%s", absent, got)
		}
	}
	for _, absent := range []string{"FOUND", "UNREAD"} {
		if strings.Contains(console, absent) {
			t.Errorf("empty tree printed %s:\n%s", absent, console)
		}
	}
}

func TestInitPrintsWhatItFoundAndWhatIsUnread(t *testing.T) {
	t.Parallel()
	_, got := runInitIn(t, shop, initOptions{})
	for _, want := range []string{
		"wrote ", "FOUND\n",
		"  go ", "sca · gosec · govulncheck",
		"  copied JavaScript ", "retirejs",
		"  read by Grype only ", "grype-fs",
		"  Terraform ", "  Helm ", "iac · images, commented",
		"  OpenAPI ", "hosts spec, commented",
		"UNREAD  " + initUnreadNote + "\n  web/package.json  no lockfile\n",
		"Next:\n  draugr doctor ",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("console missing %q:\n%s", want, got)
		}
	}
}

// Two parts and one nested inside another: each part is scoped to its own directory, and every
// component above a part ignores it, so no file is scanned twice and none is scanned by nobody.
func TestInitPerDirectoryScopesEachPart(t *testing.T) {
	t.Parallel()
	files := map[string]string{
		"go.mod":                           "module shop\n\nrequire golang.org/x/text v0.3.0\n",
		"services/api/go.mod":              "module api\n\nrequire golang.org/x/net v0.1.0\n",
		"services/api/worker/package.json": `{"dependencies": {"left-pad": "1.0.0"}}`,
		"web/package.json":                 `{"dependencies": {"left-pad": "1.0.0"}}`,
		"web/package-lock.json":            `{"lockfileVersion": 3, "packages": {}}`,
		"Dockerfile":                       "FROM scratch\n",
	}
	got, _ := runInitIn(t, files, initOptions{perDirectory: true})
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
func TestInitPerDirectoryKeepsWorkspaceMembersWithTheirRoot(t *testing.T) {
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
	got, _ := runInitIn(t, files, initOptions{perDirectory: true})
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
func TestInitPerDirectoryNamesNeverCollide(t *testing.T) {
	t.Parallel()
	pkg := `{"dependencies": {"left-pad": "1.0.0"}}`
	files := map[string]string{
		"apps/web/package.json":  pkg,
		"tools/web/package.json": pkg,
		"libs/shop/package.json": pkg,
		"docs/package.json":      pkg,
	}
	got, _ := runInitIn(t, files, initOptions{perDirectory: true})
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

// --per-directory on a tree with no parts cannot do what it was asked, and says so rather than
// writing one component in silence.
func TestInitPerDirectoryWithNoPartsSaysSo(t *testing.T) {
	t.Parallel()
	got, console := runInitIn(t, map[string]string{"go.mod": "module shop\n\nrequire golang.org/x/text v0.3.0\n"},
		initOptions{perDirectory: true})
	if strings.Count(got, "\n  - name: ") != 1 {
		t.Errorf("want one component:\n%s", got)
	}
	if !strings.Contains(console, "--per-directory: no directory below the root holds its own dependency file") {
		t.Errorf("console does not say --per-directory had nothing to split:\n%s", console)
	}
}

// Two modules that require nothing still get the Go controls, and the console names both under
// FOUND without crediting sca, which has nothing in either to read.
func TestInitProposesTheGoControlsForModulesThatRequireNothing(t *testing.T) {
	t.Parallel()
	files := map[string]string{
		"go.mod":        "module shop\n\ngo 1.26\n",
		"main.go":       "package main\n",
		"tools/go.mod":  "module tools\n\ngo 1.26\n",
		"tools/main.go": "package main\n",
	}
	got, console := runInitIn(t, files, initOptions{})
	for _, want := range []string{
		"analyzers: [govulncheck]   # ranks a Go finding down when no code calls it · go.mod · tools/go.mod\n",
		"gosec:\n        enabled: true     # Go-specific checks · go.mod · tools/go.mod\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("descriptor missing %q:\n%s", want, got)
		}
	}
	if !strings.Contains(console, "  go  go.mod · tools/go.mod  gosec · govulncheck\n") {
		t.Errorf("console does not list the modules under FOUND:\n%s", console)
	}
	if strings.Contains(console, "UNREAD") {
		t.Errorf("a go.mod with nothing to resolve is reported unread:\n%s", console)
	}
}

// Where one module requires something and another does not, the one row names both, and sca
// reads the one with requirements.
func TestInitFoundRowNamesEveryGoModule(t *testing.T) {
	t.Parallel()
	_, console := runInitIn(t, map[string]string{
		"go.mod":       "module shop\n\nrequire golang.org/x/text v0.3.0\n",
		"tools/go.mod": "module tools\n\ngo 1.26\n",
	}, initOptions{})
	if !strings.Contains(console, "  go  go.mod · tools/go.mod  sca · gosec · govulncheck\n") {
		t.Errorf("console does not name both modules in one row:\n%s", console)
	}
}

// A requirements file named anything but requirements.txt is one Trivy opens only through a file
// pattern, so init writes the pattern that reaches each way such a file is named, and names the
// files behind it.
func TestInitWritesFilePatternsForRequirementsTrivyDoesNotOpen(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name  string
		files map[string]string
		want  string
	}{
		{"named", map[string]string{"requirements-dev.txt": "flask==0.12.2\n", "requirements.txt": "click==8.0.0\n"},
			`filePatterns: ['pip:requirements[^/]*\.txt$']   # requirements files under other names · requirements-dev.txt` + "\n"},
		{"in a directory", map[string]string{"requirements/test.txt": "pytest==8.0.0\n"},
			`filePatterns: ['pip:(^|/)requirements/[^/]+\.txt$']   # requirements files under other names · requirements/test.txt` + "\n"},
		{"both", map[string]string{"api/dev-requirements.txt": "black==24.1.0\n", "web/requirements/test.txt": "pytest==8.0.0\n"},
			`filePatterns: ['pip:requirements[^/]*\.txt$', 'pip:(^|/)requirements/[^/]+\.txt$']`},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			got, console := runInitIn(t, c.files, initOptions{})
			if !strings.Contains(got, "      trivyFs:\n        "+c.want) {
				t.Errorf("descriptor missing %q:\n%s", c.want, got)
			}
			if !strings.Contains(console, "read by a file pattern") {
				t.Errorf("console does not list the files under FOUND:\n%s", console)
			}
		})
	}

	// requirements.txt alone is what Trivy opens anyway, and needs no pattern.
	got, _ := runInitIn(t, map[string]string{"requirements.txt": "flask==0.12.2\n"}, initOptions{})
	if strings.Contains(got, "trivyFs") {
		t.Errorf("init wrote a pattern for requirements.txt:\n%s", got)
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
	if got := pathList([]string{"a", "b", "c", "d", "e"}); got != "a · b · c · +2" {
		t.Errorf("pathList = %q", got)
	}
	if got := pathList([]string{"a", "b"}); got != "a · b" {
		t.Errorf("pathList = %q", got)
	}
}

func TestInitCommandTakesADirectoryAndTheFlag(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	layout(t, dir, map[string]string{"web/package.json": `{"dependencies": {"left-pad": "1.0.0"}}`})
	out := filepath.Join(dir, "draugr.saga.yaml")
	cmd := newInitCommand()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{dir, "--per-directory", "-o", out})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(out) // #nosec G304 -- the test's own temp path
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "paths: [web]") {
		t.Errorf("--per-directory did not reach the scaffold:\n%s", data)
	}
}

// --fragment with no -o writes beside the directory it describes, not into the working directory.
func TestInitCommandWritesAFragmentIntoTheDirectory(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cmd := newInitCommand()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{dir, "--fragment"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "draugr.saga-fragment.yaml")); err != nil {
		t.Errorf("fragment not written into %s: %v", dir, err)
	}
}
