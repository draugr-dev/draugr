package inventory

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/draugr-dev/draugr/internal/manifests"
)

// write lays out files under root, creating their directories.
func write(t *testing.T, root string, files map[string]string) {
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

const deployment = "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n"

func TestReadFindsWhatATreeHolds(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	write(t, root, map[string]string{
		"go.mod":       "module shop\n\nrequire golang.org/x/text v0.3.0\n",
		"tools/go.mod": "module tools\n\nrequire golang.org/x/tools v0.1.0\n",

		"web/package.json":               `{"dependencies": {"left-pad": "1.0.0"}}`,
		"web/static/jquery-1.8.3.min.js": "",
		"web/static/angular.1.2.js":      "",
		"web/vendor/lib/widget.js":       "",
		"web/src/app.js":                 "",
		"web/node_modules/x/x-1.0.0.js":  "",

		"ml/setup.py":         "setup(install_requires=['requests'])\n",
		"ml/requirements.txt": "requests\n",
		// Trivy's pip analyzer opens requirements.txt by name and no other requirements file.
		"ml/requirements-dev.txt": "pytest==8.0.0\n",
		"ml/dev-requirements.txt": "black==24.1.0\n",

		"deploy/terraform/main.tf":                 "",
		"deploy/terraform/.terraform/modules/m.tf": "",
		"deploy/chart/Chart.yaml":                  "apiVersion: v2\nname: web\n",
		"deploy/chart/templates/deployment.yaml":   deployment,
		"deploy/k8s/deployment.yml":                deployment,

		"Dockerfile":          "FROM scratch\n",
		"Dockerfile.prod":     "FROM scratch\n",
		"svc/api.Dockerfile":  "FROM scratch\n",
		"svc/Containerfile":   "FROM scratch\n",
		"api/openapi.yaml":    "openapi: 3.0.0\ninfo:\n  title: shop\n",
		"api/v1/swagger.json": `{"swagger": "2.0"}`,
		"config.yaml":         "name: shop\n",
		"config.json":         `{"name": "shop"}`,
	})

	got := Read(root)

	for _, c := range []struct {
		field     string
		got, want []string
	}{
		{"Go", got.Go, []string{".", "tools"}},
		{"VendoredJS", got.VendoredJS, []string{"web/static/angular.1.2.js", "web/static/jquery-1.8.3.min.js", "web/vendor/lib/widget.js"}},
		{"Terraform", got.Terraform, []string{"deploy/terraform"}},
		{"Helm", got.Helm, []string{"deploy/chart"}},
		{"Kubernetes", got.Kubernetes, []string{"deploy/k8s/deployment.yml"}},
		{"Dockerfiles", got.Dockerfiles, []string{"Dockerfile", "Dockerfile.prod", "svc/Containerfile", "svc/api.Dockerfile"}},
		{"OpenAPI", got.OpenAPI, []string{"api/openapi.yaml", "api/v1/swagger.json"}},
		{"Parts", got.Parts, []string{"ml", "tools", "web"}},
		{"TrivyUnread", paths(got.TrivyUnread), []string{"ml/setup.py"}},
		{"TrivyByPattern", paths(got.TrivyByPattern), []string{"ml/dev-requirements.txt", "ml/requirements-dev.txt"}},
	} {
		if !slices.Equal(c.got, c.want) {
			t.Errorf("%s = %q, want %q", c.field, c.got, c.want)
		}
	}

	// What is known before a scan: the manifest with no lockfile and the requirements file with no
	// exact version. Nothing is NotRead, because nothing has been asked to read yet.
	var unresolved []string
	for _, u := range got.Unresolved {
		if u.Reason == manifests.NotRead {
			t.Errorf("%s is NotRead; Read reports only what no scanner could read", u.Path)
		}
		unresolved = append(unresolved, u.Path+" "+string(u.Reason))
	}
	want := []string{"ml/requirements.txt " + string(manifests.Unpinned), "web/package.json " + string(manifests.NoLockfile)}
	slices.Sort(unresolved)
	if !slices.Equal(unresolved, want) {
		t.Errorf("Unresolved = %q, want %q", unresolved, want)
	}
}

// A tree with nothing in it has nothing to propose, and says so with empty fields rather than
// failing.
func TestReadAnEmptyTree(t *testing.T) {
	t.Parallel()
	got := Read(t.TempDir())
	if len(got.Dependencies)+len(got.Go)+len(got.VendoredJS)+len(got.Parts)+len(got.Dockerfiles) != 0 {
		t.Errorf("an empty tree reported contents: %+v", got)
	}
}

func TestReadAMissingRoot(t *testing.T) {
	t.Parallel()
	if got := Read(filepath.Join(t.TempDir(), "absent")); len(got.Dependencies)+len(got.Dockerfiles) != 0 {
		t.Errorf("a missing root reported contents: %+v", got)
	}
}

// A go.mod that requires nothing is still a Go module: its code has SAST findings and its toolchain
// has advisories. It is not a dependency file, so a scan never reports it unread, and a vendored
// module's go.mod belongs to somebody else.
func TestReadFindsAGoModuleThatRequiresNothing(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	write(t, root, map[string]string{
		"go.mod":                            "module shop\n\ngo 1.26\n",
		"tools/go.mod":                      "module tools\n\ngo 1.26\n",
		"vendor/example.com/lib/go.mod":     "module example.com/lib\n",
		"tools/vendor/example.com/x/go.mod": "module example.com/x\n",
	})

	got := Read(root)

	if want := []string{".", "tools"}; !slices.Equal(got.Go, want) {
		t.Errorf("Go = %q, want %q", got.Go, want)
	}
	if want := []string{"tools"}; !slices.Equal(got.Parts, want) {
		t.Errorf("Parts = %q, want %q", got.Parts, want)
	}
	if len(got.Dependencies)+len(got.Unresolved) != 0 {
		t.Errorf("a go.mod with nothing to resolve is a dependency file: %+v %+v", got.Dependencies, got.Unresolved)
	}
}

// A JavaScript workspace keeps one lockfile at its root for every member, so a member holding only
// a package.json stays with the root. Three workspaces in one tree, one per way of naming members:
// npm's array, Yarn's object with packages, and pnpm-workspace.yaml.
func TestReadKeepsWorkspaceMembersWithTheirRoot(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	dep := `{"dependencies": {"minimist": "1.2.5"}}`
	write(t, root, map[string]string{
		"npm/package.json":              `{"workspaces": ["packages/*", "./tools/**", "!packages/legacy"]}`,
		"npm/package-lock.json":         `{"lockfileVersion": 3, "packages": {"node_modules/minimist": {}}}`,
		"npm/packages/web/package.json": dep,
		"npm/packages/cli/package.json": dep,
		"npm/tools/a/b/package.json":    dep,
		// Excluded by a ! glob, and beneath a member without being one: each resolves on its own.
		"npm/packages/legacy/package.json":      dep,
		"npm/packages/legacy/package-lock.json": `{"lockfileVersion": 3, "packages": {"node_modules/minimist": {}}}`,
		"npm/packages/web/nested/package.json":  dep,
		// A member with a lockfile of its own, and one holding a dependency file of another ecosystem.
		"npm/packages/cli/package-lock.json": `{"lockfileVersion": 3, "packages": {"node_modules/minimist": {}}}`,
		"npm/tools/py/package.json":          dep,
		"npm/tools/py/requirements.txt":      "flask==0.12.2\n",

		"yarn/package.json":                `{"workspaces": {"packages": ["apps/*"], "nohoist": ["**/x"]}}`,
		"yarn/yarn.lock":                   "minimist@1.2.5:\n  version \"1.2.5\"\n",
		"yarn/apps/site/package.json":      dep,
		"pnpm/package.json":                `{"name": "root"}`,
		"pnpm-workspace.yaml":              "packages: [ignored]\n",
		"pnpm/pnpm-workspace.yaml":         "packages:\n  - \"libs/**\"\n",
		"pnpm/pnpm-lock.yaml":              "lockfileVersion: '9.0'\npackages:\n  minimist@1.2.5:\n    version: 1.2.5\n",
		"pnpm/libs/core/util/package.json": dep,

		"standalone/package.json":      dep,
		"standalone/package-lock.json": `{"lockfileVersion": 3, "packages": {"node_modules/minimist": {}}}`,
		"broken/package.json":          `{"workspaces": 3, "dependencies": {"minimist": "1.2.5"}}`,
	})

	got := Read(root)

	want := []string{
		"broken", "npm", "npm/packages/cli", "npm/packages/legacy", "npm/packages/web/nested", "npm/tools/py",
		"pnpm", "standalone", "yarn",
	}
	if !slices.Equal(got.Parts, want) {
		t.Errorf("Parts = %q, want %q", got.Parts, want)
	}
}

func TestGlobMatch(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		pattern, dir string
		want         bool
	}{
		{"packages/*", "packages/web", true},
		{"packages/*", "packages/web/sub", false},
		{"packages/**", "packages/web/sub", true},
		{"**", "anything/at/all", true},
		{"./apps/*/", "apps/site", true},
		{"apps/site", "apps/site", true},
		{"apps/[", "apps/[", false},
	} {
		if got := globMatch(c.pattern, c.dir); got != c.want {
			t.Errorf("globMatch(%q, %q) = %v, want %v", c.pattern, c.dir, got, c.want)
		}
	}
}

func paths(files []manifests.File) []string {
	out := make([]string, len(files))
	for i, f := range files {
		out[i] = f.Path
	}
	return out
}
