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

func paths(files []manifests.File) []string {
	out := make([]string, len(files))
	for i, f := range files {
		out[i] = f.Path
	}
	return out
}
