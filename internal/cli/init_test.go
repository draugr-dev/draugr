package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/draugr-dev/draugr/pkg/saga"
)

func TestRunInitWritesFileWithDetection(t *testing.T) {
	dir := t.TempDir()
	// Go + Dockerfile → gosec hint + images stub.
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module x\ngo 1.26\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte("FROM alpine\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "draugr.saga.yaml")
	var buf bytes.Buffer
	if err := runInit(dir, initOptions{output: out}, &buf); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(out) //nolint:gosec // out is a test-controlled temp path
	if err != nil {
		t.Fatalf("expected %s written: %v", out, err)
	}
	s := string(data)
	for _, want := range []string{"Detected: Go", "gosec:\n        enabled: true", "images:", "sca:", "url: ."} {
		if !strings.Contains(s, want) {
			t.Errorf("generated Saga missing %q:\n%s", want, s)
		}
	}
	// The generated Saga must be valid.
	if _, err := loadSaga(out); err != nil {
		t.Errorf("generated Saga is not valid: %v", err)
	}
}

func TestRunInitStdout(t *testing.T) {
	var buf bytes.Buffer
	if err := runInit(t.TempDir(), initOptions{output: "-"}, &buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "release:") || !strings.Contains(buf.String(), "controllers:") {
		t.Errorf("stdout Saga looks wrong:\n%s", buf.String())
	}
}

func TestRunInitNoOverwrite(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "draugr.saga.yaml")
	if err := os.WriteFile(out, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := runInit(dir, initOptions{output: out}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("expected refuse-to-overwrite, got %v", err)
	}
	// --force overwrites.
	if err := runInit(dir, initOptions{output: out, force: true}, &bytes.Buffer{}); err != nil {
		t.Errorf("--force should overwrite: %v", err)
	}
}

// The comment `draugr init` writes names the file the reader can see in their own directory, so
// the mapping is worth pinning — and the fallback wording has to stay something a reader can act
// on when no manifest was recognized.
func TestInitNamesTheManifestItFound(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"go.mod", "package.json", "pyproject.toml", "Cargo.toml"} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if got := depManifest(dir); got != name {
			t.Errorf("depManifest with %s = %q", name, got)
		}
	}
	if got := depManifest(t.TempDir()); got != "a lockfile" {
		t.Errorf("depManifest with nothing recognizable = %q", got)
	}
}

// A descriptor Draugr writes must not be one Draugr's own next command warns about.
//
// `draugr init` then `draugr validate` are the first two steps of the quickstart, and the
// scaffold wrote the field the deprecation notice tells the reader to stop using — so a new
// user's very first run contradicted the tutorial that sent them there.
func TestTheScaffoldWritesTheFieldTheDocsTellPeopleToUse(t *testing.T) {
	out := scaffoldSaga(t.TempDir(), "acme-api")

	if !strings.Contains(out, "project: acme-api") {
		t.Errorf("scaffold does not name the project:\n%s", out)
	}
	if strings.Contains(out, "name: acme-api\n  version") {
		t.Errorf("scaffold still writes release.name:\n%s", out)
	}

	var m saga.Model
	if err := yaml.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("scaffold is not valid YAML: %v", err)
	}
	if got := m.Deprecations(); len(got) != 0 {
		t.Errorf("what init wrote is deprecated on arrival: %v", got)
	}
}
