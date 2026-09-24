package cli

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/draugr-dev/draugr/internal/sagatest"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// Whatever `init` writes has to load, and the descriptor it writes carries the directory's name.
// A capital letter or a dot in a directory name is ordinary, and `My.Service` produced a file
// Draugr rejected, so the scaffold this command exists to make failed the validation of the very
// next command it suggests.
func TestInitWritesAProjectNameTheValidatorAccepts(t *testing.T) {
	for _, dir := range []string{
		"My.Service", "payments_api", "Team Alpha", "---", "ok-name", "APP", "a.b.c", "9lives",
		"", ".", "..", "-leading", "trailing-", "ünïcödé",
	} {
		name := projectNameFrom(dir)
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
func TestInitKeepsTheNameRecognizable(t *testing.T) {
	for dir, want := range map[string]string{
		"My.Service":   "my-service",
		"payments_api": "payments-api",
		"Team Alpha":   "team-alpha",
		"ok-name":      "ok-name",
		"---":          "app",
	} {
		if got := projectNameFrom(dir); got != want {
			t.Errorf("%q became %q, want %q", dir, got, want)
		}
	}
}

// The real path, not the helper alone: whatever ends up on disk is what a reader runs against.
func TestInitOnAwkwardlyNamedDirectoryProducesALoadableFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "My.Service")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "draugr.saga.yaml")
	if err := runInit(dir, initOptions{output: out}, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
	sagatest.EditorAcceptsFile(t, out, false)
	if _, err := saga.LoadFile(out); err != nil {
		t.Errorf("init wrote a file Draugr cannot load: %v", err)
	}
}
