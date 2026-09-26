package cli

import (
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/draugr-dev/draugr/internal/sagatest"
	"github.com/draugr-dev/draugr/pkg/saga"
)

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

// A directory named something YAML reads as a number, a boolean or null still gives a descriptor
// both the schema and Draugr accept, with the name as written. Two components under
// --per-directory, the root and a subdirectory, so a name quoted in one place and not the other
// cannot pass; and a fragment, which names its component too.
func TestInitQuotesANameYAMLWouldNotReadAsAString(t *testing.T) {
	for _, name := range []string{"2024", "true", "null", "1e3", "0x10", "yes"} {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), name)
			sub := filepath.Join(dir, "0o17")
			if err := os.MkdirAll(sub, 0o750); err != nil {
				t.Fatal(err)
			}
			for _, d := range []string{dir, sub} {
				if err := os.WriteFile(filepath.Join(d, "go.mod"), []byte("module example.com/x\n\ngo 1.26\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			out := filepath.Join(dir, "draugr.saga.yaml")
			if err := runInit(dir, initOptions{output: out, perDirectory: true}, io.Discard); err != nil {
				t.Fatalf("init: %v", err)
			}
			sagatest.EditorAcceptsFile(t, out, false)
			model, err := saga.LoadFile(out)
			if err != nil {
				t.Fatalf("init wrote a file Draugr cannot load: %v", err)
			}
			var names []string
			for _, c := range model.Components {
				names = append(names, c.Name)
			}
			if model.ProjectName() != name || !slices.Equal(names, []string{name, "0o17"}) {
				t.Errorf("project %q, components %v; want %q and [%s 0o17]", model.ProjectName(), names, name, name)
			}

			frag := filepath.Join(sub, "draugr.saga-fragment.yaml")
			if err := runInit(sub, initOptions{fragment: true, output: frag}, io.Discard); err != nil {
				t.Fatalf("init --fragment: %v", err)
			}
			sagatest.EditorAcceptsFile(t, frag, true)
			data, err := os.ReadFile(frag) // #nosec G304 -- a file this test wrote
			if err != nil {
				t.Fatal(err)
			}
			if f, err := saga.LoadFragment(data, frag); err != nil || f.Components[0].Name != "0o17" {
				t.Errorf("fragment: %v, %+v", err, f)
			}
		})
	}
}
