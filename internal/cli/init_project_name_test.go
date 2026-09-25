package cli

import (
	"io"
	"os"
	"path/filepath"
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
