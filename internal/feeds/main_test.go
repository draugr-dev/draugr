package feeds

import (
	"os"
	"testing"
)

// TestMain clears DRAUGR_HOME, so a test that isolates Draugr's directory by setting HOME reads the
// temporary home it set rather than a directory the developer's shell exported. A test about the
// variable sets it itself.
func TestMain(m *testing.M) {
	_ = os.Unsetenv("DRAUGR_HOME")
	os.Exit(m.Run())
}
