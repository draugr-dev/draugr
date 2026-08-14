//go:build integration

package integration

import (
	"os"
	"os/exec"
	"testing"
)

// strictEnv is how a caller declares it has provisioned the tools these tests need.
const strictEnv = "DRAUGR_INTEGRATION_STRICT"

// requireTool resolves an external tool these tests exec, and decides what a missing one means.
//
// The two callers want opposite answers from the same check. Someone running
// `go test -tags integration` on a laptop is better served by being told which tool is missing
// than by a failure they have to decode, so the default is a skip. A job whose whole premise is
// that the tools are installed is not: there, a skip is a test that announced it was not running
// in a log nobody reads, and reported success.
//
// So the job declares itself by setting DRAUGR_INTEGRATION_STRICT, and the skip becomes a
// failure. Provisioning a scanner and then silently not using it is the shape of green tick this
// project exists to prevent, and it is worth refusing in our own pipeline first.
func requireTool(t *testing.T, binary, why string) string {
	t.Helper()
	path, err := exec.LookPath(binary)
	if err == nil {
		return path
	}
	if os.Getenv(strictEnv) != "" {
		t.Fatalf("%s is not on PATH, and %s is set: %s. The job provisions it, so this is the "+
			"provisioning being wrong rather than the test being unrunnable — skipping here would "+
			"report success for a test that did nothing", binary, strictEnv, why)
	}
	t.Skipf("%s is not on PATH: %s. Install it (`draugr tools install %s`) to run this test; set "+
		"%s to make a missing tool a failure instead", binary, why, binary, strictEnv)
	return ""
}
