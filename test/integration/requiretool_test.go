//go:build integration

package integration

import (
	"net"
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
			"provisioning being wrong rather than the test being unrunnable, skipping here would "+
			"report success for a test that did nothing", binary, strictEnv, why)
	}
	t.Skipf("%s is not on PATH: %s. Install it (`draugr tools install %s`) to run this test; set "+
		"%s to make a missing tool a failure instead", binary, why, binary, strictEnv)
	return ""
}

// registryEnv names an OCI registry these tests may push to, as localhost:<port>.
const registryEnv = "DRAUGR_INTEGRATION_REGISTRY"

// requireRegistry returns the registry a test may push to, and decides what an absent one means
// the way requireTool decides about a binary: a skip by default, a failure in a strict job, whose
// workflow starts one.
//
// The host has to be localhost. notation speaks plain HTTP to a registry there without being told
// to, and Draugr runs it without --insecure-registry, so a registry under any other name would fail
// on TLS before notation looked for a signature, and the test would be about the wrong thing.
func requireRegistry(t *testing.T, why string) string {
	t.Helper()
	addr := os.Getenv(registryEnv)
	if addr == "" {
		if os.Getenv(strictEnv) != "" {
			t.Fatalf("%s is not set, and %s is set: %s. The job starts a registry, so this is the "+
				"provisioning being wrong rather than the test being unrunnable", registryEnv, strictEnv, why)
		}
		t.Skipf("%s is not set: %s. Start one on a loopback port (`docker run -d -p 127.0.0.1::5000 "+
			"registry:2.8.3`) and set %s to localhost:<port>", registryEnv, why, registryEnv)
	}
	if host, _, err := net.SplitHostPort(addr); err != nil || host != "localhost" {
		t.Fatalf("%s=%q, want localhost:<port>: notation reaches any other host over TLS", registryEnv, addr)
	}
	return addr
}

// fixtureDrifted ends a test whose fixture no longer shows the difference the test measures.
//
// Some of these tests compare two answers and need the fixture to rank, match or be reported a
// particular way, and that is decided by advisory and package data that moves with nothing in this
// tree changing. On a laptop the result is a skip that gives the reason, as requireTool gives one.
// In a job that declared itself strict it is a failure, because the comparison left would be
// between two answers that cannot differ, and a skip would report success on every run until
// somebody chose a new fixture, with nothing to tell them to.
func fixtureDrifted(t *testing.T, why string) {
	t.Helper()
	if os.Getenv(strictEnv) != "" {
		t.Fatalf("%s, and %s is set. The fixture has to change until it shows the difference again; "+
			"skipping here would report success for a test that compared nothing", why, strictEnv)
	}
	t.Skipf("%s. Set %s to make this a failure instead", why, strictEnv)
}
