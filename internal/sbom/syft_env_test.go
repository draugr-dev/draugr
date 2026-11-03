package sbom

import (
	"context"
	"strings"
	"testing"
)

// TestSyftRunsWithoutItsUpdateCheck: the runner a Generator uses gives the process Syft's setting
// that turns off the request asking whether a newer Syft exists. Run against `env`, which prints
// the environment the runner gave it.
func TestSyftRunsWithoutItsUpdateCheck(t *testing.T) {
	g := New()
	out, err := g.run(context.Background(), "", []string{"env"})
	if err != nil {
		t.Fatalf("run env: %v", err)
	}
	if !strings.Contains(string(out), "SYFT_CHECK_FOR_APP_UPDATE=false\n") {
		t.Errorf("Syft's runner does not set SYFT_CHECK_FOR_APP_UPDATE=false; its environment:\n%s", out)
	}
}
