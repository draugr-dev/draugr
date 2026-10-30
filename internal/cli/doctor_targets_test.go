package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/preflight"
)

// Images named by digest in doctor's targets table: shortened on screen, and on a terminal too
// narrow for the table each target on its own line with its result under it, whole.
func TestTargetChecksFitTheTerminal(t *testing.T) {
	const pilot = "contoso.azurecr.io/istio/pilot:1.30.5-distroless@sha256:78052a996140d7f0a3f03d04fb3352714cbc40e0b69dcf70b59ee07511ff3dfb"
	checks := []preflight.Check{
		{Kind: "image", Target: pilot, Status: preflight.Failed, Detail: "401 unauthorized, no credential for contoso.azurecr.io"},
		{Kind: "repository", Target: "https://github.com/draugr-dev/draugr-demo.git@main", Status: preflight.Passed, Detail: "resolves to a103420078f4"},
		{Kind: "host", Target: "https://shop.example.com", Status: preflight.NotChecked, Detail: "--offline"},
	}
	short := "contoso.azurecr.io/istio/pilot:1.30.5-distroless@sha256:78052a996140…"

	t.Setenv("COLUMNS", "")
	var wide bytes.Buffer
	writeTargetChecks(&wide, checks)
	for _, want := range []string{
		"Kind        Target ",
		"image       " + short + "  ✗ 401 unauthorized, no credential for contoso.azurecr.io",
		"host        https://shop.example.com",
		"not checked: --offline",
	} {
		if !strings.Contains(wide.String(), want) {
			t.Errorf("without a terminal width, missing %q:\n%s", want, wide.String())
		}
	}
	if strings.Contains(wide.String(), "0cb40e0b69dcf70b59ee") {
		t.Errorf("the digest was printed whole:\n%s", wide.String())
	}

	t.Setenv("COLUMNS", "80")
	var narrow bytes.Buffer
	writeTargetChecks(&narrow, checks)
	want := "image " + short + "\n  ✗ 401 unauthorized, no credential for contoso.azurecr.io\n" +
		"repository https://github.com/draugr-dev/draugr-demo.git@main\n  ✓ resolves to a103420078f4\n"
	if !strings.Contains(narrow.String(), want) {
		t.Errorf("at 80 columns, want each target over its result:\n%s", narrow.String())
	}
	for _, line := range strings.Split(narrow.String(), "\n") {
		if n := len([]rune(line)); n > 80 {
			t.Errorf("a line is %d wide at 80 columns: %s", n, line)
		}
	}
}
