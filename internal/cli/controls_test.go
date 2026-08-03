package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/builtins"
)

func TestRunControls(t *testing.T) {
	var out bytes.Buffer
	if err := runControls(&out, builtins.Registry()); err != nil {
		t.Fatalf("runControls: %v", err)
	}
	s := out.String()
	// Header + a few known controls with their default scanners.
	for _, want := range []string{
		"Control", "Scanners", "Purpose",
		"images", "trivy",
		"secrets", "gitleaks",
		"sast", "semgrep",
		"headers", "http-headers",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("controls output missing %q\n%s", want, s)
		}
	}
	// gosec is an opt-in sast scanner → marked with * + a footnote.
	if !strings.Contains(s, "gosec*") || !strings.Contains(s, "opt-in scanner") {
		t.Errorf("expected gosec marked opt-in with a footnote\n%s", s)
	}
}

func TestControlsCommandViaCobra(t *testing.T) {
	cmd := newControlsCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs(nil)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !strings.Contains(out.String(), "sast") {
		t.Errorf("output = %q", out.String())
	}
}

func TestControlsShowsWhoPublishesEachScanner(t *testing.T) {
	var buf bytes.Buffer
	if err := runControls(&buf, builtins.Registry()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	if !strings.Contains(out, "Who publishes each scanner:") {
		t.Fatalf("no provenance section:\n%s", out)
	}
	// The question this answers: reading the control table, http-headers and gitleaks look
	// alike, and one of them is somebody else's binary.
	for _, want := range []string{"draugr", "aquasecurity", "projectdiscovery", "securego"} {
		if !strings.Contains(out, want) {
			t.Errorf("origin %q missing:\n%s", want, out)
		}
	}
	// Draugr's own scanners come first — the reader is usually asking which are *not* ours.
	i := strings.Index(out, "Who publishes each scanner:")
	rest := out[i:]
	if strings.Index(rest, "draugr ") > strings.Index(rest, "aquasecurity") {
		t.Error("draugr is not listed first")
	}
}

func TestEveryRegisteredScannerDeclaresAnOrigin(t *testing.T) {
	// An unlabelled scanner would render as "unknown", which is honest but is a gap in the
	// roster — and the roster is only useful if it is complete.
	for _, s := range builtins.Registry().Scanners() {
		if s.Info().Origin == "" {
			t.Errorf("scanner %q declares no Origin, so nothing says who publishes it", s.Info().Name)
		}
	}
}
