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
		"CONTROL", "SCANNERS", "PURPOSE",
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
