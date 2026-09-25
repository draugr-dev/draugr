package cli

import (
	"testing"

	draugrmcp "github.com/draugr-dev/draugr/internal/mcp"
)

// The default decides what an assistant may do on a machine where nobody chose a mode, so it is
// pinned rather than left to whatever the flag declaration happens to say.
func TestMCPScanDefaultsToEffects(t *testing.T) {
	flag := newMCPCommand().Flags().Lookup("scan")
	if flag == nil {
		t.Fatal("draugr mcp has no --scan flag")
	}
	if got := draugrmcp.ScanMode(flag.DefValue); got != draugrmcp.ScanEffects {
		t.Errorf("--scan defaults to %q, want %q", got, draugrmcp.ScanEffects)
	}
}

func TestMCPRejectsAnUnknownScanMode(t *testing.T) {
	cmd := newMCPCommand()
	cmd.SetArgs([]string{"--scan=yes"})
	if err := cmd.Execute(); err == nil {
		t.Error("want an error for an unknown scan mode")
	}
}
