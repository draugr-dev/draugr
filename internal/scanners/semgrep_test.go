package scanners

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
)

func TestSemgrepInfo(t *testing.T) {
	info := NewSemgrep().Info()
	if info.Name != "semgrep" {
		t.Errorf("name = %q", info.Name)
	}
	if len(info.Controls) != 1 || info.Controls[0] != "sast" {
		t.Errorf("controls = %v", info.Controls)
	}
	if len(info.TargetKinds) != 1 || info.TargetKinds[0] != plugin.TargetRepository {
		t.Errorf("target kinds = %v", info.TargetKinds)
	}
}

func TestSemgrepArgs(t *testing.T) {
	argv := semgrepArgs("/work/repo", nil)
	want := []string{
		"semgrep", "scan",
		"--sarif",
		"--quiet",
		"--no-error",
		"--metrics=off",
		"--config", "p/default",
		"/work/repo",
	}
	if len(argv) != len(want) {
		t.Fatalf("argv = %v", argv)
	}
	for i := range want {
		if argv[i] != want[i] {
			t.Fatalf("argv[%d] = %q, want %q", i, argv[i], want[i])
		}
	}
}
