package scanners

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
)

func TestGitleaksInfo(t *testing.T) {
	info := NewGitleaks().Info()
	if info.Name != "gitleaks" {
		t.Errorf("name = %q", info.Name)
	}
	if len(info.Controls) != 1 || info.Controls[0] != "secrets" {
		t.Errorf("controls = %v", info.Controls)
	}
	if len(info.TargetKinds) != 1 || info.TargetKinds[0] != plugin.TargetRepository {
		t.Errorf("target kinds = %v", info.TargetKinds)
	}
}

func TestGitleaksArgs(t *testing.T) {
	argv := gitleaksArgs("/work/repo", nil)
	want := []string{
		"gitleaks", "dir", "/work/repo",
		"--report-format", "sarif",
		"--report-path", "/dev/stdout",
		"--exit-code", "0",
		"--no-banner",
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
