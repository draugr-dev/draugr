package scanners

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
)

func TestTrivyConfigInfo(t *testing.T) {
	info := NewTrivyConfig().Info()
	if info.Name != "trivy-config" {
		t.Errorf("name = %q", info.Name)
	}
	if len(info.Controls) != 1 || info.Controls[0] != "iac" {
		t.Errorf("controls = %v", info.Controls)
	}
	if len(info.TargetKinds) != 1 || info.TargetKinds[0] != plugin.TargetRepository {
		t.Errorf("target kinds = %v", info.TargetKinds)
	}
}

func TestTrivyConfigArgs(t *testing.T) {
	argv := trivyConfigArgs("/work/repo", nil)
	want := []string{"trivy", "config", "--quiet", "--format", "sarif", "/work/repo"}
	if len(argv) != len(want) {
		t.Fatalf("argv = %v", argv)
	}
	for i := range want {
		if argv[i] != want[i] {
			t.Fatalf("argv[%d] = %q, want %q", i, argv[i], want[i])
		}
	}
}
