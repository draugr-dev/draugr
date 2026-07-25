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

func TestSemgrepArgsCustomRuleset(t *testing.T) {
	// A "config" option overrides the default ruleset.
	argv := semgrepArgs("/work/repo", plugin.Config{"config": "p/owasp-top-ten"})
	found := false
	for i := range argv {
		if argv[i] == "--config" {
			if i+1 >= len(argv) || argv[i+1] != "p/owasp-top-ten" {
				t.Fatalf("--config not set to custom ruleset: %v", argv)
			}
			found = true
		}
	}
	if !found {
		t.Fatalf("--config flag missing: %v", argv)
	}
}

func TestSemgrepArgsEmptyConfigFallsBack(t *testing.T) {
	// An empty config string falls back to the default ruleset.
	argv := semgrepArgs("/work/repo", plugin.Config{"config": ""})
	for i := range argv {
		if argv[i] == "--config" && argv[i+1] != "p/default" {
			t.Fatalf("empty config should fall back to p/default, got %q", argv[i+1])
		}
	}
}

func TestSemgrepConfigSchemaValid(t *testing.T) {
	// The declared schema accepts a config ruleset and rejects unknown keys.
	schema := NewSemgrep().Info().ConfigSchema
	if len(schema) == 0 {
		t.Fatal("semgrep should declare a ConfigSchema")
	}
	if err := plugin.ValidateConfig(schema, plugin.Config{"config": "p/ci"}); err != nil {
		t.Errorf("valid config rejected: %v", err)
	}
	if err := plugin.ValidateConfig(schema, plugin.Config{"rules": "x"}); err == nil {
		t.Error("unknown key should be rejected by schema")
	}
}
