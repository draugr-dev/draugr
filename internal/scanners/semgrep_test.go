package scanners

import (
	"context"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"testing"

	"github.com/draugr-dev/draugr/internal/toolexec"
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
		"--json-output", semgrepJSONPath,
		"--verbose",
		"--max-target-bytes", "1000000",
		"--timeout-threshold", "3",
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

// A relative config resolves against Draugr's working directory, whichever directory Semgrep scans:
// the root of one clone, or a component's directory inside another.
func TestSemgrepArgsResolvesARelativeConfig(t *testing.T) {
	wd := t.TempDir()
	t.Chdir(wd)
	want := filepath.Join(wd, ".draugr", "semgrep.yaml")
	for _, dir := range []string{"/tmp/clone-a", "/tmp/clone-b/services/api"} {
		if got := semgrepConfigArg(t, semgrepArgs(dir, plugin.Config{"config": ".draugr/semgrep.yaml"})); got != want {
			t.Errorf("scanning %s: --config %s, want %s", dir, got, want)
		}
	}
	for _, config := range []string{"p/owasp-top-ten", "r/python.lang", "s/team", "auto", "https://example.com/r.yaml", want} {
		if got := semgrepConfigArg(t, semgrepArgs("/tmp/clone-a", plugin.Config{"config": config})); got != config {
			t.Errorf("--config %s, want %s unchanged", got, config)
		}
	}
}

func semgrepConfigArg(t *testing.T, argv []string) string {
	t.Helper()
	i := slices.Index(argv, "--config")
	if i < 0 || i+1 >= len(argv) {
		t.Fatalf("no --config in %v", argv)
	}
	return argv[i+1]
}

// Semgrep's own default is round(0.85 × min(16, CPUs)), at least one.
func TestSemgrepDefaultJobs(t *testing.T) {
	for cpus, want := range map[int]int{1: 1, 2: 2, 4: 3, 16: 14, 32: 14} {
		if got := semgrepDefaultJobs(cpus); got != want {
			t.Errorf("semgrepDefaultJobs(%d) = %d, want %d", cpus, got, want)
		}
	}
}

// Every run carries --jobs after `semgrep scan`, at its job's share of the machine, which the jobs
// running at once of every scanner divide among them, and never above Semgrep's default.
func TestSemgrepJobsAreTheJobsShare(t *testing.T) {
	var got []string
	run := withSemgrepJobs(func(_ context.Context, _ string, argv []string) ([]byte, error) {
		got = argv
		return nil, nil
	})
	argv := semgrepArgs("/work/repo", nil)
	def := semgrepDefaultJobs(runtime.GOMAXPROCS(0))
	for _, beside := range []int{1, 4, 1000} {
		ctx := toolexec.WithJobs(context.Background(), beside)
		if _, err := run(ctx, "/work/repo", argv); err != nil {
			t.Fatal(err)
		}
		want := strconv.Itoa(max(1, min(def, toolexec.Bound(ctx))))
		if len(got) < 4 || got[0] != "semgrep" || got[1] != "scan" || got[2] != "--jobs" || got[3] != want {
			t.Errorf("%d jobs at once: argv = %v, want --jobs %s after `semgrep scan`", beside, got, want)
		}
	}
	if got[3] != "1" {
		t.Errorf("among a thousand jobs, --jobs %s, want 1", got[3])
	}
	if slices.Contains(argv, "--jobs") {
		t.Error("the caller's argv was changed")
	}
}
