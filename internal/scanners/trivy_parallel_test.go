package scanners

import (
	"context"
	"slices"
	"strconv"
	"testing"

	"github.com/draugr-dev/draugr/internal/toolexec"
	"github.com/draugr-dev/draugr/pkg/plugin"
)

// Where the operator asked to share worker pools, a Trivy scan carries --parallel after its
// subcommand at the job's share of the machine, never above Trivy's default; a command that is not a
// scan, or that set --parallel, is left alone.
func TestTrivyScansRunAtTheJobsShare(t *testing.T) {
	alone := toolexec.WithSharedWorkers(context.Background())
	crowded := toolexec.WithJobs(alone, 1000)
	want := strconv.Itoa(min(trivyDefaultParallel, toolexec.Bound(alone)))
	for _, sub := range []string{"fs", "image", "repository", "rootfs"} {
		argv := []string{"trivy", sub, "--quiet", "x"}
		got := withTrivyParallel(alone, argv)
		if !slices.Equal(got[:4], []string{"trivy", sub, "--parallel", want}) {
			t.Errorf("%s alone: %v, want --parallel %s after the subcommand", sub, got, want)
		}
		if got := withTrivyParallel(crowded, argv); got[3] != "1" {
			t.Errorf("%s among a thousand jobs: %v, want --parallel 1", sub, got)
		}
		if len(argv) != 4 {
			t.Errorf("%s: the caller's argv was changed: %v", sub, argv)
		}
	}
	for _, argv := range [][]string{
		{"trivy", "config", "--quiet", "x"},
		{"trivy", "version", "--format", "json"},
		{"trivy", "convert", "--format", "sarif", "r.json"},
		{"trivy", "fs", "--parallel", "2", "x"},
		{"trivy", "fs", "--parallel=2", "x"},
		{"trivy"},
	} {
		if got := withTrivyParallel(alone, argv); !slices.Equal(got, argv) {
			t.Errorf("%v became %v", argv, got)
		}
	}
}

// A run that did not ask to share worker pools keeps Trivy's own --parallel, however many jobs run
// beside it.
func TestTrivyKeepsItsDefaultUnlessAsked(t *testing.T) {
	argv := []string{"trivy", "fs", "--quiet", "x"}
	if got := withTrivyParallel(toolexec.WithJobs(context.Background(), 1000), argv); !slices.Equal(got, argv) {
		t.Errorf("%v became %v", argv, got)
	}
}

// The repository scans, which keep Trivy's log, pass the share too.
func TestTrivyLoggedScansPassTheirShare(t *testing.T) {
	prior := execWithStderr
	t.Cleanup(func() { execWithStderr = prior })
	var got []string
	execWithStderr = func(_ context.Context, _ string, argv, _ []string) ([]byte, []byte, error) {
		got = argv
		return nil, nil, nil
	}
	ctx := toolexec.WithJobs(toolexec.WithSharedWorkers(context.Background()), 1000)
	if _, _, err := trivyExecLogged(ctx, t.TempDir(), []string{"trivy", "fs", "--debug", "x"}, nil); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []string{"trivy", "fs", "--parallel", "1", "--debug", "x"}) {
		t.Errorf("ran %v, want --parallel 1", got)
	}
}

// The image scanners, vulnerabilities and licenses, run their scan with the share, through the
// exec a test substitutes.
func TestTrivyImageScannersPassTheirShare(t *testing.T) {
	prior := execArgv
	t.Cleanup(func() { execArgv = prior })
	var ran [][]string
	execArgv = func(_ context.Context, argv []string) ([]byte, error) {
		ran = append(ran, argv)
		return []byte(`{"Results":[]}`), nil
	}
	ctx := toolexec.WithJobs(toolexec.WithSharedWorkers(context.Background()), 1000)
	target := plugin.ImageTarget{Ref: "registry.example/app:1"}
	for _, s := range []plugin.Scanner{NewTrivy(), NewTrivyLicense()} {
		_, _ = s.Scan(ctx, target, plugin.Config{})
	}
	found := 0
	for _, argv := range ran {
		if len(argv) > 3 && argv[1] == "image" && argv[2] == "--parallel" && argv[3] == "1" {
			found++
		}
	}
	if found != 2 {
		t.Errorf("ran %v, want both image scans with --parallel 1", ran)
	}
}
