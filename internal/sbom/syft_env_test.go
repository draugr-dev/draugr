package sbom

import (
	"context"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/toolexec"
)

// TestSyftRunsWithoutItsUpdateCheck: the runner a Generator uses gives the process Syft's setting
// that turns off the request asking whether a newer Syft exists. Run against `env`, which prints
// the environment the runner gave it.
func TestSyftRunsWithoutItsUpdateCheck(t *testing.T) {
	g := New()
	out, err := g.run(context.Background(), "", []string{"env"})
	if err != nil {
		t.Fatalf("run env: %v", err)
	}
	if !strings.Contains(string(out), "SYFT_CHECK_FOR_APP_UPDATE=false\n") {
		t.Errorf("Syft's runner does not set SYFT_CHECK_FOR_APP_UPDATE=false; its environment:\n%s", out)
	}
}

// Syft runs four cataloging workers for each CPU of its job's share, rather than for each CPU of the
// machine, and a SYFT_PARALLELISM the operator set wins.
func TestSyftRunsAtItsJobsShare(t *testing.T) {
	none := func(string) string { return "" }
	ctx := toolexec.WithJobs(context.Background(), 10000)
	if got := syftParallelism(ctx, none); !slices.Equal(got, []string{"SYFT_PARALLELISM=4"}) {
		t.Errorf("among many jobs: %v, want SYFT_PARALLELISM=4", got)
	}
	want := "SYFT_PARALLELISM=" + strconv.Itoa(4*toolexec.Workers(context.Background(), runtime.NumCPU()))
	if got := syftParallelism(context.Background(), none); !slices.Equal(got, []string{want}) {
		t.Errorf("alone: %v, want %s", got, want)
	}
	if got := syftParallelism(ctx, func(string) string { return "2" }); got != nil {
		t.Errorf("with SYFT_PARALLELISM set: %v, want nothing added", got)
	}
	out, err := New().run(ctx, "", []string{"env"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "SYFT_PARALLELISM=") {
		t.Errorf("Syft's runner sets no SYFT_PARALLELISM; its environment:\n%s", out)
	}
}
