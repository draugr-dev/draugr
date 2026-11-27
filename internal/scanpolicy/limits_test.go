package scanpolicy

import (
	"context"
	"runtime"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/toolexec"
	"github.com/draugr-dev/draugr/pkg/config"
)

// Each scan.* key sets its limit where its flag was not typed, a typed flag wins whatever its value,
// and a key the file leaves out leaves the limit as it was.
func TestConfigureFoldsTheFileUnderTypedFlags(t *testing.T) {
	on, off, four, eight, none := true, false, 4, "8GiB", "0"
	file := config.ScanSettings{Jobs: &four, LimitToolThreads: &on, ShareWorkers: &on, ToolMemory: &eight}
	for _, tc := range []struct {
		name  string
		start Limits
		cfg   config.ScanSettings
		typed map[string]bool
		want  Limits
	}{
		{"no flags", Limits{}, file, nil, Limits{Jobs: 4, LimitToolThreads: true, ShareWorkers: true, ToolMemory: "8GiB"}},
		{"every flag typed", Limits{Jobs: 0}, file,
			map[string]bool{JobsFlag: true, LimitToolThreadsFlag: true, ShareWorkersFlag: true, ToolMemoryFlag: true}, Limits{}},
		{"a file that turns them off", Limits{LimitToolThreads: true, ShareWorkers: true, ToolMemory: "1GiB"},
			config.ScanSettings{LimitToolThreads: &off, ShareWorkers: &off, ToolMemory: &none}, nil, Limits{ToolMemory: "0"}},
		{"a file that sets nothing", Limits{Jobs: 7, ShareWorkers: true}, config.ScanSettings{}, nil,
			Limits{Jobs: 7, ShareWorkers: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.start
			got.Configure(tc.cfg, tc.typed)
			if got != tc.want {
				t.Errorf("limits = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// A job count reaches the engine as an option, and none is given where the engine sizes it.
func TestOptionsCarryOnlyAChosenJobCount(t *testing.T) {
	if got := (Limits{}).Options(); len(got) != 0 {
		t.Errorf("no job count chosen, and %d engine options", len(got))
	}
	if got := (Limits{Jobs: 3}).Options(); len(got) != 1 {
		t.Errorf("a job count of 3 gave %d engine options, want 1", len(got))
	}
}

// The context asks for the thread limit under either setting, and for shared workers only under
// ShareWorkers.
func TestContextMarksTheToolLimits(t *testing.T) {
	for _, tc := range []struct {
		limits                Limits
		wantLimited, wantPool bool
	}{
		{Limits{}, false, false},
		{Limits{LimitToolThreads: true}, true, false},
		{Limits{ShareWorkers: true}, true, true},
	} {
		ctx := tc.limits.Context(context.Background())
		if toolexec.LimitsThreads(ctx) != tc.wantLimited || toolexec.SharesWorkers(ctx) != tc.wantPool {
			t.Errorf("%+v: threads limited %t, workers shared %t, want %t and %t", tc.limits,
				toolexec.LimitsThreads(ctx), toolexec.SharesWorkers(ctx), tc.wantLimited, tc.wantPool)
		}
	}
}

// A bound no run could apply is refused, naming the flag when it was typed and the key when a file
// set it, and an empty or valid one passes.
func TestCheckNamesWhereABadBoundCameFrom(t *testing.T) {
	for _, ok := range []string{"", "0", "512MiB"} {
		if err := (Limits{ToolMemory: ok}).Check(nil); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	bad := Limits{ToolMemory: "8G"}
	if err := bad.Check(map[string]bool{ToolMemoryFlag: true}); err == nil || !strings.HasPrefix(err.Error(), "--tool-memory: ") {
		t.Errorf("a typed bad bound: %v, want the flag named", err)
	}
	if err := bad.Check(nil); err == nil || !strings.HasPrefix(err.Error(), "scan.toolMemory: ") {
		t.Errorf("a configured bad bound: %v, want the key named", err)
	}
}

// The context carries the bound where the platform enforces one, and none where ToolMemory is unset,
// zero or a value Check would refuse.
func TestContextCarriesTheMemoryBound(t *testing.T) {
	got := toolexec.MemoryBoundOf((Limits{ToolMemory: "2GiB"}).Context(context.Background()))
	want := uint64(0)
	if runtime.GOOS == "linux" {
		want = 2 << 30
	}
	if got.Bytes != want {
		t.Errorf("bound = %+v, want %d bytes on %s", got, want, runtime.GOOS)
	}
	for _, none := range []string{"", "0", "8G"} {
		if b := toolexec.MemoryBoundOf((Limits{ToolMemory: none}).Context(context.Background())); b.Bytes != 0 {
			t.Errorf("%q gave the bound %+v", none, b)
		}
	}
}
