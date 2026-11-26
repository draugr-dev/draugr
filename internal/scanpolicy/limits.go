package scanpolicy

import (
	"context"
	"fmt"
	"log/slog"
	"runtime"

	"github.com/draugr-dev/draugr/internal/toolexec"
	"github.com/draugr-dev/draugr/pkg/config"
	"github.com/draugr-dev/draugr/pkg/engine"
)

// Limits is how much of the machine a scan may take: how many jobs run at once, and whether the
// tools those jobs start are held to a share of it.
//
// `draugr scan` and the MCP scan tool both read them from scan.* in the configuration (Configure)
// and apply them (Options, Context) here. A machine whose operator turned the thread limit on
// because a tool ran out of memory without it would otherwise run the unlimited scan whenever an
// assistant started one, and the advice on the failure would name a key that scan never read.
type Limits struct {
	// Jobs caps the jobs running at once. Zero leaves it to the engine, which sizes it to the
	// machine.
	Jobs int
	// LimitToolThreads holds every tool's threads and Go build processes to its job's share of the
	// parallelism bound (toolexec.WithThreadLimit).
	LimitToolThreads bool
	// ShareWorkers holds the worker pools Semgrep and Trivy size for themselves to that share too
	// (toolexec.WithSharedWorkers), and implies LimitToolThreads.
	ShareWorkers bool
	// ToolMemory is the most resident memory one tool run may use before Draugr stops it, as
	// --tool-memory and scan.toolMemory write it (toolexec.ParseMemoryBound). Empty or 0 is none.
	ToolMemory string
}

// The flags `draugr scan` sets each limit with, by which Configure tells a limit typed on the
// command line from one the configuration supplies.
const (
	JobsFlag             = "jobs"
	LimitToolThreadsFlag = "limit-tool-threads"
	ShareWorkersFlag     = "share-workers"
	ToolMemoryFlag       = "tool-memory"
)

// Configure sets each limit scan.* in cfg names, except where typed names its flag. A typed flag
// wins whatever its value, so `--jobs 0` asks for the automatic default over a configured cap and
// `--limit-tool-threads=false` runs without the limit a file turned on. A caller with no flags
// passes nil, and cfg decides every limit it names.
func (l *Limits) Configure(cfg config.ScanSettings, typed map[string]bool) {
	if cfg.Jobs != nil && !typed[JobsFlag] {
		l.Jobs = *cfg.Jobs
	}
	if cfg.LimitToolThreads != nil && !typed[LimitToolThreadsFlag] {
		l.LimitToolThreads = *cfg.LimitToolThreads
	}
	if cfg.ShareWorkers != nil && !typed[ShareWorkersFlag] {
		l.ShareWorkers = *cfg.ShareWorkers
	}
	if cfg.ToolMemory != nil && !typed[ToolMemoryFlag] {
		l.ToolMemory = *cfg.ToolMemory
	}
}

// Check refuses a limit no run could apply, naming the flag where typed says it came from the
// command line and the key otherwise.
func (l Limits) Check(typed map[string]bool) error {
	if _, err := toolexec.ParseMemoryBound(l.ToolMemory); err != nil {
		if typed[ToolMemoryFlag] {
			return fmt.Errorf("--%s: %w", ToolMemoryFlag, err)
		}
		return fmt.Errorf("scan.toolMemory: %w", err)
	}
	return nil
}

// Options is the engine options that carry the job count, none where the engine is left to size
// it.
func (l Limits) Options() []engine.Option {
	if l.Jobs > 0 {
		return []engine.Option{engine.WithConcurrency(l.Jobs)}
	}
	return nil
}

// Context is ctx, marked so the tools a run starts are held to their job's share of the
// parallelism bound where LimitToolThreads asks for it, hold their own worker pools to that share
// too where ShareWorkers does, and are stopped at ToolMemory where it is set. A ToolMemory Check
// refuses is no bound here, so a caller checks first.
//
// Where the platform cannot hold a tool to a memory bound, the run says so in its log and runs its
// tools unbounded, rather than appearing to hold them.
//
// ShareWorkers implies the thread limit. It holds a tool's own pool to the same share the limit
// gives every tool's threads, so it is the stricter of the two, and a run that asks Semgrep's
// processes to share the machine while each Go tool takes all of it saves the smaller part of the
// memory it asked to save.
func (l Limits) Context(ctx context.Context) context.Context {
	if l.LimitToolThreads || l.ShareWorkers {
		ctx = toolexec.WithThreadLimit(ctx)
	}
	if l.ShareWorkers {
		ctx = toolexec.WithSharedWorkers(ctx)
	}
	if b, err := toolexec.ParseMemoryBound(l.ToolMemory); err == nil && b.Bytes > 0 {
		if !toolexec.CanBoundMemory() {
			slog.WarnContext(ctx, "the tool memory bound is not enforced on this platform; tools run unbounded",
				"bound", b.Text, "platform", runtime.GOOS)
			return ctx
		}
		ctx = toolexec.WithMemoryBound(ctx, b)
	}
	return ctx
}
