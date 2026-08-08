// Package tooladapter turns an external command-line security tool into a Draugr
// Scanner declaratively: describe how to build the command for a target, and the adapter
// runs it and parses its SARIF output. This covers the majority of scanners (many emit
// SARIF natively) with no bespoke code.
package tooladapter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"time"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// Config declares how to adapt a tool.
type Config struct {
	Name    string
	Binary  string
	Version string
	// Origin is the upstream project that publishes the tool (see plugin.ScannerInfo.Origin).
	Origin      string
	Controls    []string
	TargetKinds []plugin.TargetKind
	// ConfigSchema is the JSON Schema for this scanner's Saga options (see
	// plugin.ScannerInfo.ConfigSchema). Declare one even when the scanner accepts nothing: an
	// absent schema accepts any option and then discards it, which is a setting that silently
	// does nothing.
	ConfigSchema json.RawMessage
	// Argv builds the command line (argv[0] is the executable) for a target and config.
	Argv func(target plugin.Target, cfg plugin.Config) ([]string, error)
	// Run executes argv and returns the tool's output. Optional; defaults to executing the
	// command and capturing stdout. Draugr's built-in scanners pass a shared implementation
	// that puts the tool's own first line of stderr into the error — `exit status 1` on its own
	// tells a reader nothing, and that string is what reaches the terminal and the report.
	Run func(ctx context.Context, argv []string) ([]byte, error)
	// Parse decodes the tool's output. Optional — nil means the tool emits SARIF, which most
	// do. A tool that reports in its own JSON supplies the conversion here rather than needing
	// a scanner type of its own.
	Parse func(out []byte, target plugin.Target, cfg plugin.Config) (sarif.Report, error)
	// CacheVersion, when set, contributes a tool/data version to the cache key (see
	// plugin.CacheVersioner). Optional.
	CacheVersion func(ctx context.Context) string
	// Prewarm, when set, warms shared tool state once before a run's fan-out (see
	// plugin.Prewarmer). Optional.
	Prewarm func(ctx context.Context) error
	// Refine, when set, adjusts the parsed report before it is returned. Tools describe a
	// finding's location in their own terms, which aren't always meaningful outside the tool;
	// this is where a scanner restates them in the target's terms. Optional.
	Refine func(target plugin.Target, report sarif.Report) sarif.Report
}

// Adapter is a Scanner backed by an external tool.
type Adapter struct {
	cfg Config
}

// New builds an Adapter. If cfg.Run is nil, the command is executed and its stdout is
// used as SARIF.
func New(cfg Config) *Adapter {
	if cfg.Run == nil {
		cfg.Run = execRun
	}
	return &Adapter{cfg: cfg}
}

// Info describes the underlying tool.
func (a *Adapter) Info() plugin.ScannerInfo {
	return plugin.ScannerInfo{
		Name:         a.cfg.Name,
		Binary:       a.cfg.Binary,
		Origin:       a.cfg.Origin,
		Version:      a.cfg.Version,
		Controls:     a.cfg.Controls,
		TargetKinds:  a.cfg.TargetKinds,
		ConfigSchema: a.cfg.ConfigSchema,
	}
}

// CacheVersion reports the tool/data version for the cache key, when the adapter was
// configured with one (implements plugin.CacheVersioner). Empty otherwise.
func (a *Adapter) CacheVersion(ctx context.Context) string {
	if a.cfg.CacheVersion == nil {
		return ""
	}
	return a.cfg.CacheVersion(ctx)
}

// Prewarm warms shared tool state before a run, when the adapter was configured with a
// prewarm hook (implements plugin.Prewarmer). No-op otherwise.
func (a *Adapter) Prewarm(ctx context.Context) error {
	if a.cfg.Prewarm == nil {
		return nil
	}
	return a.cfg.Prewarm(ctx)
}

// Scan builds and runs the command for target, then decodes its output. The tool name is
// backfilled onto the report and its results when the tool omits it.
func (a *Adapter) Scan(ctx context.Context, target plugin.Target, cfg plugin.Config) (sarif.Report, error) {
	argv, err := a.cfg.Argv(target, cfg)
	if err != nil {
		return sarif.Report{}, err
	}
	if len(argv) == 0 {
		return sarif.Report{}, errors.New("tooladapter: empty command")
	}

	out, err := a.cfg.Run(ctx, argv)
	if err != nil {
		return sarif.Report{}, fmt.Errorf("run %s: %w", a.cfg.Name, err)
	}

	report, err := a.decode(out, target, cfg)
	if err != nil {
		return sarif.Report{}, err
	}
	if report.Tool == "" {
		report.Tool = a.cfg.Name
	}
	for i := range report.Results {
		if report.Results[i].Tool == "" {
			report.Results[i].Tool = a.cfg.Name
		}
	}
	if a.cfg.Refine != nil {
		report = a.cfg.Refine(target, report)
	}
	return report, nil
}

// execRun runs the command and returns its stdout.
func execRun(ctx context.Context, argv []string) ([]byte, error) {
	started := time.Now()
	// Adapters intentionally run the configured tool; no shell (exec.CommandContext, not
	// "sh -c") and argv is built from typed config, not user shell input.
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) // #nosec G204 -- adapters intentionally run configured tools // nosem: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	out, err := cmd.Output()
	logToolRun(ctx, argv, "", started, out, err)
	return out, err
}

// logToolRun reports what Draugr actually ran. Without this a scan is a black box: you can see
// that a scanner failed but not the command, the directory, how long it took, or what the tool
// itself said. At trace the tool's own stderr is relayed, which is usually where the answer is.
func logToolRun(ctx context.Context, argv []string, dir string, started time.Time, out []byte, err error) {
	attrs := []any{
		"tool", argv[0],
		"argv", strings.Join(argv, " "),
		"duration", time.Since(started).Round(time.Millisecond).String(),
		"stdout_bytes", len(out),
	}
	if dir != "" {
		attrs = append(attrs, "dir", dir)
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		attrs = append(attrs, "exit_code", exit.ExitCode())
		// Output() puts the tool's stderr here; it explains failures far better than we can.
		if len(exit.Stderr) > 0 {
			slog.Log(ctx, levelTrace, "scanner stderr", "tool", argv[0], "stderr", string(exit.Stderr))
		}
	} else if err != nil {
		attrs = append(attrs, "error", err.Error())
	}
	slog.DebugContext(ctx, "ran scanner tool", attrs...)
}

// levelTrace mirrors observability.LevelTrace without importing it, keeping this package free of
// a dependency on the CLI's logging setup.
const levelTrace = slog.LevelDebug - 4

// decode turns the tool's output into a report, via SARIF unless the adapter was given its own
// parser. Mirrors how repository scanners handle a tool that doesn't speak SARIF.
func (a *Adapter) decode(out []byte, target plugin.Target, cfg plugin.Config) (sarif.Report, error) {
	if a.cfg.Parse != nil {
		report, err := a.cfg.Parse(out, target, cfg)
		if err != nil {
			return sarif.Report{}, fmt.Errorf("parse %s output: %w", a.cfg.Name, err)
		}
		return report, nil
	}
	report, err := sarif.FromSARIF(out)
	if err != nil {
		return sarif.Report{}, fmt.Errorf("parse %s SARIF: %w", a.cfg.Name, err)
	}
	return report, nil
}
