// Package tooladapter turns an external command-line security tool into a Draugr
// Scanner declaratively: describe how to build the command for a target, and the adapter
// runs it and parses its SARIF output. This covers the majority of scanners (many emit
// SARIF natively) with no bespoke code.
package tooladapter

import (
	"context"
	"errors"
	"fmt"
	"os/exec"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// Config declares how to adapt a tool.
type Config struct {
	Name        string
	Binary      string
	Version     string
	Controls    []string
	TargetKinds []plugin.TargetKind
	// Argv builds the command line (argv[0] is the executable) for a target and config.
	Argv func(target plugin.Target, cfg plugin.Config) ([]string, error)
	// Run executes argv and returns the tool's SARIF output. Optional; defaults to
	// executing the command and capturing stdout.
	Run func(ctx context.Context, argv []string) ([]byte, error)
	// CacheVersion, when set, contributes a tool/data version to the cache key (see
	// plugin.CacheVersioner). Optional.
	CacheVersion func(ctx context.Context) string
	// Prewarm, when set, warms shared tool state once before a run's fan-out (see
	// plugin.Prewarmer). Optional.
	Prewarm func(ctx context.Context) error
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
		Name:        a.cfg.Name,
		Binary:      a.cfg.Binary,
		Version:     a.cfg.Version,
		Controls:    a.cfg.Controls,
		TargetKinds: a.cfg.TargetKinds,
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

// Scan builds and runs the command for target, then parses its SARIF output. The tool
// name is backfilled onto the report and its results when the tool omits it.
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

	report, err := sarif.FromSARIF(out)
	if err != nil {
		return sarif.Report{}, fmt.Errorf("parse %s SARIF: %w", a.cfg.Name, err)
	}
	if report.Tool == "" {
		report.Tool = a.cfg.Name
	}
	for i := range report.Results {
		if report.Results[i].Tool == "" {
			report.Results[i].Tool = a.cfg.Name
		}
	}
	return report, nil
}

// execRun runs the command and returns its stdout.
func execRun(ctx context.Context, argv []string) ([]byte, error) {
	// Adapters intentionally run the configured tool; no shell (exec.CommandContext, not
	// "sh -c") and argv is built from typed config, not user shell input.
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) //nolint:gosec // adapters intentionally run configured tools // nosem: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	return cmd.Output()
}
