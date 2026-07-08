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
	Version     string
	Controls    []string
	TargetKinds []plugin.TargetKind
	// Argv builds the command line (argv[0] is the executable) for a target and config.
	Argv func(target plugin.Target, cfg plugin.Config) ([]string, error)
	// Run executes argv and returns the tool's SARIF output. Optional; defaults to
	// executing the command and capturing stdout.
	Run func(ctx context.Context, argv []string) ([]byte, error)
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
		Version:     a.cfg.Version,
		Controls:    a.cfg.Controls,
		TargetKinds: a.cfg.TargetKinds,
	}
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
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) //nolint:gosec // adapters intentionally run configured tools
	return cmd.Output()
}
