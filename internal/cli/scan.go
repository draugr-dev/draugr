package cli

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/draugr-dev/draugr/internal/builtins"
	"github.com/draugr-dev/draugr/pkg/cache"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/skald"
)

type scanOptions struct {
	outputDir string
	failOn    string
	cacheDir  string
	cacheTTL  time.Duration
}

func newScanCommand() *cobra.Command {
	opts := &scanOptions{}
	cmd := &cobra.Command{
		Use:   "scan <saga.yaml>",
		Short: "Scan an application described by a Saga and produce a verdict",
		Long: "Load a Saga descriptor, run the applicable security controls, and produce\n" +
			"pass/fail evidence. Exits non-zero when the policy verdict is fail.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScan(cmd.Context(), args[0], *opts, builtins.Registry(), cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVarP(&opts.outputDir, "output", "o", "", "directory to write report.json and results.sarif")
	cmd.Flags().StringVar(&opts.failOn, "fail-on", string(sarif.LevelError), "severity that fails the gate: error, warning, note")
	cmd.Flags().StringVar(&opts.cacheDir, "cache-dir", "", "enable content-hash caching in this directory")
	cmd.Flags().DurationVar(&opts.cacheTTL, "cache-ttl", 24*time.Hour, "cache entry lifetime (0 = no expiry)")
	return cmd
}

// runScan executes the full pipeline: describe → plan → scan → aggregate → judge → report.
func runScan(ctx context.Context, sagaPath string, opts scanOptions, reg *engine.Registry, w io.Writer) error {
	model, err := saga.LoadFile(sagaPath)
	if err != nil {
		return err
	}

	var eopts []engine.Option
	if opts.cacheDir != "" {
		eopts = append(eopts, engine.WithCache(cache.NewLocal(opts.cacheDir, opts.cacheTTL)))
	}

	run, runErr := engine.New(reg, eopts...).Run(ctx, *model)
	if runErr != nil {
		// Scan/plan issues are surfaced but do not by themselves fail the gate.
		slog.Warn("scan completed with issues", "error", runErr)
	}

	reports := make(map[string]sarif.Report, len(run.Controls))
	for name, cr := range run.Controls {
		reports[name] = cr.Report
	}
	verdict := norn.Policy{FailOn: sarif.Level(opts.failOn)}.Evaluate(reports)

	if err := skald.RenderJSON(w, model.Release, run, verdict); err != nil {
		return err
	}
	if opts.outputDir != "" {
		if err := writeArtifacts(opts.outputDir, model.Release, run, verdict); err != nil {
			return err
		}
	}

	if verdict.Verdict == norn.Fail {
		return fmt.Errorf("policy verdict: fail")
	}
	return nil
}

func writeArtifacts(dir string, release saga.Release, run engine.Result, verdict norn.Result) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	reportFile, err := os.Create(filepath.Join(dir, "report.json")) //nolint:gosec // operator-provided output dir
	if err != nil {
		return err
	}
	defer func() { _ = reportFile.Close() }()
	if err := skald.RenderJSON(reportFile, release, run, verdict); err != nil {
		return err
	}

	sarifFile, err := os.Create(filepath.Join(dir, "results.sarif")) //nolint:gosec // operator-provided output dir
	if err != nil {
		return err
	}
	defer func() { _ = sarifFile.Close() }()
	return skald.WriteSARIF(sarifFile, run)
}
