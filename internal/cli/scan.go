package cli

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/draugr-dev/draugr/internal/builtins"
	"github.com/draugr-dev/draugr/internal/controllers"
	"github.com/draugr-dev/draugr/pkg/cache"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/exploit"
	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/prioritization"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/skald"
)

type scanOptions struct {
	outputDir      string
	failOn         string
	failOnPriority string
	cacheDir       string
	cacheTTL       time.Duration
	minPriority    string
	kevFile        string
	epssFile       string
	epssThreshold  float64
	jobs           int
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
	cmd.Flags().StringVar(&opts.failOnPriority, "fail-on-priority", "", "also fail the gate on any finding at or above this priority (P1-P4)")
	cmd.Flags().StringVar(&opts.cacheDir, "cache-dir", "", "enable content-hash caching in this directory")
	cmd.Flags().DurationVar(&opts.cacheTTL, "cache-ttl", 24*time.Hour, "cache entry lifetime (0 = no expiry)")
	cmd.Flags().StringVar(&opts.minPriority, "min-priority", "", "list findings at or above this priority band (P1-P4)")
	cmd.Flags().StringVar(&opts.kevFile, "kev", "", "CISA KEV catalog JSON: a CVE on it is escalated to critical")
	cmd.Flags().StringVar(&opts.epssFile, "epss", "", "FIRST EPSS scores CSV: a CVE at/above --epss-threshold is bumped one severity band")
	cmd.Flags().Float64Var(&opts.epssThreshold, "epss-threshold", 0.5, "EPSS probability (0-1) that triggers a severity bump")
	cmd.Flags().IntVarP(&opts.jobs, "jobs", "j", 0, "max scan jobs to run in parallel (0 = auto, one per CPU); reported as stats.concurrency")
	return cmd
}

// runScan executes the full pipeline: describe → plan → scan → aggregate → judge → report.
func runScan(ctx context.Context, sagaPath string, opts scanOptions, reg *engine.Registry, w io.Writer) error {
	model, err := loadSaga(sagaPath)
	if err != nil {
		return err
	}
	minPriority, err := validatePriority("--min-priority", opts.minPriority)
	if err != nil {
		return err
	}
	failOnPriority, err := validatePriority("--fail-on-priority", opts.failOnPriority)
	if err != nil {
		return err
	}
	expl, err := loadExploitSource(opts)
	if err != nil {
		return err
	}

	if opts.jobs < 0 {
		return fmt.Errorf("--jobs must be >= 0 (0 = auto, one per CPU)")
	}

	eopts := []engine.Option{engine.WithPrioritization(defaultPrioritizer(expl))}
	if opts.cacheDir != "" {
		eopts = append(eopts, engine.WithCache(cache.NewLocal(opts.cacheDir, opts.cacheTTL)))
	}
	if opts.jobs > 0 {
		eopts = append(eopts, engine.WithConcurrency(opts.jobs))
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
	verdict := norn.Policy{FailOn: sarif.Level(opts.failOn), FailOnPriority: failOnPriority}.Evaluate(reports)

	if err := skald.RenderJSON(w, model.Release, run, verdict, minPriority); err != nil {
		return err
	}
	if opts.outputDir != "" {
		if err := writeArtifacts(opts.outputDir, model.Release, run, verdict, minPriority); err != nil {
			return err
		}
	}

	if verdict.Verdict == norn.Fail {
		return fmt.Errorf("policy verdict: fail")
	}
	return nil
}

// defaultPrioritizer builds the engine prioritizer from the shipped matrices and the
// per-control severity floors: resolve each finding's normalized severity, enrich it with
// exploitability (KEV/EPSS) when a source is loaded, then rank it by the component's exposure
// and criticality.
func defaultPrioritizer(expl *exploit.Source) engine.Prioritizer {
	matrices := prioritization.DefaultMatrices()
	return func(control string, exposure saga.Exposure, criticality saga.Criticality, res sarif.Result) string {
		sev := res.Severity(controllers.SeverityFloor(control))
		sev = expl.Enrich(sev, res.RuleID) // nil-safe: no-op when no source
		return string(matrices.Prioritize(exposure, criticality, sev))
	}
}

// loadExploitSource builds an exploitability source from the optional --kev / --epss files.
// Returns nil when neither is provided (enrichment disabled).
func loadExploitSource(opts scanOptions) (*exploit.Source, error) {
	if opts.kevFile == "" && opts.epssFile == "" {
		return nil, nil
	}
	var kev map[string]bool
	var epss map[string]float64
	if opts.kevFile != "" {
		f, err := os.Open(opts.kevFile) //nolint:gosec // operator-provided path
		if err != nil {
			return nil, fmt.Errorf("open --kev: %w", err)
		}
		defer func() { _ = f.Close() }()
		if kev, err = exploit.LoadKEV(f); err != nil {
			return nil, fmt.Errorf("parse --kev: %w", err)
		}
	}
	if opts.epssFile != "" {
		f, err := os.Open(opts.epssFile) //nolint:gosec // operator-provided path
		if err != nil {
			return nil, fmt.Errorf("open --epss: %w", err)
		}
		defer func() { _ = f.Close() }()
		if epss, err = exploit.LoadEPSS(f); err != nil {
			return nil, fmt.Errorf("parse --epss: %w", err)
		}
	}
	return exploit.New(kev, epss, opts.epssThreshold), nil
}

// validatePriority validates and upper-cases a priority-band flag value. Empty is allowed
// (feature disabled); flag names the flag for the error message.
func validatePriority(flag, v string) (string, error) {
	if v == "" {
		return "", nil
	}
	up := strings.ToUpper(v)
	switch prioritization.Priority(up) {
	case prioritization.P1, prioritization.P2, prioritization.P3, prioritization.P4:
		return up, nil
	default:
		return "", fmt.Errorf("invalid %s %q (want one of P1, P2, P3, P4)", flag, v)
	}
}

func writeArtifacts(dir string, release saga.Release, run engine.Result, verdict norn.Result, minPriority string) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	reportFile, err := os.Create(filepath.Join(dir, "report.json")) //nolint:gosec // operator-provided output dir
	if err != nil {
		return err
	}
	defer func() { _ = reportFile.Close() }()
	if err := skald.RenderJSON(reportFile, release, run, verdict, minPriority); err != nil {
		return err
	}

	sarifFile, err := os.Create(filepath.Join(dir, "results.sarif")) //nolint:gosec // operator-provided output dir
	if err != nil {
		return err
	}
	defer func() { _ = sarifFile.Close() }()
	return skald.WriteSARIF(sarifFile, run)
}
