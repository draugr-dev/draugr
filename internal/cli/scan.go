package cli

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/draugr-dev/draugr/internal/builtins"
	"github.com/draugr-dev/draugr/internal/git"
	sbomgen "github.com/draugr-dev/draugr/internal/sbom"
	"github.com/draugr-dev/draugr/internal/version"
	"github.com/draugr-dev/draugr/pkg/cache"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/exploit"
	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/prioritization"
	"github.com/draugr-dev/draugr/pkg/publish"
	"github.com/draugr-dev/draugr/pkg/report"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/skald"

	"github.com/draugr-dev/draugr/internal/scanpolicy"
)

type scanOptions struct {
	outputDir       string
	failOn          string
	failOnPriority  string
	cacheDir        string
	cacheTTL        time.Duration
	minPriority     string
	allowEffects    []string
	kevFile         string
	epssFile        string
	epssThreshold   float64
	jobs            int
	format          string
	template        string
	templateFile    string
	noPublish       bool
	top             int
	noTips          bool
	allowScanErrors bool
	compact         bool
}

func newScanCommand() *cobra.Command {
	opts := &scanOptions{}
	cmd := &cobra.Command{
		Use:   "scan [saga.yaml | dir]",
		Short: "Scan an application described by a Saga (or a directory) and produce a verdict",
		Long: "Load a Saga descriptor, run the applicable security controls, and produce\n" +
			"pass/fail evidence. Exits non-zero when the policy verdict is fail.\n\n" +
			"Zero-config: point it at a directory (or omit the argument to use the current\n" +
			"one) and Draugr scans that repository with " + ZeroConfigControls("and") + " — no\n" +
			"Saga required. Write a Saga (or run `draugr init`) when you need more control.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := ""
			if len(args) == 1 {
				target = args[0]
			}
			return runScan(cmd.Context(), target, *opts, builtins.Registry(), cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVarP(&opts.outputDir, "output", "o", "", "directory to write report.json and results.sarif")
	cmd.Flags().StringVar(&opts.failOn, "fail-on", string(sarif.LevelError), "severity that fails the gate: error, warning, note")
	cmd.Flags().StringVar(&opts.failOnPriority, "fail-on-priority", "", "also fail the gate on any finding at or above this priority (P1-P4)")
	cmd.Flags().StringVar(&opts.cacheDir, "cache-dir", "", "enable content-hash caching in this directory")
	cmd.Flags().DurationVar(&opts.cacheTTL, "cache-ttl", 24*time.Hour, "cache entry lifetime (0 = no expiry)")
	cmd.Flags().StringVar(&opts.minPriority, "min-priority", "", "list findings at or above this priority band (P1-P4)")
	cmd.Flags().StringSliceVar(&opts.allowEffects, "allow-effects", nil,
		"accept scanner effects for this run (mutate, privilege); config.allowEffects is the reviewed equivalent")
	cmd.Flags().StringVar(&opts.kevFile, "kev", "", "CISA KEV catalog: a file path, or `auto`/`cache` to read ~/.draugr/feeds. A CVE on it is escalated to critical")
	cmd.Flags().StringVar(&opts.epssFile, "epss", "", "FIRST EPSS scores: a file path, or `auto`/`cache` to read ~/.draugr/feeds. A CVE at/above --epss-threshold is bumped one band")
	cmd.Flags().Float64Var(&opts.epssThreshold, "epss-threshold", 0.5, "EPSS probability (0-1) that triggers a severity bump")
	cmd.Flags().IntVarP(&opts.jobs, "jobs", "j", 0, "max scan jobs to run in parallel (0 = auto, one per CPU); reported as stats.concurrency")
	cmd.Flags().StringVar(&opts.format, "format", "console", "stdout report format: console, markdown, html, junit, json, sarif, template")
	cmd.Flags().StringVar(&opts.template, "template", "", "inline Go text/template (with --format template)")
	cmd.Flags().StringVar(&opts.templateFile, "template-file", "", "Go text/template file (with --format template)")
	cmd.Flags().BoolVar(&opts.noPublish, "no-publish", false, "skip the Saga's configured publishers (still writes -o artifacts and stdout)")
	cmd.Flags().IntVar(&opts.top, "top", 10, "console: max findings to list in the ranked table (0 = all)")
	cmd.Flags().BoolVar(&opts.noTips, "no-tips", false, "suppress the console's contextual tips (also DRAUGR_NO_TIPS)")
	cmd.Flags().BoolVar(&opts.allowScanErrors, "allow-scan-errors", false,
		"treat a control that couldn't run as a warning rather than a failure (best-effort scanning)")
	cmd.Flags().BoolVar(&opts.compact, "compact", false,
		"strip indentation and rule documentation from json/sarif output, for a consumer that acts on the report rather than reads it")
	return cmd
}

// runScan executes the full pipeline: describe → plan → scan → aggregate → judge → report.
// target is a Saga file, a directory to scan zero-config, or "" for the current directory.
func runScan(ctx context.Context, target string, opts scanOptions, reg *engine.Registry, w io.Writer) error {
	model, synthesized, err := scanModel(target)
	if err != nil {
		return err
	}
	if synthesized {
		// To stderr so it never pollutes a machine-readable stdout format (json/sarif).
		// Only reachable when the directory has no descriptor, so suggesting one is safe here —
		// it used to print over a descriptor that was sitting right there, telling the reader to
		// create the file they already had.
		// Names the shape rather than one filename: a reader whose file is called `web.saga.yaml`
		// would otherwise read "no draugr.saga.yaml here" as a filename mismatch and rename it,
		// when the real answer is that the file is somewhere else.
		_, _ = fmt.Fprintf(os.Stderr, "No *.saga.yaml here — scanning %s with controls: "+ZeroConfigControls("")+".\n"+
			"(run `draugr init` to scaffold one you can customize)\n\n", model.Components[0].Repositories[0].URL)
	}
	warnUncommitted(ctx, model)

	minPriority, err := validatePriority("--min-priority", opts.minPriority)
	if err != nil {
		return err
	}
	failOnPriority, err := validatePriority("--fail-on-priority", opts.failOnPriority)
	if err != nil {
		return err
	}
	expl, err := loadExploitSource(ctx, opts)
	if err != nil {
		return err
	}

	if opts.jobs < 0 {
		return fmt.Errorf("--jobs must be >= 0 (0 = auto, one per CPU)")
	}
	if opts.top < 0 {
		return fmt.Errorf("--top must be >= 0 (0 = show all)")
	}

	eopts := []engine.Option{
		engine.WithPrioritization(defaultPrioritizer(expl)),
		engine.WithSBOM(sbomgen.New()),
	}
	if opts.cacheDir != "" {
		eopts = append(eopts, engine.WithCache(cache.NewLocal(opts.cacheDir, opts.cacheTTL)))
	}
	if opts.jobs > 0 {
		eopts = append(eopts, engine.WithConcurrency(opts.jobs))
	}
	if len(opts.allowEffects) > 0 {
		eopts = append(eopts, engine.WithAllowedEffects(opts.allowEffects))
	}

	run, runErr := engine.New(reg, eopts...).Run(ctx, *model)
	if runErr != nil {
		slog.Warn("scan completed with issues", "error", runErr)
	}

	reports := make(map[string]sarif.Report, len(run.Controls))
	for name, cr := range run.Controls {
		reports[name] = cr.Report
	}
	policy := norn.Policy{
		FailOn:         sarif.Level(opts.failOn),
		PerControl:     perControlThresholds(model.Config.Gate),
		FailOnPriority: failOnPriority,
	}
	verdict := policy.Evaluate(reports)
	components, unattributed := componentVerdicts(policy, model, reports)
	// A control that couldn't run didn't find nothing — it found out nothing. Reporting that as
	// a pass makes the gate a false negative exactly when it matters: in CI, where a scanner
	// failing to provision is the common case and the warning scrolls past unread.
	unwaived, waived := splitScanErrors(run.ScanErrors)
	incomplete := len(unwaived) > 0 || (len(waived) > 0 && !opts.allowScanErrors)
	if incomplete {
		verdict.Verdict = norn.Fail
	}

	format := opts.format
	if format == "" {
		format = "console"
	}
	data := report.Data{
		Release:              model.Release,
		Run:                  run,
		Verdict:              verdict,
		MinPriority:          minPriority,
		TopN:                 fixFirstLimit(opts.top),
		Compact:              opts.compact,
		Components:           components,
		UnattributedFindings: unattributed,
		// Stamped so a rendered report can say when it ran and what produced it. A report
		// offered as evidence has to answer both, and only the CLI knows either.
		Generated: time.Now(),
		Version:   reportVersion(),
	}
	if format == "template" {
		art, err := report.Build(saga.ReportConfig{
			Format: "template", Template: opts.template, TemplateFile: opts.templateFile,
		}, data)
		if err != nil {
			return err
		}
		if _, err := w.Write(art.Bytes); err != nil {
			return err
		}
	} else {
		reporter, err := report.For(format)
		if err != nil {
			return err
		}
		if err := reporter.Render(w, data); err != nil {
			return err
		}
		if format == "console" {
			printScanTips(w, model, run, opts.noTips)
		}
	}
	if opts.outputDir != "" {
		if err := writeArtifacts(opts.outputDir, model.Release, run, verdict, minPriority); err != nil {
			return err
		}
	}
	// Deliver configured reports to configured publishers (Saga config.reports/publishers).
	// --no-publish suppresses this so a caller (e.g. the diff workflow, which scans both sides
	// of a PR) can produce artifacts without triggering side effects like a code-scanning upload.
	//
	// Held rather than returned: a run that both failed its gate and could not publish is two
	// facts, and the gate is the one the command exists to report. Returning here named the
	// publisher as the outcome and never mentioned the verdict, which sends a reader to fix a
	// token when what actually happened is that the build should not ship.
	var publishErr error
	if !opts.noPublish {
		publishErr = publish.Run(ctx, model.Config.Reports, model.Config.Publishers, data)
	}

	if incomplete {
		// Distinct from a policy failure: nothing was necessarily found, the scan just didn't
		// finish. Saying so is the difference between a bug report and a shrug.
		//
		// The flag is only offered when it would actually help. Recommending it for a planning
		// failure sent readers to a green PASS over a scan that had checked nothing — the flag
		// accepts a scanner that failed, and there was no scanner.
		if len(unwaived) > 0 {
			return alsoPublish(fmt.Errorf("scan incomplete: %s could not run — "+
				"--allow-scan-errors accepts a scanner that failed; it cannot accept a scan "+
				"that had nothing to do", strings.Join(unwaived, ", ")), publishErr)
		}
		return alsoPublish(fmt.Errorf("scan incomplete: %s could not run "+
			"(use --allow-scan-errors to accept partial results)",
			strings.Join(waived, ", ")), publishErr)
	}
	if verdict.Verdict == norn.Fail {
		return alsoPublish(fmt.Errorf("policy verdict: fail"), publishErr)
	}
	return publishErr
}

// alsoPublish folds a publishing failure into the run's outcome without displacing it.
//
// Both are worth knowing and only one can be the exit message, so the run's own outcome leads:
// a gate that failed is what the reader has to act on, and a publisher that could not deliver
// the evidence is the second sentence rather than the first. When the run itself was fine, the
// publishing failure is the outcome and stands alone.
func alsoPublish(outcome, publishErr error) error {
	if publishErr == nil {
		return outcome
	}
	return fmt.Errorf("%w (publishing also failed: %w)", outcome, publishErr)
}

// fixFirstLimit maps the --top flag to report.Data.TopN: 0 (show all) becomes -1, and any
// positive value passes through. The default (10) therefore shows ten rows, as before.
func fixFirstLimit(top int) int {
	if top == 0 {
		return -1
	}
	return top
}

// defaultPrioritizer builds the engine prioritizer from the shipped matrices and the
// per-control severity floors: resolve each finding's normalized severity, enrich it with
// exploitability (KEV/EPSS) when a source is loaded, then rank it by the component's exposure
// and criticality.
func defaultPrioritizer(expl *exploit.Source) engine.Prioritizer {
	return scanpolicy.DefaultPrioritizer(expl)
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

// reportVersion labels a rendered report. version.Version is "dev" for anything not built from
// a release tag, which reads in a report footer as though "dev" were the version number.
func reportVersion() string {
	if version.Version == "" || version.Version == "dev" {
		return "(development build)"
	}
	return "v" + strings.TrimPrefix(version.Version, "v")
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
	if err := skald.WriteSARIF(sarifFile, run); err != nil {
		return err
	}

	// SBOMs are evidence of the run and belong with the rest of it, so -o writes them too
	// rather than making them reachable only through a configured publisher.
	for _, a := range report.SBOMArtifacts(run.SBOMs) {
		if err := os.WriteFile(filepath.Join(dir, a.Filename), a.Bytes, 0o600); err != nil {
			return fmt.Errorf("write %s: %w", a.Filename, err)
		}
	}
	return nil
}

// perControlThresholds converts the Saga's gate block into the norn policy's per-control map.
// Nil when unset, which leaves every control on --fail-on.
func perControlThresholds(g *saga.GateConfig) map[string]sarif.Level {
	if g == nil || len(g.Controls) == 0 {
		return nil
	}
	out := make(map[string]sarif.Level, len(g.Controls))
	for control, level := range g.Controls {
		out[control] = sarif.Level(level)
	}
	return out
}

// splitScanErrors separates failures --allow-scan-errors cannot accept from those it can.
// Both lists are sorted, so the message is stable between runs.
func splitScanErrors(scanErrors map[string][]string) (unwaived, waived []string) {
	for control := range scanErrors {
		if engine.Waivable(control) {
			waived = append(waived, control)
		} else {
			unwaived = append(unwaived, control)
		}
	}
	sort.Strings(unwaived)
	sort.Strings(waived)
	return unwaived, waived
}

// componentVerdicts judges each component on its own findings, and counts those belonging to
// none.
//
// The same policy, re-run over a partition of the same findings — not a second implementation of
// the gate. Reproducing "what counts as failing" in the reporter is how the parts come to
// disagree with the whole, and the disagreement would surface as a component reading PASS under
// a headline that says FAIL.
//
// Findings with no component come from project-scoped controls (infrastructure). They are
// counted rather than assigned: a breakdown that quietly omits them makes the parts look like
// the whole.
func componentVerdicts(policy norn.Policy, model *saga.Model, reports map[string]sarif.Report) ([]report.ComponentVerdict, int) {
	if model == nil || len(model.Components) < 2 {
		// One component repeats what the headline already said. The breakdown exists to tell
		// components apart, and there is nothing to tell apart.
		return nil, 0
	}
	byComponent := map[string]map[string]sarif.Report{}
	unattributed := 0

	for control, rep := range reports {
		for _, res := range rep.Results {
			if res.Suppressed() {
				continue // the counts skip these, so the breakdown must too
			}
			if res.Component == "" {
				unattributed++
				continue
			}
			if byComponent[res.Component] == nil {
				byComponent[res.Component] = map[string]sarif.Report{}
			}
			r := byComponent[res.Component][control]
			r.Tool = rep.Tool
			r.Results = append(r.Results, res)
			byComponent[res.Component][control] = r
		}
	}
	// Every declared component gets a row, including the ones with nothing against them. A
	// clean component is the answer someone can take back to their team, and building the list
	// from the findings would have dropped exactly those.
	out := make([]report.ComponentVerdict, 0, len(model.Components))
	names := make([]string, 0, len(model.Components))
	for _, c := range model.Components {
		names = append(names, c.Name)
	}
	sort.Strings(names)
	for _, name := range names {
		res := policy.Evaluate(byComponent[name])
		cv := report.ComponentVerdict{Name: name, Verdict: res.Verdict}
		for _, c := range res.Controls {
			if c.Verdict == norn.Fail {
				cv.Controls = append(cv.Controls, c.Control)
			}
		}
		for _, rep := range byComponent[name] {
			for _, r := range rep.Results {
				cv.Findings++
				if band := priorityBand(r.Priority); band >= 0 {
					cv.Priorities[band]++
				}
			}
		}
		out = append(out, cv)
	}
	// Failing first: the reader is looking for what stops them shipping, and an alphabetical
	// list buries it behind whatever happens to start with an early letter.
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Verdict == norn.Fail && out[j].Verdict != norn.Fail
	})
	return out, unattributed
}

// priorityBand maps a priority label to its index, or -1 when unset.
func priorityBand(p string) int {
	switch p {
	case "P1":
		return 0
	case "P2":
		return 1
	case "P3":
		return 2
	case "P4":
		return 3
	}
	return -1
}

// warnUncommitted says when a local repository has work the scan will not see.
//
// A repository given as a path is cloned like any other source, so the scan describes the
// committed revision rather than the files on disk. That is the right behaviour — evidence has to
// name a revision someone else can reproduce — and it is silent, which is the problem: a change
// that introduces a finding passes until it is committed, and a fix appears not to have worked.
//
// Once per repository per run, not once per scanner. Four controls over one checkout is one fact
// about that checkout, and saying it four times is how a warning becomes wallpaper.
func warnUncommitted(ctx context.Context, model *saga.Model) {
	if model == nil {
		return
	}
	seen := map[string]bool{}
	for _, c := range model.Components {
		for _, r := range c.Repositories {
			if seen[r.URL] {
				continue
			}
			seen[r.URL] = true
			if n := git.UncommittedFiles(ctx, r.URL); n > 0 {
				slog.WarnContext(ctx, "scanning the committed revision, not your working tree",
					"repository", r.URL, "uncommitted_files", n)
			}
		}
	}
}
