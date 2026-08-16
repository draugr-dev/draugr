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
	"github.com/draugr-dev/draugr/internal/netpolicy"
	sbomgen "github.com/draugr-dev/draugr/internal/sbom"
	"github.com/draugr-dev/draugr/internal/tools"
	"github.com/draugr-dev/draugr/internal/version"
	"github.com/draugr-dev/draugr/pkg/cache"
	"github.com/draugr-dev/draugr/pkg/config"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/exploit"
	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/prioritization"
	"github.com/draugr-dev/draugr/pkg/publish"
	"github.com/draugr-dev/draugr/pkg/report"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/skald"

	"github.com/draugr-dev/draugr/internal/scanpolicy"
)

type scanOptions struct {
	outputDir          string
	reports            []string
	failOn             string
	noGate             bool
	workingTree        bool
	failOnPriority     string
	cacheDir           string
	cacheTTL           time.Duration
	cacheReadOnly      bool
	cacheRequireDigest bool
	group              string
	evidence           bool
	minPriority        string
	// artifactMinPriority narrows the written artifacts as well, which --min-priority
	// deliberately does not. Separate because they answer to different readers: one trims a
	// terminal, the other changes a file another program acts on.
	artifactMinPriority string
	allowEffects        []string
	kevFile             string
	epssFile            string
	epssThreshold       float64
	// setFlags names the flags the user actually typed. Needed because the descriptor supplies
	// defaults for the same settings, and a flag with a non-zero default — --epss-threshold is
	// 0.5 — cannot be told apart from an unset one by its value.
	setFlags        map[string]bool
	jobs            int
	format          string
	template        string
	templateFile    string
	noPublish       bool
	top             int
	noTips          bool
	components      []string
	controls        []string
	allowScanErrors bool
	compact         bool
}

// scanFlagGroups is how `draugr scan --help` is organised: a heading per question a reader
// arrives with, rather than one alphabetical list of thirty-odd flags.
//
// Order is deliberate and is not alphabetical either. It runs from what a scan looks at, through
// what its answer means, to how the answer is delivered — the order the decisions are actually
// made in.
var scanFlagGroups = []flagGroup{
	{"What is scanned", []string{"components", "controls", "working-tree"}},
	{"What fails the build", []string{"fail-on", "fail-on-priority", "no-gate", "allow-scan-errors"}},
	{"Exploitability data", []string{"kev", "epss", "epss-threshold"}},
	{"Output", []string{
		"format", "output", "report", "group", "evidence", "top", "min-priority",
		"artifact-min-priority", "compact", "template", "template-file", "no-tips",
	}},
	{"Caching", []string{"cache-dir", "cache-ttl", "cache-read-only", "cache-require-digest"}},
	{"Running the scan", []string{"jobs", "allow-effects", "no-publish"}},
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
			"Saga required. Write a Saga (or run `draugr init`) when you need more control.\n\n" +
			"Answers you give every time — the cache, scanner builds, how you like the report —\n" +
			"belong in draugr.config.yaml rather than on this command line. `draugr config show`\n" +
			"prints what is in effect and where each setting came from.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := ""
			if len(args) == 1 {
				target = args[0]
			}
			opts.setFlags = changedFlags(cmd)
			return runScan(cmd.Context(), target, *opts, builtins.Registry(), cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVarP(&opts.outputDir, "output", "o", "", "directory to write reports into (see --report; default report.json and results.sarif)")
	cmd.Flags().BoolVar(&opts.workingTree, "working-tree", false,
		"scan repositories as they are on disk, uncommitted work included — for iterating on a "+
			"fix without committing. The result is not reproducible and the report says so")
	cmd.Flags().BoolVar(&opts.noGate, "no-gate", false,
		"report the verdict but exit 0 on a fail — for producing a report to compare later, "+
			"where `draugr diff` is the gate")
	cmd.Flags().StringVar(&opts.failOn, "fail-on", string(sarif.LevelError), "severity that fails the gate: error, warning, note")
	cmd.Flags().StringVar(&opts.failOnPriority, "fail-on-priority", "", "also fail the gate on any finding at or above this priority (P1-P4)")
	cmd.Flags().BoolVar(&opts.evidence, "evidence", false,
		"also print what stands behind the verdict: tool provenance, what each control measured "+
			"against, the scanned revision, and what the run cost")
	cmd.Flags().StringVar(&opts.group, "group", groupAction,
		"how the fix list is organised: `action` (one row per thing to do) or none (one per finding)")
	cmd.Flags().StringVar(&opts.cacheDir, "cache-dir", "", "enable content-hash caching in this directory")
	cmd.Flags().DurationVar(&opts.cacheTTL, "cache-ttl", 24*time.Hour, "cache entry lifetime (0 = no expiry)")
	cmd.Flags().BoolVar(&opts.cacheReadOnly, "cache-read-only", false,
		"read the cache but never write it — for a run whose results should not be trusted by the next one")
	cmd.Flags().BoolVar(&opts.cacheRequireDigest, "cache-require-digest", false,
		"do not cache an image identified only by a tag: a tag can be rebuilt, so a hit can be right about the key and wrong about the image")
	cmd.Flags().StringVar(&opts.minPriority, "min-priority", "", "list findings at or above this priority band (P1-P4)")
	cmd.Flags().StringVar(&opts.artifactMinPriority, "artifact-min-priority", "",
		"also narrow the -o artifacts to this band, and record the band inside them; "+
			"--min-priority alone narrows only what is printed, because a file that silently "+
			"omits findings is read as a scan that did not find them")
	cmd.Flags().StringSliceVar(&opts.allowEffects, "allow-effects", nil,
		"accept scanner effects for this run (mutate, privilege); config.allowEffects is the reviewed equivalent")
	cmd.Flags().StringVar(&opts.kevFile, "kev", "", "CISA KEV catalog: a file path, or `auto`/`cache` to read ~/.draugr/feeds. A CVE on it is escalated to critical")
	cmd.Flags().StringVar(&opts.epssFile, "epss", "", "FIRST EPSS scores: a file path, or `auto`/`cache` to read ~/.draugr/feeds. A CVE at/above --epss-threshold is bumped one band")
	cmd.Flags().Float64Var(&opts.epssThreshold, "epss-threshold", 0.5, "EPSS probability (0-1) that triggers a severity bump")
	cmd.Flags().IntVarP(&opts.jobs, "jobs", "j", 0, "max scan jobs to run in parallel (0 = auto, one per CPU); reported as stats.concurrency")
	cmd.Flags().StringVar(&opts.format, "format", "console",
		"what to print: "+strings.Join(report.StreamFormats, ", "))
	// Built from the registry, not restated. --format already does this; --report listed its
	// formats by hand, so a format could ship, work, and be undiscoverable from the one place a
	// user looks for the list.
	cmd.Flags().StringSliceVar(&opts.reports, "report", nil,
		"formats to write into -o ("+strings.Join(report.Formats(), ", ")+"); default json,sarif")
	cmd.Flags().StringVar(&opts.template, "template", "", "inline Go text/template (with --format template)")
	cmd.Flags().StringVar(&opts.templateFile, "template-file", "", "Go text/template file (with --format template)")
	cmd.Flags().BoolVar(&opts.noPublish, "no-publish", false, "skip the Saga's configured publishers (still writes -o artifacts and stdout)")
	cmd.Flags().IntVar(&opts.top, "top", 10, "console: max findings to list in the ranked table (0 = all)")
	cmd.Flags().BoolVar(&opts.noTips, "no-tips", false, "suppress the console's contextual tips (also DRAUGR_NO_TIPS)")
	cmd.Flags().StringSliceVar(&opts.components, "components", nil,
		"scan only these components; the verdict says what it covered")
	cmd.Flags().StringSliceVar(&opts.controls, "controls", nil,
		"run only these controls; the verdict says what it covered")
	cmd.Flags().BoolVar(&opts.allowScanErrors, "allow-scan-errors", false,
		"treat a control that couldn't run as a warning rather than a failure (best-effort scanning)")
	cmd.Flags().BoolVar(&opts.compact, "compact", false,
		"strip indentation and rule documentation from json/sarif output, for a consumer that acts on the report rather than reads it")

	useFlagGroups(cmd, scanFlagGroups)

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
		// Only reachable when the directory has no descriptor, which is what makes suggesting one
		// safe: the same words printed over a descriptor that exists tell the reader to create a
		// file they already have.
		// Names the shape rather than one filename: a reader whose file is called `web.saga.yaml`
		// would otherwise read "no draugr.saga.yaml here" as a filename mismatch and rename it,
		// when the real answer is that the file is somewhere else.
		_, _ = fmt.Fprintf(os.Stderr, "No *.saga.yaml here — scanning %s with controls: "+ZeroConfigControls("")+".\n"+
			"(run `draugr init` to scaffold one you can customize)\n\n", model.Components[0].Repositories[0].URL)
	}
	// Organisation defaults are merged *underneath* the descriptor, so the engine sees one
	// effective Saga and nothing downstream has to know there were two files. Merged after the
	// descriptor has been validated on its own, so an error still names what the author wrote.
	cfg, err := applyConfigDefaults(ctx, model)
	if err != nil {
		return err
	}
	cacheOptionsFrom(&opts, cfg.Cache)
	outputOptionsFrom(&opts, cfg.Output)

	// Validated before anything runs, and against this descriptor. A misspelled name matches
	// nothing, scans nothing, and passes — the "we did not look" verdict the scope is otherwise
	// careful not to produce, reached by typo.
	scope := engine.Scope{Components: opts.components, Controls: opts.controls}
	if err := scope.Validate(*model, controlNames(reg)); err != nil {
		return err
	}
	// Resolved once, here, where the descriptor is: everything downstream reads what was left out
	// off the scope rather than needing the descriptor again. A rendered report knows what ran,
	// not what was declared.
	scope = scope.Resolve(*model)

	minPriority, err := validatePriority("--min-priority", opts.minPriority)
	if err != nil {
		return err
	}
	failOnPriority, err := validatePriority("--fail-on-priority", opts.failOnPriority)
	if err != nil {
		return err
	}
	// Before the scan, not after. A typo discovered once the scanners have finished is a wasted
	// pipeline minute for a mistake that was visible on the command line.
	failOn, err := sarif.ParseLevel(opts.failOn)
	if err != nil {
		return fmt.Errorf("--fail-on: %w", err)
	}
	if err := checkWorkingTree(opts.workingTree, model); err != nil {
		return err
	}
	expl, feedProv, err := loadExploitSource(ctx, exploitSettings(opts, model.Config.Exploitability))
	if err != nil {
		return err
	}

	if opts.jobs < 0 {
		return fmt.Errorf("--jobs must be >= 0 (0 = auto, one per CPU)")
	}
	if opts.top < 0 {
		return fmt.Errorf("--top must be >= 0 (0 = show all)")
	}
	if err := validateGroup(opts.group); err != nil {
		return err
	}

	eopts := []engine.Option{
		engine.WithPrioritization(defaultPrioritizer(expl)),
		engine.WithSBOM(sbomgen.New()),
		// Name a local checkout by the repository it came from, so a scan here and a scan in a
		// pipeline recognise each other as one source rather than two.
		engine.WithRemoteResolver(func(path string) string {
			if !git.IsLocalPath(path) {
				return ""
			}
			return git.RemoteURL(context.Background(), path)
		}),
	}
	if netpolicy.Offline() {
		eopts = append(eopts, engine.WithoutPrewarm())
	}
	if opts.cacheDir != "" {
		var c cache.Cache = cache.NewLocal(opts.cacheDir, opts.cacheTTL)
		if opts.cacheReadOnly {
			c = cache.ReadOnly(c)
		}
		if opts.cacheRequireDigest {
			eopts = append(eopts, engine.WithCacheableTarget(digestPinnedOnly))
		}
		eopts = append(eopts, engine.WithCache(c))
	}
	if opts.jobs > 0 {
		eopts = append(eopts, engine.WithConcurrency(opts.jobs))
	}
	// Drawn on stderr so a report on stdout stays a report, and only for somebody watching one.
	progress := newProgressLine(os.Stderr, opts)
	if progress != nil {
		eopts = append(eopts, engine.WithProgress(progress.update))
		defer progress.done()
	}
	if len(opts.allowEffects) > 0 {
		eopts = append(eopts, engine.WithAllowedEffects(opts.allowEffects))
	}
	if opts.workingTree {
		eopts = append(eopts, engine.WithWorkingTree())
	}
	if !scope.Empty() {
		eopts = append(eopts, engine.WithScope(scope))
	}

	// One checkout per repository for this run, shared by every scanner that asks for the same
	// one. Owned by the invocation rather than the engine: the lifetime is this run's, and
	// pkg/engine orchestrates targets in general — it should not learn about git to make
	// repositories cheaper.
	pool := git.NewPool()
	defer pool.Close()
	ctx = git.WithPool(ctx, pool)

	// The error is deliberately not logged here. Every failure it joins is also recorded against
	// a control in run.ScanErrors — a planning failure against a pseudo-control precisely so it
	// has somewhere to be reported from — so the report prints each one under the control it
	// belongs to, and the command exits naming the control that could not run. Logging the join
	// as well puts a third copy of the same sentences on the screen, the longest of them first,
	// above the report that explains them.
	run, _ := engine.New(reg, eopts...).Run(ctx, *model)

	// Erased here rather than only on the way out. The deferred call runs when this function
	// returns, which is after the report has been written — so the line describing a run in
	// progress stays on the terminal while the report prints over it, and the verdict arrives
	// welded to a job counter. The run is finished at this point and the line has nothing left
	// to say; done is idempotent, so the defer remains as the path for an early return.
	progress.done()

	reports := make(map[string]sarif.Report, len(run.Controls))
	for name, cr := range run.Controls {
		reports[name] = cr.Report
	}
	policy := norn.Policy{
		FailOn:         failOn,
		PerControl:     perControlThresholds(model.Config.Gate),
		FailOnPriority: failOnPriority,
	}
	verdict := policy.Evaluate(reports)
	components, unattributed := componentVerdicts(policy, model, reports, scope, run.Stats.Unscanned)
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
	// Checked here rather than when the reporter is looked up, so the message can say where a
	// document format did go instead of only that it is not a printable one.
	if err := report.StreamFormat(format); err != nil {
		return err
	}
	if len(opts.reports) > 0 && opts.outputDir == "" {
		return fmt.Errorf("--report needs somewhere to write: pass -o <dir>")
	}
	for _, f := range opts.reports {
		if _, err := report.For(f); err != nil {
			return err
		}
	}
	data := report.Data{
		Release:              model.Release,
		Run:                  run,
		Verdict:              verdict,
		MinPriority:          minPriority,
		TopN:                 fixFirstLimit(opts.top),
		GroupActions:         opts.group != groupNone, // "" is unset, and the default is grouped
		Evidence:             opts.evidence,
		Compact:              opts.compact,
		Components:           components,
		Scope:                reportScope(scope),
		UnattributedFindings: unattributed,
		Exploitability:       feedProv,
		Tools:                toolBuilds(ctx, run),
		Repositories:         report.RepositoriesFrom(run),
		VEX:                  model.Config.VEX,
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
			printScanTips(w, tipContext{model: model, run: run, verdict: verdict, opts: &opts})
		}
	}
	if opts.outputDir != "" {
		if err := writeArtifacts(opts.outputDir, opts.reports, data, model.Release, run, verdict, minPriority, declaredBand(opts, model)); err != nil {
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
			return alsoPublish(fmt.Errorf("scan incomplete: %s could not run. "+
				"--allow-scan-errors does not apply: it accepts a failed scanner, and no scanner ran",
				strings.Join(unwaived, ", ")), publishErr)
		}
		return alsoPublish(fmt.Errorf("scan incomplete: %s could not run "+
			"(use --allow-scan-errors to accept partial results)",
			strings.Join(waived, ", ")), publishErr)
	}
	// --no-gate suppresses the *verdict's* exit code only. A scan that could not run still fails,
	// above: the flag says "I am producing a report to compare later, and the comparison is the
	// gate" — not "ignore whatever happened". `|| true` in a pipeline cannot tell the two apart,
	// and swallows the scan error that leaves no report for the diff to read.
	if verdict.Verdict == norn.Fail && !opts.noGate {
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

// How the fix list is organised.
const (
	// groupAction is the default: one row per thing to do, saying how many findings it clears.
	groupAction = "action"
	// groupNone lists every finding on its own row, which is what somebody auditing a specific
	// finding wants.
	groupNone = "none"
)

// validateGroup rejects a value that is not one of the two, rather than quietly choosing.
//
// A mistyped --group that fell through to the default would render a list the reader did not ask
// for and say nothing about it — a flag that either does something or explains why it did not.
func validateGroup(v string) error {
	switch v {
	// Empty is unset rather than mistyped: a caller building the options directly, or a test,
	// gets the same default the flag does rather than an error about a flag it never set.
	case "", groupAction, groupNone:
		return nil
	default:
		return fmt.Errorf("--group %q is not %s or %s", v, groupAction, groupNone)
	}
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

// defaultArtifacts is what -o writes when --report says nothing: the two a pipeline already
// depends on.
var defaultArtifacts = []string{"json", "sarif"}

// declaredBand is the priority band the artifacts were asked to be narrowed to, or "" for the
// complete set.
//
// The flag wins over the descriptor so a workflow can narrow what it uploads without editing a
// file it may not own — the same precedence every other scan setting uses. Only a sarif report's
// band is consulted, because -o writes one sarif and asking which of several reports it came from
// has no answer.
func declaredBand(opts scanOptions, model *saga.Model) string {
	if opts.artifactMinPriority != "" {
		return opts.artifactMinPriority
	}
	for _, r := range model.Config.Reports {
		if r.Format == "sarif" && r.MinPriority != "" {
			return r.MinPriority
		}
	}
	return ""
}

// firstNonEmpty returns the first value that is set.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// writeArtifacts renders the requested formats into dir.
//
// The formats are rendered through the same reporters that serve --format and the Saga's
// config.reports, so an HTML file written here and one delivered by a publisher cannot differ.
func writeArtifacts(dir string, formats []string, data report.Data, release saga.Release,
	run engine.Result, verdict norn.Result, minPriority, declared string,
) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	if len(formats) == 0 {
		formats = defaultArtifacts
	}

	for _, format := range formats {
		name := report.Filename(format)
		// json and sarif go through skald directly, as they always have. They are written complete
		// regardless of --min-priority, because a file that claims to be the scan and is not
		// misleads whatever consumes it — most sharply `draugr diff`, which reads a missing
		// finding as a fixed one.
		//
		// `declared` is the exception, and the difference is that it was asked for: a descriptor
		// that says minPriority on a report, or --artifact-min-priority on the command line. The
		// artifact then states the band inside itself, so a consumer can tell a narrowed file from
		// a whole one rather than having to assume.
		switch format {
		case "json":
			if err := writeTo(filepath.Join(dir, name), func(w io.Writer) error {
				return skald.RenderJSON(w, release, run, verdict, firstNonEmpty(declared, minPriority))
			}); err != nil {
				return err
			}
		case "sarif":
			if err := writeTo(filepath.Join(dir, name), func(w io.Writer) error {
				return skald.WriteSARIFNarrowed(w, report.FilterByPriority(run, declared), declared, sarif.MarshalOptions{})
			}); err != nil {
				return err
			}
		default:
			r, err := report.For(format)
			if err != nil {
				return err
			}
			if err := writeTo(filepath.Join(dir, name), func(w io.Writer) error {
				return r.Render(w, data)
			}); err != nil {
				return err
			}
		}
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

// writeTo creates path and hands the writer to render, closing it either way.
func writeTo(path string, render func(io.Writer) error) error {
	f, err := os.Create(path) // #nosec G304 -- operator-provided output dir
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	if err := render(f); err != nil {
		return fmt.Errorf("write %s: %w", filepath.Base(path), err)
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
func componentVerdicts(
	policy norn.Policy, model *saga.Model, reports map[string]sarif.Report,
	scope engine.Scope, unscanned []engine.Unscanned,
) ([]report.ComponentVerdict, int) {
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
	// Every declared component *that ran* gets a row, including the ones with nothing against
	// them. A clean component is the answer someone can take back to their team, and building
	// the list from the findings would drop exactly those.
	//
	// A component the scope left out is not one of them, and must not appear here as passing:
	// nothing looked at it, so a `pass` beside its name would be the report asserting something
	// no scanner established. It is listed separately as `not scanned`.
	out := make([]report.ComponentVerdict, 0, len(model.Components))
	names := make([]string, 0, len(model.Components))
	for _, c := range model.Components {
		if scope.IncludesComponent(c.Name) {
			names = append(names, c.Name)
		}
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
		for _, u := range unscanned {
			if u.Component == name {
				cv.Unscanned = append(cv.Unscanned, u)
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

// digestPinnedOnly refuses to cache an image identified only by a mutable tag.
//
// A tag is a name, not content. Rebuild and re-push `acme/api:latest` and the cache key is
// unchanged, so the next scan reports the previous image's findings and is entirely convinced.
// Every other target Draugr scans is content-addressed already — a commit, a digest, a normalised
// endpoint — which is why this is the one exception worth being able to switch off.
//
// Off by default: the reader who pins digests loses nothing, and refusing to cache tags outright
// would punish the common case to prevent an uncommon one. Turning it on is for a pipeline that
// would rather re-scan than be wrong.
func digestPinnedOnly(t plugin.Target) bool {
	img, ok := t.(plugin.ImageTarget)
	if !ok {
		return true // not an image; nothing about it is mutable behind our back
	}
	return img.Digest != ""
}

// applyConfigDefaults merges the machine/organisation controller defaults under the descriptor.
//
// Under, not over: a project that has an opinion keeps it, and inherits the rest. The alternative
// — defaults that a Saga cannot override — is a guarantee a CLI cannot keep, because the config
// lives on a machine the same person controls.
func applyConfigDefaults(ctx context.Context, model *saga.Model) (config.File, error) {
	wd, err := os.Getwd()
	if err != nil {
		return config.File{}, err
	}
	res, err := config.Load(rootConfigPath, wd)
	if err != nil {
		return config.File{}, err
	}
	if len(res.File.Controllers) == 0 {
		return res.File, nil
	}
	if model.Config.Controllers == nil {
		model.Config.Controllers = map[string]saga.ControllerSettings{}
	}
	for control, defaults := range res.File.Controllers {
		model.Config.Controllers[control] = config.DeepMerge(defaults, model.Config.Controllers[control])
	}
	// Said once, at debug: a reader wondering why a control behaved unexpectedly needs to know a
	// second file had a say, and `draugr config show` is where the detail lives.
	slog.DebugContext(ctx, "merged controller defaults from configuration",
		"files", len(res.Sources), "controls", len(res.File.Controllers))
	return res.File, nil
}

// outputOptionsFrom folds the configured rendering preferences under the flags.
//
// Same rule as the cache settings, and the same reason: a typed flag cannot tell "not passed"
// from "passed its zero value", so the test is whether it was typed. Without that, `--top 0`
// (show everything, deliberately) would read as absent and a configured cap would override an
// explicit instruction.
func outputOptionsFrom(opts *scanOptions, cfg config.OutputSettings) {
	if cfg.Group != "" && !opts.setFlags["group"] {
		opts.group = cfg.Group
	}
	if cfg.Evidence && !opts.setFlags["evidence"] {
		opts.evidence = true
	}
	if cfg.Top != 0 && !opts.setFlags["top"] {
		opts.top = cfg.Top
	}
}

// cacheOptionsFrom folds the configured cache settings under the flags.
//
// A typed flag cannot distinguish "not passed" from "passed its zero value", so the check is
// whether it was *typed* — otherwise `--cache-ttl 0` (no expiry, deliberately) would read as
// absent and the configured value would override an explicit instruction.
func cacheOptionsFrom(opts *scanOptions, cfg config.CacheSettings) {
	if cfg.Dir != "" && !opts.setFlags["cache-dir"] {
		opts.cacheDir = cfg.Dir
	}
	if cfg.TTL != 0 && !opts.setFlags["cache-ttl"] {
		opts.cacheTTL = cfg.TTL
	}
	// Booleans only ever turn on: a config that says read-only means somebody decided this
	// machine's results should not be trusted by the next run, and a flag's absence is not an
	// argument against that. --cache-read-only=false is still honoured, because it was typed.
	if cfg.ReadOnly && !opts.setFlags["cache-read-only"] {
		opts.cacheReadOnly = true
	}
	if cfg.RequireDigest && !opts.setFlags["cache-require-digest"] {
		opts.cacheRequireDigest = true
	}
}

// toolBuilds reports the build of each external scanner the run actually used.
//
// Derived from the results rather than from the registry: a scanner that was configured but never
// ran has no bearing on how these findings were produced, and listing it would pad the evidence
// with tools that did nothing.
//
// Native scanners are skipped — their rules ship in this binary, so "which build" is answered by
// Draugr's own version, which the report already stamps.
func toolBuilds(ctx context.Context, run engine.Result) []report.ToolBuild {
	binaries := map[string]bool{}
	for _, name := range run.Scanners {
		// The registry is the only thing that maps a scanner to its executable. A finding's Tool
		// is the SARIF driver name the tool gives itself — "Trivy" for trivy-fs — so matching on
		// it finds nothing, which is exactly what the first version of this did.
		if sc, ok := builtins.Registry().Scanner(name); ok {
			if b := sc.Info().Binary; b != "" {
				binaries[b] = true
			}
		}
	}
	if len(binaries) == 0 {
		return nil
	}

	names := make([]string, 0, len(binaries))
	for b := range binaries {
		names = append(names, b)
	}
	sort.Strings(names)

	out := make([]report.ToolBuild, 0, len(names))
	for _, b := range names {
		a := tools.AttestFound(b, "")
		// The version of a tool Draugr installed comes from its install record. A tool the
		// operator brought has no record, so it had none — and that is the one this section
		// exists for. The whole reason a scan runs whatever is on PATH rather than refusing it is
		// that the report can still say which build produced the findings; without a version it
		// says only that Draugr did not install it, which is a fact about Draugr rather than
		// about the run, and cannot be reproduced from.
		if a.Version == "" {
			a.Version = probeVersion(ctx, b)
		}
		out = append(out, report.ToolBuild{
			Name: a.Tool, Version: a.Version, Level: string(a.Level),
			Reason: tools.DescribeFor(a.Level, a.Tool),
		})
	}
	return out
}

// probeVersion asks a tool on PATH what version it is, or returns "" if it will not say.
//
// Best-effort and bounded: this runs after a scan has finished, to describe what produced it, and
// a tool that hangs on `--version` must not hold the report. Nothing here fails the run — a
// missing version is the state this improves on, not a regression to guard against.
func probeVersion(ctx context.Context, binary string) string {
	t, ok := tools.Catalog()[binary]
	if !ok || len(t.VersionArgs) == 0 {
		return ""
	}
	ctx, cancel := context.WithTimeout(ctx, versionProbeTimeout)
	defer cancel()
	if st := tools.Detect(ctx, t, nil, nil); st.Found {
		return st.Version
	}
	return ""
}

// versionProbeTimeout bounds the extra call. Two seconds is far longer than any of these take and
// far shorter than a reader waiting on a report will tolerate.
const versionProbeTimeout = 2 * time.Second

// checkWorkingTree refuses --working-tree for a descriptor Draugr cannot honour it for.
//
// A remote repository has no working tree. Falling back to the committed revision would produce a
// report that looks like the one asked for and describes something else — and the whole reason to
// ask is that you want to see work that is not committed yet.
func checkWorkingTree(enabled bool, model *saga.Model) error {
	if !enabled || model == nil {
		return nil
	}
	var remote []string
	for _, c := range model.Components {
		for _, r := range c.Repositories {
			if !git.IsLocalPath(r.URL) {
				remote = append(remote, r.URL)
			}
		}
	}
	if len(remote) > 0 {
		return fmt.Errorf("--working-tree needs a local checkout, and %s %s a remote: "+
			"scan without the flag, or point the descriptor at a path",
			strings.Join(remote, ", "), plural2(len(remote), "is", "are"))
	}
	return nil
}

// reportScope describes a scoped run for the report, and returns nil for an unscoped one.
//
// nil rather than an empty struct so an unscoped report renders and serialises exactly as it
// always has. The presence of a scope is the signal, and inventing an empty one for every run
// would turn that signal into a field consumers have to interpret.
func reportScope(scope engine.Scope) *report.Scope {
	if scope.Empty() {
		return nil
	}
	return &report.Scope{
		Components:        scope.Components,
		Controls:          scope.Controls,
		SkippedComponents: scope.SkippedComponents,
	}
}
