package cli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/draugr-dev/draugr/pkg/config"
	"github.com/draugr-dev/draugr/pkg/diff"
	"github.com/draugr-dev/draugr/pkg/prioritization"
	"github.com/draugr-dev/draugr/pkg/publish"
	"github.com/draugr-dev/draugr/pkg/report"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/skald"
)

type diffOptions struct {
	format            string
	view              string
	top               int
	failOnNew         string
	failOnNewPriority string
	minPriority       string
	repository        string
	publish           bool
	// saga is --saga as typed: the descriptor, or a directory holding one, whose
	// config.gate.failOnNew applies where neither --fail-on-new spelling is passed.
	saga string
	// gate is that descriptor's gate block, read by the command before runDiff, and nil where no
	// descriptor was read.
	gate *saga.GateConfig
}

func newDiffCommand() *cobra.Command {
	opts := &diffOptions{}
	cmd := &cobra.Command{
		Use:   "diff [base.sarif] <head.sarif>",
		Short: "Compare two scans and classify findings as new, unaccepted, accepted, fixed or unchanged",
		Long: "Compare two Draugr SARIF results (the results.sarif that `draugr scan -o` writes)\n" +
			"and classify every finding as new / unaccepted / accepted / fixed / unchanged, the\n" +
			"security delta of a change, typically a PR's head vs its base branch.\n\n" +
			"Accepted is a finding somebody excused rather than fixed. Unaccepted is one whose\n" +
			"exclusion was removed or reached its expiry date, so it counts again; nobody\n" +
			"introduced it and nothing about it was ever fixed.\n\n" +
			"With the head report alone every finding is new, because there is no base to compare\n" +
			"against. It is the form for the pull request that adds a repository's first descriptor.\n\n" +
			"--fail-on-new gates on findings the change introduces, not on the existing backlog,\n" +
			"and takes a priority band or a severity. Exits non-zero when that gate trips. Without\n" +
			"it, config.gate.failOnNew in the descriptor applies: the one --saga names, or the one\n" +
			"in the working directory.\n\n" +
			"output.view and output.top in draugr.config.yaml set the --view and --top defaults,\n" +
			"as they do for `draugr scan`. A diff has no evidence section, so output.evidence\n" +
			"sets nothing here.",
		// One report is a head with no base to compare against: the pull request that adds the
		// descriptor has nothing at its base to scan.
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			wd, err := os.Getwd()
			if err != nil {
				return err
			}
			res, err := loadConfig(wd)
			if err != nil {
				return err
			}
			diffOutputFrom(opts, res.File.Output, changedFlags(cmd))
			// The descriptor is read only where it can decide something: a named one always, so a
			// path that names nothing is an error, and the working directory's only where no
			// threshold was typed.
			if opts.saga != "" || (opts.failOnNew == "" && opts.failOnNewPriority == "") {
				if opts.gate, err = diffDescriptorGate(opts.saga, cmd.ErrOrStderr()); err != nil {
					return err
				}
			}
			if len(args) == 1 {
				return runDiff(cmd.Context(), "", args[0], *opts, cmd.OutOrStdout())
			}
			return runDiff(cmd.Context(), args[0], args[1], *opts, cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVar(&opts.format, "format", "console", "output format: "+strings.Join(diff.Formats(), ", "))
	cmd.Flags().StringVar(&opts.view, "view", string(diff.ViewFindings),
		"what the listing shows: `findings` (a row each, with the finding's own sentence under it), "+
			"actions (a row per thing to do) or compact (one line each)")
	// Zero, where `scan` defaults to ten. A diff is already narrowed to what one change did, so
	// truncating it silently removes the thing the command exists to show; the flag is for the
	// dependency bump that introduces forty, and the gate counts every one either way.
	cmd.Flags().IntVar(&opts.top, "top", 0,
		"console: max findings to list (0 = all; output.top sets the default)")
	cmd.Flags().StringVar(&opts.failOnNew, "fail-on-new", "",
		"fail if the change introduces a finding at or above this: a priority band (P1-P4) or a "+
			"severity (critical, high, medium, low); overrides config.gate.failOnNew")
	cmd.Flags().StringVar(&opts.saga, "saga", "",
		"descriptor, or directory holding one, whose config.gate.failOnNew applies when "+
			"--fail-on-new is not passed (default: the one in the working directory)")
	cmd.Flags().StringVar(&opts.failOnNewPriority, "fail-on-new-priority", "",
		"deprecated: write the band in --fail-on-new, which takes either vocabulary")
	_ = cmd.Flags().MarkDeprecated("fail-on-new-priority",
		"use --fail-on-new, which takes a band or a severity")
	cmd.Flags().StringVar(&opts.minPriority, "min-priority", "", "report only new findings at or above this priority band (P1-P4); fixed and unchanged are unaffected")
	cmd.Flags().StringVar(&opts.repository, "repository", "",
		"keep only new findings from this repository, plus those belonging to none (an image, a "+
			"host). For a code-scanning upload, whose paths anchor to one checkout, a finding "+
			"from elsewhere would annotate a same-named file here")
	cmd.Flags().BoolVar(&opts.publish, "publish", false, "post the diff as a sticky pull-request comment (GitHub, GitLab or Azure DevOps, detected from the CI environment)")
	return cmd
}

// diffOutputFrom folds output.view and output.top under --view and --top, by the rule `scan`
// applies, so a flag typed on the command line wins and `top: 0` in the file keeps the built-in
// default. output.evidence has no flag here to default: a diff renders no evidence section.
func diffOutputFrom(opts *diffOptions, cfg config.OutputSettings, typed map[string]bool) {
	d := untypedOutput(cfg, typed)
	if d.view != "" {
		opts.view = d.view
	}
	if d.top != 0 {
		opts.top = d.top
	}
}

// runDiff loads both SARIF reports, compares them, renders the delta, optionally posts it as a
// PR comment, and applies the differential gate.
func runDiff(ctx context.Context, basePath, headPath string, opts diffOptions, w io.Writer) error {
	// The cheap check first. A mistyped gate level should not need two readable SARIF files
	// before it will admit to being mistyped, and it should certainly not be discovered after
	// the comment has already been posted.
	// One threshold in either vocabulary, the same as the gate `scan` applies. The older
	// --fail-on-new-priority still resolves, and the two together are refused for the reason the
	// pair on `scan` is: one of them would be doing nothing.
	failOn, failOnNewPriority, err := resolveDiffGate(opts.failOnNew, opts.failOnNewPriority, opts.gate)
	if err != nil {
		return err
	}
	// The same check `scan --min-priority` makes. A band outside P1-P4 would otherwise narrow
	// nothing, and the full list would read as the narrowed one.
	minPriority, err := validatePriority("--min-priority", opts.minPriority)
	if err != nil {
		return err
	}

	// No base path is a head with nothing to compare against. A base path that names nothing is
	// still an error: leaving the base out is a choice, and a missing file is a mistake.
	noBase := basePath == ""
	var base sarif.Report
	if !noBase {
		if base, err = loadSARIF(basePath); err != nil {
			return fmt.Errorf("base report: %w", err)
		}
	}
	head, err := loadSARIF(headPath)
	if err != nil {
		return fmt.Errorf("head report: %w", err)
	}
	// With no base there is no scope to compare and nothing for a head finding to match.
	var compared diff.Result
	if noBase {
		compared = diff.CompareWithoutBase(head)
	} else {
		headBand, _ := skald.MinPriorityOfReport(head)
		if err := comparableBands(basePath, base, headPath, headBand, minPriority); err != nil {
			return err
		}
		if compared, err = compareWithBase(basePath, base, headPath, head); err != nil {
			return err
		}
	}

	// Narrowed after the comparison, never before it: a diff computed from filtered inputs reads
	// every finding the filter removed as fixed.
	result := compared.NarrowNew(minPriority).OnlyRepository(opts.repository)

	// The gate travels with the result so every rendering states what the verdict was measured
	// against, and so the verdict itself is computed once rather than in each format.
	result.Gate = diff.Gate{FailOn: failOn, FailOnPriority: failOnNewPriority}
	result.Tripped = result.GateNew(failOn, failOnNewPriority)

	view, err := resolveDiffView(opts.view)
	if err != nil {
		return err
	}
	render := diff.Options{View: view, Top: opts.top}
	if err := diff.Render(w, opts.format, result, render); err != nil {
		return err
	}

	// The gate is the outcome; publishing is delivery. Returning a publish failure here would
	// replace the verdict rather than accompany it. The run reports a missing token, and the P1
	// this change introduced is never mentioned. That sends a reader to fix a credential when what
	// actually happened is that the change should not merge. `scan` reconciles the two the same
	// way, and a delivery problem still exits non-zero: a flag either does something or says why
	// it did not.
	var publishErr error
	if opts.publish {
		// The same view the run was asked for. Which of the two shapes a team wants is a property
		// of how they review rather than of the change, so it is set once in the pipeline template
		// and the comment follows it.
		publishErr = publishDiff(ctx, result, render)
	}

	if len(result.Tripped) > 0 {
		return alsoPublish(errNewFindings(len(result.Tripped)), publishErr)
	}
	// The gate passed and only delivery failed, which is still non-zero. But the message has to
	// say which, because the two are the same color in a checks list and only one of them is about
	// the code under review. Without the first clause a reader sees a red tick and a forge error
	// and has no way to tell it from a change that introduced a finding.
	if publishErr != nil {
		return fmt.Errorf("the gate passed, but publishing failed: %w", publishErr)
	}
	return nil
}

// diffPublisherKind picks the sticky-comment publisher for the CI system this is running on.
//
// Hardcoding GitHub would make --publish a flag that silently does nothing on an Azure agent:
// the GitHub publisher no-ops when it cannot see GITHUB_ACTIONS, so the run stays green and the
// comment never appears. A flag either does something or says why it did not.
func diffPublisherKind() string {
	switch {
	case os.Getenv("TF_BUILD") == "True":
		return "azure-pr-comment"
	case os.Getenv("GITLAB_CI") == "true":
		return "gitlab-mr-comment"
	}
	return "github-pr-comment"
}

// publishDiff renders the diff as markdown and delivers it as a sticky pull-request comment on
// whichever CI system is running it. Outside a pull request the publisher no-ops.
func publishDiff(ctx context.Context, result diff.Result, opts diff.Options) error {
	var md bytes.Buffer
	if err := diff.Render(&md, "markdown", result, opts); err != nil {
		return err
	}
	// A distinct marker from the Saga's own PR-comment publisher. A pipeline running both, a full
	// report and the delta this pull request introduced. Wants two comments, and sharing the
	// default meant the second silently replaced the first.
	pub, err := publish.For(saga.PublisherConfig{
		Kind: diffPublisherKind(), Marker: publish.DiffMarker,
	})
	if err != nil {
		return err
	}
	return pub.Publish(ctx, []report.Artifact{{
		Format:      "markdown",
		Filename:    "draugr-diff.md",
		ContentType: "text/markdown",
		Bytes:       md.Bytes(),
	}})
}

// loadSARIF reads and parses a SARIF report file.
func loadSARIF(path string) (sarif.Report, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- operator-provided report path
	if err != nil {
		return sarif.Report{}, err
	}
	rep, err := sarif.FromSARIF(data)
	if err != nil {
		return sarif.Report{}, fmt.Errorf("%s: %w", path, err)
	}
	return rep, nil
}

// compareWithBase is the comparison `draugr diff` makes and `draugr scan --base` makes, one
// function so the two cannot classify one pair of reports differently: refused where the reports
// did not cover the same ground, and otherwise every finding classified by diff.Compare.
func compareWithBase(baseName string, base sarif.Report, headName string, head sarif.Report) (diff.Result, error) {
	if err := comparableScopes(baseName, base, headName, head); err != nil {
		return diff.Result{}, err
	}
	return diff.Compare(base, head), nil
}

// diffDescriptorGate is the gate block of the descriptor whose config.gate.failOnNew a diff
// applies: the one --saga names, or else the one in the working directory. Nil where there is
// none to read.
//
// A named descriptor that cannot be found or read is an error, because somebody asked for it. In
// the working directory, none is the diff of two reports with no descriptor beside them, which
// gates nothing as it always has. Several is said on w and read as none: picking one by name
// would apply a gate nobody chose, and refusing would stop a diff that asked for no gate at all.
func diffDescriptorGate(sagaPath string, w io.Writer) (*saga.GateConfig, error) {
	path := ""
	if sagaPath != "" {
		found := false
		var err error
		if path, found, err = resolveDescriptor(sagaPath, "diff --saga"); err != nil {
			return nil, err
		}
		if !found {
			return nil, fmt.Errorf("--saga: no *.saga.yaml in %s. Name a descriptor file, or a directory that holds one", sagaPath)
		}
	} else {
		here, err := descriptorsIn(".")
		if err != nil {
			return nil, err
		}
		switch len(here) {
		case 0:
			return nil, nil
		case 1:
			path = here[0]
		default:
			names := make([]string, len(here))
			for i, p := range here {
				names[i] = filepath.Base(p)
			}
			_, _ = fmt.Fprintf(w, "config.gate.failOnNew not read: the working directory holds %d descriptors (%s). "+
				"Name one with --saga.\n", len(here), strings.Join(names, ", "))
			return nil, nil
		}
	}
	model, err := loadSaga(path)
	if err != nil {
		return nil, err
	}
	return model.Config.Gate, nil
}

// comparableScopes refuses to compare two reports that did not cover the same ground.
//
// Every finding present in the base and absent from the head is reported as fixed. That is
// correct when both scans looked at the same things, and confidently wrong when one of them was
// scoped: a diff of a one-component head against a twelve-component base announces that eleven
// components' worth of findings were resolved, and a gate on new findings passes it.
//
// Refusing rather than warning, because the failure is silent and the output is not obviously
// wrong. It is a list of fixes, which is the thing a reader was hoping to see. A warning above
// a plausible answer is a warning that gets read after the decision.
func comparableScopes(basePath string, base sarif.Report, headPath string, head sarif.Report) error {
	baseScope, baseScoped := skald.ScopeOfReport(base)
	headScope, headScoped := skald.ScopeOfReport(head)
	if baseScope == headScope {
		return nil
	}
	describe := func(path, scope string, scoped bool) string {
		if !scoped {
			return path + " covered everything the descriptor declares"
		}
		return path + " was scoped to " + scope
	}
	return fmt.Errorf("these reports do not describe the same scan:\n  %s\n  %s\n"+
		"a finding the head did not look for would be reported as fixed. Re-run the scoped side "+
		"unscoped, or scope both the same way",
		describe(basePath, baseScope, baseScoped), describe(headPath, headScope, headScoped))
}

// comparableBands refuses to compare two reports narrowed to bands the comparison would misread.
//
// A report written with --artifact-min-priority, or from a publisher report with minPriority, holds only
// the findings at or above its band, and says so inside itself. Compared with a report holding more,
// every finding below that band reads as new, when the base is the narrower one, or as fixed, when
// the head is. A gate on new findings then fails a change that introduced nothing, or a reader is
// told that findings were resolved when they were only left out.
//
// headBand is the band the head was narrowed to, "" where it holds every finding, as a scan in
// progress does. minPriority is the band below which the comparison reports nothing new, from
// `draugr diff --min-priority`; a base narrowed to it or below covers what is judged. Refused rather
// than judged at the narrower band, so a gate never silently judges a band other than the one
// configured.
func comparableBands(basePath string, base sarif.Report, headPath, headBand, minPriority string) error {
	baseBand, baseNarrowed := skald.MinPriorityOfReport(base)
	// Narrowed to P4 holds every banded finding, and narrowing keeps the unbanded ones, so it holds
	// what a whole report holds.
	if rankOf(baseBand) <= rankOf("P4") {
		baseBand, baseNarrowed = "", false
	}
	if rankOf(headBand) <= rankOf("P4") {
		headBand = ""
	}
	if headBand != "" && (!baseNarrowed || rankOf(headBand) > rankOf(baseBand)) {
		baseHolds := "holds every band"
		if baseNarrowed {
			baseHolds = "was narrowed to " + baseBand
		}
		return fmt.Errorf("these reports were not narrowed to the same band:\n  %s %s\n  %s was narrowed to %s\n"+
			"every %s finding in the base would be reported as fixed. Narrow the base to %s too, or "+
			"write the head without narrowing it", basePath, baseHolds, headPath, headBand, bandsBelow(headBand), headBand)
	}
	if !baseNarrowed {
		return nil
	}
	reach := headBand
	if minPriority != "" && (reach == "" || rankOf(minPriority) > rankOf(reach)) {
		reach = minPriority
	}
	if reach != "" && rankOf(reach) >= rankOf(baseBand) {
		return nil
	}
	headHolds := "holds every band"
	if headBand != "" {
		headHolds = "was narrowed to " + headBand
	}
	fix := "Write the base without narrowing it (no --artifact-min-priority or minPriority)"
	if headPath != thisScan {
		fix += ", or pass --min-priority " + baseBand
	}
	return fmt.Errorf("these reports were not narrowed to the same band:\n  %s was narrowed to %s\n  %s %s\n"+
		"every %s finding in the head would be reported as new. %s",
		basePath, baseBand, headPath, headHolds, bandsBelow(baseBand), fix)
}

// rankOf is a band's urgency, P1 highest, as prioritization ranks it.
func rankOf(band string) int { return prioritization.Priority(strings.ToUpper(band)).Rank() }

// bandsBelow names the bands less urgent than band, such as "P3 or P4" below P2.
func bandsBelow(band string) string {
	var below []string
	for _, b := range []string{"P1", "P2", "P3", "P4"} {
		if rankOf(b) < rankOf(band) {
			below = append(below, b)
		}
	}
	if len(below) == 1 {
		return below[0]
	}
	return strings.Join(below[:len(below)-1], ", ") + " or " + below[len(below)-1]
}

// resolveDiffView turns the flag into a view, refusing a name that is not one.
//
// The same three names `scan` takes, so a reader who has learned one has learned the other, and a
// typo says which names exist rather than quietly falling back to the default.
func resolveDiffView(name string) (diff.View, error) {
	switch diff.View(name) {
	case "", diff.ViewFindings:
		return diff.ViewFindings, nil
	case diff.ViewActions:
		return diff.ViewActions, nil
	case diff.ViewCompact:
		return diff.ViewCompact, nil
	}
	return "", fmt.Errorf("unknown view %q (available: %s)", name, strings.Join(diff.Views(), ", "))
}
