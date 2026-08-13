package cli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/draugr-dev/draugr/pkg/diff"
	"github.com/draugr-dev/draugr/pkg/publish"
	"github.com/draugr-dev/draugr/pkg/report"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/skald"
)

type diffOptions struct {
	format            string
	failOnNew         string
	failOnNewPriority string
	minPriority       string
	repository        string
	publish           bool
}

func newDiffCommand() *cobra.Command {
	opts := &diffOptions{}
	cmd := &cobra.Command{
		Use:   "diff <base.sarif> <head.sarif>",
		Short: "Compare two scans and classify findings as new, fixed, or unchanged",
		Long: "Compare two Draugr SARIF results (the results.sarif that `draugr scan -o` writes)\n" +
			"and classify every finding as new / fixed / unchanged — the security delta of a\n" +
			"change, typically a PR's head vs its base branch.\n\n" +
			"--fail-on-new and --fail-on-new-priority gate on findings the change introduces, not\n" +
			"on the existing backlog. Exits non-zero when that gate trips.",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDiff(cmd.Context(), args[0], args[1], *opts, cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVar(&opts.format, "format", "console", "output format: "+strings.Join(diff.Formats(), ", "))
	cmd.Flags().StringVar(&opts.failOnNew, "fail-on-new", "", "fail if a new finding is at or above this severity: error, warning, note")
	cmd.Flags().StringVar(&opts.failOnNewPriority, "fail-on-new-priority", "", "fail if a new finding is at or above this priority (P1-P4)")
	cmd.Flags().StringVar(&opts.minPriority, "min-priority", "", "report only new findings at or above this priority band (P1-P4); fixed and unchanged are unaffected")
	cmd.Flags().StringVar(&opts.repository, "repository", "",
		"keep only new findings from this repository, plus those belonging to none (an image, a "+
			"host). For a code-scanning upload, whose paths anchor to one checkout — a finding "+
			"from elsewhere would annotate a same-named file here")
	cmd.Flags().BoolVar(&opts.publish, "publish", false, "post the diff as a sticky pull-request comment (GitHub or Azure DevOps, detected from the CI environment)")
	return cmd
}

// runDiff loads both SARIF reports, compares them, renders the delta, optionally posts it as a
// PR comment, and applies the differential gate.
func runDiff(ctx context.Context, basePath, headPath string, opts diffOptions, w io.Writer) error {
	// The cheap check first. A mistyped gate level should not need two readable SARIF files
	// before it will admit to being mistyped, and it should certainly not be discovered after
	// the comment has already been posted.
	var failOn sarif.Level
	if opts.failOnNew != "" {
		var err error
		if failOn, err = sarif.ParseLevel(opts.failOnNew); err != nil {
			return fmt.Errorf("--fail-on-new: %w", err)
		}
	}

	base, err := loadSARIF(basePath)
	if err != nil {
		return fmt.Errorf("base report: %w", err)
	}
	head, err := loadSARIF(headPath)
	if err != nil {
		return fmt.Errorf("head report: %w", err)
	}

	if err := comparableScopes(basePath, base, headPath, head); err != nil {
		return err
	}

	// Narrowed after the comparison, never before it: a diff computed from filtered inputs reads
	// every finding the filter removed as fixed.
	result := diff.Compare(base, head).NarrowNew(opts.minPriority).OnlyRepository(opts.repository)
	if err := diff.Render(w, opts.format, result); err != nil {
		return err
	}

	if opts.publish {
		if err := publishDiff(ctx, result); err != nil {
			return err
		}
	}

	tripped := result.GateNew(failOn, opts.failOnNewPriority)
	if len(tripped) > 0 {
		return fmt.Errorf("differential gate: %d new finding(s) at or above the threshold", len(tripped))
	}
	return nil
}

// diffPublisherKind picks the sticky-comment publisher for the CI system this is running on.
//
// Hardcoding GitHub would make --publish a flag that silently does nothing on an Azure agent:
// the GitHub publisher no-ops when it cannot see GITHUB_ACTIONS, so the run stays green and the
// comment never appears. A flag either does something or says why it did not.
func diffPublisherKind() string {
	if os.Getenv("TF_BUILD") == "True" {
		return "azure-pr-comment"
	}
	return "github-pr-comment"
}

// publishDiff renders the diff as markdown and delivers it as a sticky pull-request comment on
// whichever CI system is running it. Outside a pull request the publisher no-ops.
func publishDiff(ctx context.Context, result diff.Result) error {
	var md bytes.Buffer
	if err := diff.Render(&md, "markdown", result); err != nil {
		return err
	}
	// A distinct marker from the Saga's own PR-comment publisher. A pipeline running both — a
	// full report and the delta this pull request introduced — wants two comments, and sharing
	// the default meant the second silently replaced the first.
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
	return sarif.FromSARIF(data)
}

// comparableScopes refuses to compare two reports that did not cover the same ground.
//
// Every finding present in the base and absent from the head is reported as fixed. That is
// correct when both scans looked at the same things, and confidently wrong when one of them was
// scoped: a diff of a one-component head against a twelve-component base announces that eleven
// components' worth of findings were resolved, and a gate on new findings passes it.
//
// Refusing rather than warning, because the failure is silent and the output is not obviously
// wrong — it is a list of fixes, which is the thing a reader was hoping to see. A warning above
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
		"a finding the head did not look for would be reported as fixed — re-run the scoped side "+
		"unscoped, or scope both the same way",
		describe(basePath, baseScope, baseScoped), describe(headPath, headScope, headScoped))
}
