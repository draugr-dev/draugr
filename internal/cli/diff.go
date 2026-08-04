package cli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/draugr-dev/draugr/pkg/diff"
	"github.com/draugr-dev/draugr/pkg/publish"
	"github.com/draugr-dev/draugr/pkg/report"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

type diffOptions struct {
	format            string
	failOnNew         string
	failOnNewPriority string
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
			"The differential gate (--fail-on-new / --fail-on-new-priority) fails only on findings\n" +
			"the change *introduces*, not the pre-existing backlog — so a PR gate stays adoptable.\n" +
			"Exits non-zero when the differential gate trips.",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDiff(cmd.Context(), args[0], args[1], *opts, cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVar(&opts.format, "format", "console", "output format: console, markdown, json")
	cmd.Flags().StringVar(&opts.failOnNew, "fail-on-new", "", "fail if a new finding is at or above this severity: error, warning, note")
	cmd.Flags().StringVar(&opts.failOnNewPriority, "fail-on-new-priority", "", "fail if a new finding is at or above this priority (P1-P4)")
	cmd.Flags().BoolVar(&opts.publish, "publish", false, "post the diff as a sticky pull-request comment (GitHub or Azure DevOps, detected from the CI environment)")
	return cmd
}

// runDiff loads both SARIF reports, compares them, renders the delta, optionally posts it as a
// PR comment, and applies the differential gate.
func runDiff(ctx context.Context, basePath, headPath string, opts diffOptions, w io.Writer) error {
	base, err := loadSARIF(basePath)
	if err != nil {
		return fmt.Errorf("base report: %w", err)
	}
	head, err := loadSARIF(headPath)
	if err != nil {
		return fmt.Errorf("head report: %w", err)
	}

	result := diff.Compare(base, head)
	if err := diff.Render(w, opts.format, result); err != nil {
		return err
	}

	if opts.publish {
		if err := publishDiff(ctx, result); err != nil {
			return err
		}
	}

	tripped := result.GateNew(sarif.Level(opts.failOnNew), opts.failOnNewPriority)
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
	data, err := os.ReadFile(path) //nolint:gosec // operator-provided report path
	if err != nil {
		return sarif.Report{}, err
	}
	return sarif.FromSARIF(data)
}
