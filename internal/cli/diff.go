package cli

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/draugr-dev/draugr/pkg/diff"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

type diffOptions struct {
	format            string
	failOnNew         string
	failOnNewPriority string
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
			return runDiff(args[0], args[1], *opts, cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVar(&opts.format, "format", "console", "output format: console, markdown, json")
	cmd.Flags().StringVar(&opts.failOnNew, "fail-on-new", "", "fail if a new finding is at or above this severity: error, warning, note")
	cmd.Flags().StringVar(&opts.failOnNewPriority, "fail-on-new-priority", "", "fail if a new finding is at or above this priority (P1-P4)")
	return cmd
}

// runDiff loads both SARIF reports, compares them, renders the delta, and applies the
// differential gate.
func runDiff(basePath, headPath string, opts diffOptions, w io.Writer) error {
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

	tripped := result.GateNew(sarif.Level(opts.failOnNew), opts.failOnNewPriority)
	if len(tripped) > 0 {
		return fmt.Errorf("differential gate: %d new finding(s) at or above the threshold", len(tripped))
	}
	return nil
}

// loadSARIF reads and parses a SARIF report file.
func loadSARIF(path string) (sarif.Report, error) {
	data, err := os.ReadFile(path) //nolint:gosec // operator-provided report path
	if err != nil {
		return sarif.Report{}, err
	}
	return sarif.FromSARIF(data)
}
