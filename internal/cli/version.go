package cli

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/draugr-dev/draugr/internal/version"
)

func newVersionCommand() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print the Draugr version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Not cmd.Println: Cobra's Print* helpers write to stderr, which breaks the
			// canonical `v=$(draugr version)`. The version is this command's output.
			out := cmd.OutOrStdout()
			if asJSON {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(version.Current())
			}
			_, err := fmt.Fprintln(out, version.String())
			return err
		},
	}
	// --json rather than --format json: this command has exactly one machine format, and it
	// matches `doctor --json`. Reserve --format for commands that render several (scan).
	cmd.Flags().BoolVar(&asJSON, "json", false, "output the version as JSON")
	return cmd
}
