package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/draugr-dev/draugr/internal/version"
)

func newVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the Draugr version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Not cmd.Println: Cobra's Print* helpers write to stderr, which breaks the
			// canonical `v=$(draugr version)`. The version is this command's output.
			_, err := fmt.Fprintln(cmd.OutOrStdout(), version.String())
			return err
		},
	}
}
