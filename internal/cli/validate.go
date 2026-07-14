package cli

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/draugr-dev/draugr/pkg/saga"
)

func newValidateCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "validate <saga.yaml>",
		Short: "Validate a Saga descriptor against the schema",
		Long: "Parse a Saga descriptor, resolve ${{ VAR }} references, and check it against\n" +
			"the schema — without running any scanners. Fast and dependency-free, so it fits\n" +
			"a pre-commit hook, a CI lint step, or an editor. Exits non-zero when invalid.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runValidate(args[0], cmd.OutOrStdout())
		},
	}
}

// runValidate loads the Saga (which parses, substitutes env vars, and validates); a nil
// error means the descriptor is valid.
func runValidate(sagaPath string, w io.Writer) error {
	if _, err := saga.LoadFile(sagaPath); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(w, "✓ %s is valid\n", sagaPath)
	return nil
}
