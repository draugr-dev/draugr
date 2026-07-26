package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/draugr-dev/draugr/internal/version"
	"github.com/draugr-dev/draugr/pkg/saga"
)

func newSchemaCommand() *cobra.Command {
	var out string
	cmd := &cobra.Command{
		Use:   "schema",
		Short: "Print the Saga JSON Schema this build enforces",
		Long: "Print the JSON Schema for draugr.saga.yaml, as embedded in this binary.\n\n" +
			"Editors normally fetch the schema from draugr.dev, which requires network access and\n" +
			"tracks whatever version is published. Writing it locally instead pins validation to\n" +
			"exactly the Draugr you have installed, and works offline or air-gapped:\n\n" +
			"  draugr schema -o .saga.schema.json\n" +
			"  # then in your Saga:\n" +
			"  # yaml-language-server: $schema=./.saga.schema.json",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if out == "" {
				_, err := cmd.OutOrStdout().Write(saga.SchemaJSON)
				return err
			}
			if err := os.WriteFile(out, saga.SchemaJSON, 0o600); err != nil {
				return fmt.Errorf("write schema: %w", err)
			}
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(),
				"wrote %s (draugr %s)\nreference it from a Saga with:\n  # yaml-language-server: $schema=%s\n",
				out, version.Version, schemaRef(out))
			return nil
		},
	}
	cmd.Flags().StringVarP(&out, "output", "o", "", "write the schema to this file instead of stdout")
	return cmd
}

// schemaRef formats a path as the YAML language server expects it: a relative path needs a
// leading "./" to be recognised, an absolute one must not gain one.
func schemaRef(path string) string {
	if filepath.IsAbs(path) || strings.HasPrefix(path, "./") || strings.HasPrefix(path, "../") {
		return path
	}
	return "./" + path
}
