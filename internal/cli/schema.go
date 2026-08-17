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
	var fragment bool
	cmd := &cobra.Command{
		Use:   "schema",
		Short: "Print the Saga JSON Schema this build enforces",
		Long: "Print the JSON Schema for draugr.saga.yaml, as embedded in this binary.\n\n" +
			"Editors fetch it from draugr.dev by default, which needs network access and follows\n" +
			"whatever is published. A local copy pins validation to this build and works offline:\n\n" +
			"  draugr schema -o .saga.schema.json\n" +
			"  # then in your Saga:\n" +
			"  # yaml-language-server: $schema=./.saga.schema.json\n\n" +
			"--fragment prints the schema for a Saga fragment instead. A fragment is a different\n" +
			"shape — no release, and no policy — so it has a schema of its own.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			doc := saga.SchemaJSON
			if fragment {
				doc = saga.FragmentSchemaJSON
			}
			if out == "" {
				_, err := cmd.OutOrStdout().Write(doc)
				return err
			}
			if err := os.WriteFile(out, doc, 0o600); err != nil {
				return fmt.Errorf("write schema: %w", err)
			}
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(),
				"wrote %s (draugr %s)\nreference it from a Saga with:\n  # yaml-language-server: $schema=%s\n",
				out, version.Version, schemaRef(out))
			return nil
		},
	}
	cmd.Flags().BoolVar(&fragment, "fragment", false,
		"print the Saga fragment schema instead of the Saga schema")
	cmd.Flags().StringVarP(&out, "output", "o", "", "write the schema to this file instead of stdout")
	return cmd
}

// schemaRef formats a path as the YAML language server expects it: a relative path needs a
// leading "./" to be recognized, an absolute one must not gain one.
func schemaRef(path string) string {
	if filepath.IsAbs(path) || strings.HasPrefix(path, "./") || strings.HasPrefix(path, "../") {
		return path
	}
	return "./" + path
}
