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
	var fragment, configFile bool
	cmd := &cobra.Command{
		Use:   "schema",
		Short: "Print the JSON Schema this build enforces for a Saga, a fragment or the config file",
		Long: "Print the JSON Schema for draugr.saga.yaml, as embedded in this binary.\n\n" +
			"Editors fetch it from draugr.dev by default, which needs network access and follows\n" +
			"whatever is published. A local copy pins validation to this build and works offline:\n\n" +
			"  draugr schema -o .saga.schema.json\n" +
			"  # then in your Saga:\n" +
			"  # yaml-language-server: $schema=./.saga.schema.json\n\n" +
			"--fragment prints the schema for a Saga fragment instead. A fragment is a different\n" +
			"shape, no release, and no policy, so it has a schema of its own.\n\n" +
			"--config-file prints the schema for draugr.config.yaml instead, which checks what\n" +
			"`draugr config validate` checks, scanner options included.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			doc, file := saga.SchemaJSON, "a Saga"
			switch {
			case fragment:
				doc, file = saga.FragmentSchemaJSON, "a Saga fragment"
			case configFile:
				doc, file = saga.ConfigSchemaJSON, "draugr.config.yaml"
			}
			if out == "" {
				_, err := cmd.OutOrStdout().Write(doc)
				return err
			}
			if err := os.WriteFile(out, doc, 0o600); err != nil {
				return fmt.Errorf("write schema: %w", err)
			}
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(),
				"wrote %s (draugr %s)\nreference it from %s with:\n  # yaml-language-server: $schema=%s\n",
				out, version.Version, file, schemaRef(out))
			return nil
		},
	}
	cmd.Flags().BoolVar(&fragment, "fragment", false,
		"print the Saga fragment schema instead of the Saga schema")
	// Not --config: that is the global flag naming which config file a command reads.
	cmd.Flags().BoolVar(&configFile, "config-file", false,
		"print the draugr.config.yaml schema instead of the Saga schema")
	cmd.MarkFlagsMutuallyExclusive("fragment", "config-file")
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
