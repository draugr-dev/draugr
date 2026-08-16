package cli

import (
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spf13/cobra"

	"github.com/draugr-dev/draugr/internal/builtins"
	draugrmcp "github.com/draugr-dev/draugr/internal/mcp"
)

func newMCPCommand() *cobra.Command {
	var scanMode string

	cmd := &cobra.Command{
		Use:   "mcp",
		Short: "Serve Draugr to AI coding agents over the Model Context Protocol",
		Long: "Serve Draugr over MCP on stdin/stdout, so an AI coding assistant can ask it what\n" +
			"controls exist, how to write a Saga, whether one is valid, and what a scan found.\n\n" +
			"Tools are read-only unless --scan says otherwise. A scan clones repositories, runs\n" +
			"external tools and reaches the network:\n\n" +
			"  --scan=off      not offered (default)\n" +
			"  --scan=ask      offered; you approve each call (needs a client that can prompt)\n" +
			"  --scan=always   offered; runs without asking\n\n" +
			"Every *.saga.yaml nearby is exposed as a resource.\n\n" +
			"Register it with your assistant:\n\n" +
			"  {\n" +
			"    \"mcpServers\": {\n" +
			"      \"draugr\": { \"command\": \"draugr\", \"args\": [\"mcp\"] }\n" +
			"    }\n" +
			"  }\n\n" +
			"Run by hand in a terminal it will look hung. It is waiting for a client.",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			mode, err := draugrmcp.ParseScanMode(scanMode)
			if err != nil {
				return err
			}
			srv, err := draugrmcp.NewServer(draugrmcp.Options{
				Scan:      mode,
				Registry:  builtins.Registry(),
				Surveyors: builtins.SurveyorRegistry(),
			})
			if err != nil {
				return err
			}
			if err := srv.Run(cmd.Context(), &mcp.StdioTransport{}); err != nil {
				return fmt.Errorf("mcp server: %w", err)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&scanMode, "scan", "off",
		"whether the assistant may start scans: off (not offered), ask (approve each one), always (no prompt)")
	return cmd
}
