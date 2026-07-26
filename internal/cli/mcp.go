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
			"Without this, an assistant asked \"is this safe to ship?\" improvises: it runs whatever\n" +
			"scanner it can find over a scope it invented, and reads the raw output. That answer has\n" +
			"no relationship to the one your pipeline will give. Pointing it at Draugr makes them the\n" +
			"same answer — same descriptor, same controls, same priorities.\n\n" +
			"The tools are read-only by default. Scanning clones repositories, runs external tools\n" +
			"and reaches the network, so it is offered only when you say so:\n\n" +
			"  --scan=off      not offered at all (default)\n" +
			"  --scan=ask      offered, and you approve each call — needs a client that can prompt\n" +
			"  --scan=always   offered, and runs without asking\n\n" +
			"Draugr also exposes every *.saga.yaml it finds nearby as a resource, so an assistant\n" +
			"can read the descriptor without being told where it is.\n\n" +
			"Register it with your assistant (most clients use this shape):\n\n" +
			"  {\n" +
			"    \"mcpServers\": {\n" +
			"      \"draugr\": { \"command\": \"draugr\", \"args\": [\"mcp\"] }\n" +
			"    }\n" +
			"  }\n\n" +
			"The server speaks MCP, not text — running it in a terminal by hand will look like it\n" +
			"has hung. It's waiting for a client.",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			mode, err := draugrmcp.ParseScanMode(scanMode)
			if err != nil {
				return err
			}
			srv, err := draugrmcp.NewServer(draugrmcp.Options{
				Scan:     mode,
				Registry: builtins.Registry(),
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
