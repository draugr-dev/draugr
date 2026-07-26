package cli

import (
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spf13/cobra"

	"github.com/draugr-dev/draugr/internal/builtins"
	draugrmcp "github.com/draugr-dev/draugr/internal/mcp"
)

func newMCPCommand() *cobra.Command {
	var allowScan bool

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
			"and reaches the network, so it is exposed only with --allow-scan.\n\n" +
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
			srv, err := draugrmcp.NewServer(draugrmcp.Options{
				AllowScan: allowScan,
				Registry:  builtins.Registry(),
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
	cmd.Flags().BoolVar(&allowScan, "allow-scan", false,
		"expose the scan tool, letting the assistant start scans (clones repos, runs scanners, uses the network)")
	return cmd
}
