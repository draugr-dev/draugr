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
			"--scan decides whether the assistant may start a scan, and when you are asked first:\n\n" +
			"  --scan=effects  offered; asks before a scan that probes a live host, sends data to\n" +
			"                  a third party, changes something, needs elevated access or\n" +
			"                  delivers results off this machine (default)\n" +
			"  --scan=ask      offered; you approve each call\n" +
			"  --scan=always   offered; runs without asking\n" +
			"  --scan=off      not offered\n\n" +
			"Asking needs a client that can prompt; one that cannot is refused and given the\n" +
			"`draugr scan` command to run instead.\n\n" +
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
	cmd.Flags().StringVar(&scanMode, "scan", string(draugrmcp.ScanEffects),
		"whether the assistant may start scans: effects (ask before one that does more than read), ask (approve each one), always (no prompt), off (not offered)")
	return cmd
}
