package cli

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/draugr-dev/draugr/internal/builtins"
	"github.com/draugr-dev/draugr/pkg/engine"
)

func newControlsCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "controls",
		Short: "List the security controls Draugr can run, their purpose, and scanners",
		Long: "List every security control Draugr can run — what it checks, its scope, and which\n" +
			"scanner(s) implement it (default, plus any opt-in alternatives). Enable a control in\n" +
			"your Saga under config.controllers.<name> (or per component).",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runControls(cmd.OutOrStdout(), builtins.Registry())
		},
	}
}

func runControls(w io.Writer, reg *engine.Registry) error {
	// Which scanners serve each control (by scanner name).
	serving := map[string][]string{}
	for _, s := range reg.Scanners() {
		info := s.Info()
		for _, c := range info.Controls {
			serving[c] = append(serving[c], info.Name)
		}
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "CONTROL\tSCOPE\tSCANNERS\tPURPOSE")
	optIn := false
	for _, ctrl := range reg.Controllers() {
		info := ctrl.Info()
		isDefault := map[string]bool{}
		names := make([]string, 0, len(serving[info.Name]))
		for _, d := range info.DefaultScanners {
			isDefault[d] = true
			names = append(names, d)
		}
		// Append any registered scanners for this control that aren't defaults, marked opt-in.
		for _, s := range serving[info.Name] {
			if !isDefault[s] {
				names = append(names, s+"*")
				optIn = true
			}
		}
		scanners := strings.Join(names, ", ")
		if scanners == "" {
			scanners = "-"
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", info.Name, info.Scope, scanners, info.Summary)
	}
	_ = tw.Flush()

	if optIn {
		_, _ = fmt.Fprintln(w, "\n* opt-in scanner — enable via controllers.<control>.scanners in the Saga.")
	}
	_, _ = fmt.Fprintln(w, "\nEnable a control under config.controllers.<name> (or per component) in your Saga.")
	return nil
}
