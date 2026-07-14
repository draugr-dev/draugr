package cli

import (
	"context"
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/draugr-dev/draugr/internal/tools"
)

func newToolsCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tools",
		Short: "Manage the external scanner tools Draugr uses",
		Long: "Provision and inspect the external scanners (trivy, gitleaks, …) Draugr runs.\n" +
			"Installs are opt-in and checksum-verified — nothing is ever downloaded during a scan.",
	}
	cmd.AddCommand(newToolsInstallCommand())
	cmd.AddCommand(newToolsListCommand())
	return cmd
}

func newToolsInstallCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "install [tool...]",
		Short: "Download pinned, checksum-verified scanners into ~/.draugr/bin",
		Long: "Download pinned scanner binaries, verify each against a SHA-256 recorded in Draugr,\n" +
			"and install them into ~/.draugr/bin (which Draugr adds to PATH automatically). With no\n" +
			"arguments, installs every tool Draugr can provision. Never downloads without being asked.",
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			dir, err := tools.BinDir()
			if err != nil {
				return err
			}
			install := func(name string) (tools.Installed, error) {
				return tools.Install(cmd.Context(), name, dir, nil)
			}
			return runToolsInstall(cmd.OutOrStdout(), args, install)
		},
	}
}

func newToolsListCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List the scanner tools Draugr knows about and their install status",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runToolsList(cmd.Context(), cmd.OutOrStdout())
		},
	}
}

// runToolsInstall provisions the named tools (all installable ones when names is empty) via
// install, which is injectable for tests. Returns an error if any install fails, after
// attempting them all.
func runToolsInstall(w io.Writer, names []string, install func(name string) (tools.Installed, error)) error {
	all := len(names) == 0
	if all {
		names = tools.Installable()
	}

	var failed int
	for _, name := range names {
		if name == "semgrep" {
			printSemgrepHint(w)
			continue
		}
		res, err := install(name)
		if err != nil {
			_, _ = fmt.Fprintf(w, "✗ %s: %v\n", name, err)
			failed++
			continue
		}
		_, _ = fmt.Fprintf(w, "✓ %s %s → %s (sha256 ok)\n", res.Name, res.Version, res.Path)
	}

	// Semgrep isn't a downloadable binary; when installing everything, surface how to get it.
	if all {
		printSemgrepHint(w)
	}

	if failed > 0 {
		return fmt.Errorf("%d tool(s) failed to install", failed)
	}
	return nil
}

func printSemgrepHint(w io.Writer) {
	_, _ = fmt.Fprintf(w, "ℹ semgrep is a Python package, not a standalone binary — run:\n    %s\n",
		tools.SemgrepPipxCommand())
}

func runToolsList(ctx context.Context, w io.Writer) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "TOOL\tPINNED\tSOURCE\tSTATUS")
	for _, t := range tools.All() {
		pinned, source := "-", "system PATH"
		if spec, ok := tools.Spec(t.Binary); ok {
			pinned, source = spec.Version, "draugr tools install"
		} else if t.Binary == "semgrep" {
			pinned, source = tools.SemgrepVersion(), "pipx"
		}

		status := "✗ not found"
		if st := tools.Detect(ctx, t, nil, nil); st.Found {
			version := st.Version
			if version == "" {
				version = "?"
			}
			status = fmt.Sprintf("✓ %s (%s)", version, st.Path)
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", t.Binary, pinned, source, status)
	}
	return tw.Flush()
}
