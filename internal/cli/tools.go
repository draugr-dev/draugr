package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
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

type toolsInstallOptions struct {
	yes    bool
	dryRun bool
}

func newToolsInstallCommand() *cobra.Command {
	opts := &toolsInstallOptions{}
	cmd := &cobra.Command{
		Use:   "install [tool...]",
		Short: "Download pinned, checksum-verified tools into ~/.draugr/bin",
		Long: "Download pinned scanner/utility binaries, verify each against a SHA-256 recorded in\n" +
			"Draugr, and install them into ~/.draugr/bin (which Draugr adds to PATH automatically).\n" +
			"With no arguments, installs every tool Draugr can provision. Prints the plan first;\n" +
			"when run interactively it asks for confirmation. Never downloads without being asked.",
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			dir, err := tools.BinDir()
			if err != nil {
				return err
			}
			install := func(name string) (tools.Installed, error) {
				return tools.Install(cmd.Context(), name, dir, nil)
			}
			return runToolsInstall(cmd.OutOrStdout(), cmd.InOrStdin(), args, *opts, install)
		},
	}
	cmd.Flags().BoolVarP(&opts.yes, "yes", "y", false, "skip the confirmation prompt")
	cmd.Flags().BoolVar(&opts.dryRun, "dry-run", false, "print the install plan and exit")
	return cmd
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
// provenanceLabel summarizes how a provisioned tool was verified: the SHA-256 pin always
// applies; cosign adds signed provenance when the upstream publishes it.
func provenanceLabel(res tools.Installed) string {
	switch {
	case res.SignatureVerified:
		return "sha256 + cosign verified"
	case res.ProvenanceNote != "":
		return "sha256 verified; " + res.ProvenanceNote
	default:
		return "sha256 verified"
	}
}

func runToolsInstall(w io.Writer, in io.Reader, names []string, opts toolsInstallOptions, install func(name string) (tools.Installed, error)) error {
	all := len(names) == 0
	if all {
		names = tools.Installable()
	}

	// Show the plan before doing anything.
	writeInstallPlan(w, names, all)

	if opts.dryRun {
		_, _ = fmt.Fprintln(w, "\n(dry run — nothing installed)")
		return nil
	}
	// Confirm only when interactive (a TTY); non-interactive runs (CI, pipes) proceed so
	// existing automation isn't broken. -y always skips the prompt.
	if !opts.yes && isTTY(in) {
		_, _ = fmt.Fprint(w, "\nProceed? [y/N] ")
		if !confirmed(in) {
			_, _ = fmt.Fprintln(w, "Aborted.")
			return nil
		}
	}
	_, _ = fmt.Fprintln(w)

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
		_, _ = fmt.Fprintf(w, "✓ %s %s → %s (%s)\n", res.Name, res.Version, res.Path, provenanceLabel(res))
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

// writeInstallPlan prints what `tools install` will do, before doing it.
func writeInstallPlan(w io.Writer, names []string, all bool) {
	dir, _ := tools.BinDir()
	catalog := tools.Catalog()
	category := func(name string) string {
		if t, ok := catalog[name]; ok && t.Category != "" {
			return t.Category
		}
		return "-"
	}
	_, _ = fmt.Fprintln(w, "Install plan:")
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "  TOOL\tVERSION\tCATEGORY\tVERIFY\tDESTINATION")
	showSemgrep := all
	for _, name := range names {
		if name == "semgrep" {
			showSemgrep = true
			continue
		}
		spec, ok := tools.Spec(name)
		if !ok {
			_, _ = fmt.Fprintf(tw, "  %s\t-\t%s\t-\t(not installable)\n", name, category(name))
			continue
		}
		verify := "sha256"
		if spec.Cosign != nil {
			verify = "sha256 + cosign"
		}
		_, _ = fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\n", name, spec.Version, category(name), verify, filepath.Join(dir, spec.Binary))
	}
	if showSemgrep {
		_, _ = fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\n", "semgrep", tools.SemgrepVersion(), category("semgrep"), "pypi hash", "pipx (command printed)")
	}
	_ = tw.Flush()
}

// isTTY reports whether r is an interactive terminal — used to decide whether to prompt
// (interactive) or proceed automatically (CI/pipes). A var so tests can force it.
var isTTY = func(r io.Reader) bool {
	f, ok := r.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func runToolsList(ctx context.Context, w io.Writer) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "TOOL\tCATEGORY\tPINNED\tSOURCE\tSTATUS")
	for _, t := range tools.All() {
		category := t.Category
		if category == "" {
			category = "-"
		}
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
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", t.Binary, category, pinned, source, status)
	}
	return tw.Flush()
}
