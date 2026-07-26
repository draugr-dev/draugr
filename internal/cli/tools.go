package cli

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/draugr-dev/draugr/internal/builtins"
	"github.com/draugr-dev/draugr/internal/tools"

	"github.com/draugr-dev/draugr/pkg/tui"
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
	force  bool
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
				return tools.Install(cmd.Context(), name, dir, nil, opts.force)
			}
			return runToolsInstall(cmd.OutOrStdout(), cmd.InOrStdin(), args, *opts, install)
		},
	}
	cmd.Flags().BoolVarP(&opts.yes, "yes", "y", false, "skip the confirmation prompt")
	cmd.Flags().BoolVar(&opts.dryRun, "dry-run", false, "print the install plan and exit")
	cmd.Flags().BoolVar(&opts.force, "force", false,
		"reinstall even when the pinned version is already present (repairs a modified binary)")
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

// checkInstallable reports any names Draugr cannot provision, suggesting the closest match.
func checkInstallable(names []string) error {
	// Accept every tool Draugr knows, not just the binary-installable ones: semgrep is a Python
	// package, so `tools install semgrep` legitimately prints a pipx command instead of
	// downloading anything. Rejecting it here would break that.
	known := tools.Installable()
	set := make(map[string]bool, len(known))
	for _, k := range known {
		set[k] = true
	}
	for _, t := range tools.All() {
		set[t.Binary] = true
	}
	var unknown []string
	for _, n := range names {
		if !set[n] {
			unknown = append(unknown, n)
		}
	}
	if len(unknown) == 0 {
		return nil
	}
	msg := fmt.Sprintf("cannot install %s", strings.Join(quoteAll(unknown), ", "))
	if len(unknown) == 1 {
		if near := closestName(unknown[0], known); near != "" {
			msg += fmt.Sprintf(" — did you mean %q?", near)
		}
	}
	return fmt.Errorf("%s\ninstallable: %s", msg, strings.Join(known, ", "))
}

func quoteAll(names []string) []string {
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = fmt.Sprintf("%q", n)
	}
	return out
}

// closestName returns the known tool within a small edit distance of want, or "" if none is
// close enough to be worth suggesting.
func closestName(want string, known []string) string {
	best, bestDist := "", 3 // suggest only for near-misses
	for _, k := range known {
		if d := editDistance(want, k); d < bestDist {
			best, bestDist = k, d
		}
	}
	return best
}

// editDistance is Levenshtein, enough for "did you mean" on short tool names.
func editDistance(a, b string) int {
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(min(cur[j-1]+1, prev[j]+1), prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[len(b)]
}

func runToolsInstall(w io.Writer, in io.Reader, names []string, opts toolsInstallOptions, install func(name string) (tools.Installed, error)) error {
	all := len(names) == 0
	if all {
		names = tools.Installable()
	}
	// An unknown name is a typo, not a choice. Reject it up front rather than rendering a row of
	// dashes and asking whether to proceed — and fail the whole command, since half-installing
	// after a misspelling is the surprising outcome.
	if err := checkInstallable(names); err != nil {
		return err
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

	col := tui.For(w)
	var failed int
	for _, name := range names {
		if name == "semgrep" {
			printSemgrepHint(w)
			continue
		}
		res, err := install(name)
		if err != nil {
			_, _ = fmt.Fprintf(w, "%s %s: %v\n", col.Paint(tui.StyleFail, "✗"), name, err)
			failed++
			continue
		}
		if res.AlreadyPresent {
			_, _ = fmt.Fprintf(w, "%s %s %s already installed → %s\n",
				col.Paint(tui.StyleMuted, "•"), res.Name, res.Version,
				col.Paint(tui.StyleMuted, res.Path))
			continue
		}
		_, _ = fmt.Fprintf(w, "%s %s %s → %s %s\n", col.Paint(tui.StylePass, "✓"), res.Name, res.Version,
			res.Path, col.Paint(tui.StyleMuted, "("+provenanceLabel(res)+")"))
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
	col := tui.For(w)
	table := tui.NewTable(col, "Tool", "Version", "Category", "Verify", "Destination").Indent("  ")
	showSemgrep := all
	for _, name := range names {
		if name == "semgrep" {
			showSemgrep = true
			continue
		}
		spec, ok := tools.Spec(name)
		if !ok {
			table.Row(tui.Styled(tui.StyleAccent, name), tui.PlainCell("-"),
				tui.PlainCell(category(name)), tui.PlainCell("-"),
				tui.Styled(tui.StyleMuted, "(not installable)"))
			continue
		}
		verify := "sha256"
		if spec.Cosign != nil {
			verify = "sha256 + cosign"
		}
		table.Row(tui.Styled(tui.StyleAccent, name), tui.PlainCell(spec.Version),
			tui.PlainCell(category(name)), tui.PlainCell(verify),
			tui.Styled(tui.StyleMuted, filepath.Join(dir, spec.Binary)))
	}
	if showSemgrep {
		table.Row(tui.Styled(tui.StyleAccent, "semgrep"), tui.PlainCell(tools.SemgrepVersion()),
			tui.PlainCell(category("semgrep")), tui.PlainCell("pypi hash"),
			tui.Styled(tui.StyleMuted, "pipx (command printed)"))
	}
	table.Render(w)
}

// isTTY reports whether r is an interactive terminal — used to decide whether to prompt
// (interactive) or proceed automatically (CI/pipes). A var so tests can force it.
var isTTY = func(r io.Reader) bool { return tui.IsTerminal(r) }

func runToolsList(ctx context.Context, w io.Writer) error {
	// Map each tool binary to the controls it backs (a binary like trivy serves several).
	controlsFor := map[string][]string{}
	for _, s := range builtins.Registry().Scanners() {
		info := s.Info()
		for _, c := range info.Controls {
			controlsFor[info.Binary] = appendUnique(controlsFor[info.Binary], c)
		}
	}

	col := tui.For(w)
	table := tui.NewTable(col, "Tool", "Category", "Controls", "Pinned", "Source", "Status")
	for _, t := range tools.All() {
		category := t.Category
		if category == "" {
			category = "-"
		}
		controls := "-"
		if cs := controlsFor[t.Binary]; len(cs) > 0 {
			sort.Strings(cs)
			controls = strings.Join(cs, ",")
		}
		pinned, source := "-", "system PATH"
		if spec, ok := tools.Spec(t.Binary); ok {
			pinned, source = spec.Version, "draugr tools install"
		} else if t.Binary == "semgrep" {
			pinned, source = tools.SemgrepVersion(), "pipx"
		}

		status, statusStyle := "✗ not found", tui.StyleFail
		if st := tools.Detect(ctx, t, nil, nil); st.Found {
			version := st.Version
			if version == "" {
				version = "?"
			}
			status, statusStyle = fmt.Sprintf("✓ %s (%s)", version, st.Path), tui.StylePass
		}
		table.Row(
			tui.Styled(tui.StyleAccent, t.Binary),
			tui.PlainCell(category),
			tui.PlainCell(controls),
			tui.PlainCell(pinned),
			tui.Styled(tui.StyleMuted, source),
			tui.Styled(statusStyle, status),
		)
	}
	table.Render(w)
	return nil
}

// appendUnique appends s to xs if not already present.
func appendUnique(xs []string, s string) []string {
	for _, x := range xs {
		if x == s {
			return xs
		}
	}
	return append(xs, s)
}
