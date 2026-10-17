package cli

import (
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/draugr-dev/draugr/internal/english"
	"github.com/draugr-dev/draugr/internal/tools"
	"github.com/draugr-dev/draugr/pkg/tui"
)

type toolsUninstallOptions struct {
	yes    bool
	dryRun bool
	all    bool
	caches bool
}

func newToolsUninstallCommand() *cobra.Command {
	opts := &toolsUninstallOptions{}
	cmd := &cobra.Command{
		Use:   "uninstall [tool...]",
		Short: "Remove tools `draugr tools install` put in ~/.draugr",
		Long: "Remove the named tools, or with --all every tool Draugr installed, from ~/.draugr: the\n" +
			"binary, its Python or Node environment, and the data Draugr keeps for it. A copy of a\n" +
			"tool installed any other way is left alone. Each tool's own cache, such as Trivy's\n" +
			"database, stays unless --caches is given. Prints the plan first; when run\n" +
			"interactively it asks for confirmation.",
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			dir, err := tools.BinDir()
			if err != nil {
				return err
			}
			return runToolsUninstall(cmd.OutOrStdout(), cmd.InOrStdin(), dir, args, *opts)
		},
	}
	cmd.Flags().BoolVarP(&opts.yes, "yes", "y", false, "skip the confirmation prompt")
	cmd.Flags().BoolVar(&opts.dryRun, "dry-run", false, "print the plan and exit")
	cmd.Flags().BoolVar(&opts.all, "all", false, "remove every tool Draugr installed")
	cmd.Flags().BoolVar(&opts.caches, "caches", false,
		"also remove each tool's own cache, such as Trivy's and Grype's vulnerability databases")
	return cmd
}

// uninstallLookPath finds a tool on PATH, to say where a copy Draugr did not install lives. A var
// so tests can stand one in.
var uninstallLookPath = exec.LookPath

func runToolsUninstall(w io.Writer, in io.Reader, dir string, args []string, opts toolsUninstallOptions) error {
	if opts.all && len(args) > 0 {
		return fmt.Errorf("--all and an explicit tool list ask for different things: one removes every "+
			"tool Draugr installed, the other removes %s. Pick one", strings.Join(quoteAll(args), ", "))
	}
	if !opts.all && len(args) == 0 {
		return fmt.Errorf("name the tools to remove, or pass --all for every tool Draugr installed")
	}
	names := args
	if opts.all {
		names = tools.Uninstallable(dir)
	} else if err := checkUninstallable(names); err != nil {
		return err
	}

	col := tui.For(w)
	var plans []tools.Removal
	missing := 0
	for _, name := range names {
		r, ok := tools.PlanUninstall(dir, name)
		if !ok {
			missing++
			msg := name + ": not installed by Draugr"
			if path, err := uninstallLookPath(name); err == nil {
				msg += fmt.Sprintf(" (found at %s). Remove it the way it was installed", path)
			}
			_, _ = fmt.Fprintf(w, "%s %s.\n", col.Paint(tui.StyleFail, "✗"), msg)
			continue
		}
		plans = append(plans, r)
	}
	if len(plans) == 0 {
		if opts.all {
			_, _ = fmt.Fprintf(w, "Nothing to uninstall: Draugr has installed no tools in %s.\n", dir)
			return nil
		}
		return fmt.Errorf("%s not removed", english.Count(missing, "tool"))
	}
	if missing > 0 {
		_, _ = fmt.Fprintln(w)
	}

	freed := writeUninstallPlan(w, filepath.Dir(dir), plans, opts.caches)
	if opts.dryRun {
		_, _ = fmt.Fprintln(w, "\n(dry run, nothing removed)")
		return nil
	}
	if !opts.yes && isTTY(in) {
		_, _ = fmt.Fprint(w, "\nProceed? [y/N] ")
		if !confirmed(in) {
			_, _ = fmt.Fprintln(w, "Aborted.")
			return nil
		}
	} else {
		_, _ = fmt.Fprintln(w)
	}

	failed := 0
	for _, r := range plans {
		if err := tools.Uninstall(dir, r, opts.caches); err != nil {
			_, _ = fmt.Fprintf(w, "%s %s: %v\n", col.Paint(tui.StyleFail, "✗"), r.Name, err)
			failed++
			freed -= r.Size()
			if opts.caches {
				freed -= r.CacheSize()
			}
			continue
		}
		_, _ = fmt.Fprintf(w, "%s %s removed\n", col.Paint(tui.StylePass, "✓"),
			strings.TrimSpace(r.Name+" "+r.Version))
	}
	_, _ = fmt.Fprintf(w, "\n%s freed.\n", humanSize(freed))
	if n := failed + missing; n > 0 {
		return fmt.Errorf("%s not removed", english.Count(n, "tool"))
	}
	return nil
}

// writeUninstallPlan prints what will be removed and returns how much space that frees.
func writeUninstallPlan(w io.Writer, root string, plans []tools.Removal, withCaches bool) int64 {
	col := tui.For(w)
	_, _ = fmt.Fprintln(w, col.Paint(tui.StyleMuted, "PLAN"))
	table := tui.NewTable(col, "Tool", "Version", "Size", "Also removes").Indent("  ")
	var size, cacheSize int64
	var caches []string
	for _, r := range plans {
		var also []string
		for _, p := range r.Files {
			switch p.Kind {
			case tools.KindPythonEnv, tools.KindNodeEnv:
				also = append(also, p.Kind)
			case tools.KindData:
				also = append(also, "data "+humanSize(p.Size))
			}
		}
		version := r.Version
		if version == "" {
			version = "-"
		}
		table.Row(tui.Styled(tui.StyleAccent, r.Name), tui.PlainCell(version),
			tui.PlainCell(humanSize(r.Size())), tui.PlainCell(strings.Join(also, ", ")))
		size += r.Size()
		if len(r.Caches) > 0 {
			cacheSize += r.CacheSize()
			caches = append(caches, r.Name+" "+humanSize(r.CacheSize()))
		}
	}
	table.Render(w)

	_, _ = fmt.Fprintf(w, "\n%s to remove from %s, %s.\n", english.Count(len(plans), "tool"), root, humanSize(size))
	if len(caches) == 0 {
		return size
	}
	if withCaches {
		_, _ = fmt.Fprintf(w, "The tools' own caches go too (%s).\n", strings.Join(caches, ", "))
		return size + cacheSize
	}
	_, _ = fmt.Fprintf(w, "The tools' own caches stay (%s). `--caches` removes them too.\n", strings.Join(caches, ", "))
	return size
}

// checkUninstallable rejects a name that is no tool Draugr knows, the way install does, so a typo
// is not reported as a tool somebody else installed.
func checkUninstallable(names []string) error {
	known := map[string]bool{}
	for _, k := range tools.Installable() {
		known[k] = true
	}
	for _, t := range tools.All() {
		known[t.Binary] = true
	}
	var unknown []string
	for _, n := range names {
		if !known[n] {
			unknown = append(unknown, n)
		}
	}
	if len(unknown) == 0 {
		return nil
	}
	msg := fmt.Sprintf("cannot uninstall %s, which is not a tool Draugr knows", strings.Join(quoteAll(unknown), ", "))
	if len(unknown) == 1 {
		if near := closestName(unknown[0], tools.Installable()); near != "" {
			msg += fmt.Sprintf("; did you mean %q?", near)
		}
	}
	return fmt.Errorf("%s", msg)
}

// humanSize writes a byte count the way `du -h` does: one decimal below ten, none above.
func humanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	v, suffix := float64(n), ""
	for _, s := range []string{"K", "M", "G", "T"} {
		v /= unit
		suffix = s
		if v < unit {
			break
		}
	}
	if v < 10 {
		return fmt.Sprintf("%.1f%s", v, suffix)
	}
	return fmt.Sprintf("%.0f%s", v, suffix)
}
