package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/draugr-dev/draugr/pkg/config"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/tui"
)

// starterConfig is what `config init` writes.
//
// Commented rather than bare, because the question a reader has when they first see this file is
// not "what are the keys" but "why is this separate from my Saga".
const starterConfig = `# draugr.config.yaml — machine and organisation settings, kept apart from the Saga.
#
# A Saga describes an application. This describes the environment scanning it: which build of a
# scanner to run, and what a control should default to before any project says otherwise. Those
# want to be the same everywhere, which is exactly why they do not belong in a per-app descriptor.
#
# Nothing secret goes here. Use ${{ ENV_VAR }} for anything that is, as a Saga does, so this file
# stays safe to commit.
#
# Precedence, least specific first:
#   ~/.draugr/config.yaml  ->  ./draugr.config.yaml
# and --config / DRAUGR_CONFIG replaces both. See ` + "`draugr config show`" + ` for what is in
# effect and where each value came from.

# Default settings for a control, merged *underneath* the Saga's, so a project overrides only the
# keys it cares about.
controllers: {}
  # sast:
  #   semgrep:
  #     config: p/owasp-top-ten
`

func newConfigCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Inspect and edit Draugr's machine and organisation settings",
		Long: "Read and write draugr.config.yaml — the settings that describe the environment\n" +
			"running a scan rather than the application being scanned.\n\n" +
			"A Saga is a fact about your software and belongs in its repository. Which build of a\n" +
			"scanner runs, and what a control defaults to, are facts about a machine or an\n" +
			"organisation, and want to be the same across every project.",
	}
	cmd.AddCommand(newConfigShowCommand(), newConfigGetCommand(), newConfigSetCommand(),
		newConfigUnsetCommand(), newConfigInitCommand(), newConfigValidateCommand())
	return cmd
}

// configPath resolves which file an edit writes to.
func configPath(global bool) (string, error) {
	if !global {
		wd, err := os.Getwd()
		if err != nil {
			return "", err
		}
		return filepath.Join(wd, config.FileName), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".draugr", "config.yaml"), nil
}

// globalFlag adds --global to an editing command.
func globalFlag(cmd *cobra.Command, target *bool) {
	cmd.Flags().BoolVar(target, "global", false,
		"edit ~/.draugr/config.yaml instead of this project's draugr.config.yaml")
}

func newConfigShowCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "Print the settings in effect and where each came from",
		Long: "Print the resolved configuration, naming the file each value came from.\n\n" +
			"A layered config is undebuggable without this. \"Why is Trivy 0.68?\" has one useful\n" +
			"answer, and it is a filename.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			wd, err := os.Getwd()
			if err != nil {
				return err
			}
			res, err := config.Load(rootConfigPath, wd)
			if err != nil {
				return err
			}
			writeConfigShow(cmd.OutOrStdout(), res)
			return nil
		},
	}
}

// writeConfigShow renders the resolved settings with their provenance.
func writeConfigShow(w io.Writer, res config.Resolved) {
	col := tui.For(w)
	if len(res.Sources) == 0 {
		_, _ = fmt.Fprintln(w, col.Paint(tui.StyleMuted,
			"No configuration found. Draugr's built-in defaults are in effect."))
		_, _ = fmt.Fprintf(w, "\n%s\n", col.Paint(tui.StyleMuted,
			"`draugr config init` writes a starter file here; --global writes it to ~/.draugr."))
		return
	}

	_, _ = fmt.Fprintln(w, col.Paint(tui.StyleAccent, "Files, least specific first:"))
	for _, s := range res.Sources {
		_, _ = fmt.Fprintf(w, "  %s\n", shortHome(s.Path))
	}

	// Provenance is computed by asking which is the *last* source to set a key, which is the one
	// that won — the same rule the merge follows, rather than a second implementation of it.
	rows := map[string]string{}
	for _, s := range res.Sources {
		for _, k := range flatten(s.File) {
			rows[k.key] = s.Path
		}
	}
	keys := flatten(res.File)
	if len(keys) == 0 {
		_, _ = fmt.Fprintf(w, "\n%s\n", col.Paint(tui.StyleMuted, "They set nothing."))
		return
	}
	_, _ = fmt.Fprintln(w, "\n"+col.Paint(tui.StyleAccent, "In effect:"))
	t := tui.NewTable(col, "Setting", "Value", "From").Indent("  ")
	for _, k := range keys {
		t.Row(tui.PlainCell(k.key), tui.PlainCell(k.value),
			tui.Styled(tui.StyleMuted, shortHome(rows[k.key])))
	}
	t.Render(w)
}

// shortHome trims a home path to ~ so the column stays readable.
func shortHome(path string) string {
	if home, err := os.UserHomeDir(); err == nil && strings.HasPrefix(path, home) {
		return "~" + strings.TrimPrefix(path, home)
	}
	return path
}

// kv is one resolved setting.
type kv struct{ key, value string }

// flatten renders a config as dotted key/value pairs, sorted.
func flatten(f config.File) []kv {
	var out []kv
	for name, t := range f.Tools {
		if t.Version != "" {
			out = append(out, kv{"tools." + name + ".version", t.Version})
		}
	}
	for control, settings := range f.Controllers {
		out = append(out, flattenAny("controllers."+control, settings)...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].key < out[j].key })
	return out
}

func flattenAny(prefix string, v any) []kv {
	// Both shapes: YAML decodes a nested mapping as the enclosing named type, so matching only
	// map[string]any prints a whole subtree as one unreadable value — which is what the first
	// version of this did.
	var m map[string]any
	switch t := v.(type) {
	case saga.ControllerSettings:
		m = t
	case map[string]any:
		m = t
	default:
		return []kv{{prefix, fmt.Sprintf("%v", v)}}
	}
	var out []kv
	for k, sub := range m {
		out = append(out, flattenAny(prefix+"."+k, sub)...)
	}
	return out
}

func newConfigGetCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "get <key>",
		Short: "Print one setting's value, as resolved",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			wd, err := os.Getwd()
			if err != nil {
				return err
			}
			res, err := config.Load(rootConfigPath, wd)
			if err != nil {
				return err
			}
			for _, k := range flatten(res.File) {
				if k.key == args[0] {
					_, _ = fmt.Fprintln(cmd.OutOrStdout(), k.value)
					return nil
				}
			}
			return fmt.Errorf("%q is not set (see `draugr config show`)", args[0])
		},
	}
}

func newConfigSetCommand() *cobra.Command {
	var global bool
	cmd := &cobra.Command{
		Use:   "set <key> <value>",
		Short: "Set a value, keeping the file valid and its comments intact",
		Long: "Write key=value into a config file, given as a dotted path.\n\n" +
			"The file is edited as a document rather than rewritten, so comments survive. The\n" +
			"result is parsed before it is saved, so this command cannot leave a file Draugr\n" +
			"will refuse to load.",
		Example: "  draugr config set controllers.sast.semgrep.config p/owasp-top-ten\n" +
			"  draugr config set --global tools.trivy.version 0.69.3",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return editConfig(cmd.OutOrStdout(), global, func(doc []byte) ([]byte, error) {
				return config.Set(doc, args[0], args[1])
			})
		},
	}
	globalFlag(cmd, &global)
	return cmd
}

func newConfigUnsetCommand() *cobra.Command {
	var global bool
	cmd := &cobra.Command{
		Use:   "unset <key>",
		Short: "Remove a setting, pruning anything it leaves empty",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return editConfig(cmd.OutOrStdout(), global, func(doc []byte) ([]byte, error) {
				return config.Unset(doc, args[0])
			})
		},
	}
	globalFlag(cmd, &global)
	return cmd
}

// editConfig applies an edit and writes it back, refusing to save anything Draugr cannot load.
//
// That check is what makes these commands a recovery path rather than another way to break the
// file: whatever they write, `draugr scan` will accept.
func editConfig(w io.Writer, global bool, apply func([]byte) ([]byte, error)) error {
	path, err := configPath(global)
	if err != nil {
		return err
	}
	doc, err := os.ReadFile(path) //nolint:gosec // a path this command owns
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	out, err := apply(doc)
	if err != nil {
		return err
	}
	if _, err := config.Parse(out, path); err != nil {
		return fmt.Errorf("that edit would produce a file Draugr cannot load, so nothing was "+
			"written:\n  %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		return err
	}
	// Which file, always. With two possible destinations, a silent success is a guess.
	_, _ = fmt.Fprintf(w, "wrote %s\n", shortHome(path))
	return nil
}

func newConfigInitCommand() *cobra.Command {
	var global, force bool
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Write a starter config, or reset a broken one",
		Long: "Write a commented starter configuration.\n\n" +
			"With --force this is the way back from a file that no longer loads: it replaces it\n" +
			"with one that does. Draugr will not repair a file it cannot parse — rewriting\n" +
			"somebody's settings on a guess is worse than refusing them — so this is deliberate\n" +
			"and it is one command.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			path, err := configPath(global)
			if err != nil {
				return err
			}
			if _, err := os.Stat(path); err == nil && !force {
				return fmt.Errorf("%s already exists; pass --force to replace it with the "+
					"built-in defaults", shortHome(path))
			}
			if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
				return err
			}
			if err := os.WriteFile(path, []byte(starterConfig), 0o600); err != nil {
				return err
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n", shortHome(path))
			return nil
		},
	}
	globalFlag(cmd, &global)
	cmd.Flags().BoolVar(&force, "force", false, "replace an existing file")
	return cmd
}

func newConfigValidateCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "validate [path...]",
		Short: "Check that the config files load",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			w := cmd.OutOrStdout()
			col := tui.For(w)
			paths := args
			if len(paths) == 0 {
				wd, err := os.Getwd()
				if err != nil {
					return err
				}
				res, err := config.Load(rootConfigPath, wd)
				if err != nil {
					return err
				}
				for _, s := range res.Sources {
					paths = append(paths, s.Path)
				}
				if len(paths) == 0 {
					_, _ = fmt.Fprintln(w, col.Paint(tui.StyleMuted,
						"No configuration found — nothing to check."))
					return nil
				}
			}
			for _, p := range paths {
				data, err := os.ReadFile(p) //nolint:gosec // operator-provided path
				if err != nil {
					return err
				}
				if _, err := config.Parse(data, p); err != nil {
					return err
				}
				_, _ = fmt.Fprintf(w, "%s %s\n", col.Paint(tui.StylePass, "✓"), shortHome(p))
			}
			return nil
		},
	}
}
