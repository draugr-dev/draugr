package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/draugr-dev/draugr/internal/builtins"
	"github.com/draugr-dev/draugr/internal/english"
	"github.com/draugr-dev/draugr/internal/feeds"
	"github.com/draugr-dev/draugr/pkg/config"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/tui"
)

// starterConfig is what `config init` writes.
//
// Commented rather than bare, because the question a reader has when they first see this file is
// not "what are the keys" but "why is this separate from my Saga".
const starterConfig = `# draugr.config.yaml, machine and organization settings, kept apart from the Saga.
#
# A Saga describes an application. This describes the environment scanning it: which build of a
# scanner to run, and what a control should default to before any project says otherwise. Those
# want to be the same everywhere, which is exactly why they do not belong in a per-app descriptor.
#
# Nothing secret goes here: the file is read as written, with no ${{ ENV_VAR }} substitution.
# Credentials go in environment variables.
#
# Precedence, least specific first:
#   ~/.draugr/config.yaml  ->  ./draugr.config.yaml
# and --config / DRAUGR_CONFIG replaces both, for reading and for draugr config set.
# ` + "`draugr config show`" + ` lists what is in effect and where each value came from.

# Default settings for a control, merged *underneath* the Saga's config.controls, so a project
# overrides only the keys it cares about. For example:
#
#   controls:
#     sast:
#       semgrep:
#         config: p/owasp-top-ten
controls: {}

# Where runs are delivered, for the whole organization rather than per project.
#
# $DRAUGR_API_URL overrides it for one pipeline. Read from ~/.draugr/config.yaml or the file
# DRAUGR_CONFIG names, it is where the draugr-api publisher sends its token. Read from a project's
# draugr.config.yaml, which changes by pull request, it is held to the rule for a url: in a Saga,
# used only on that server's origin or one $DRAUGR_API_ORIGINS lists. No token here. This file is
# committed, and a credential in it is a credential in somebody's git history. For example:
#
#   publish:
#     apiUrl: https://draugr.acme.example
publish: {}
`

func newConfigCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Inspect and edit Draugr's machine and organization settings",
		Long: "Read and write draugr.config.yaml, the settings for the environment running a scan:\n" +
			"scanner versions, control defaults, cache, output, parallelism, logging, offline and\n" +
			"the publish URL.\n\n" +
			"Files, least specific first:\n" +
			"  ~/.draugr/config.yaml   this machine\n" +
			"  ./draugr.config.yaml    this project, read from the working directory only\n" +
			"--config <path> or " + config.EnvVar + " names one file, read alone in place of both.\n\n" +
			"`draugr config show` prints the settings in effect and the file each came from.\n" +
			"Every key is listed at " + config.KeysURL,
	}
	cmd.AddCommand(newConfigShowCommand(), newConfigGetCommand(), newConfigSetCommand(),
		newConfigUnsetCommand(), newConfigInitCommand(), newConfigValidateCommand())
	return cmd
}

// configPath resolves which file an edit writes to: the one a scan would read.
//
// `--config` and DRAUGR_CONFIG name a file that is read alone, so an edit goes there. --global with
// either is refused rather than obeyed, because ~/.draugr/config.yaml is not read while they are set
// and a write to it would be a setting that does nothing.
func configPath(global bool) (string, error) {
	if explicit := config.Explicit(rootConfigPath); explicit != "" {
		if global {
			return "", fmt.Errorf("--global edits ~/.draugr/config.yaml, which is not read while "+
				"%s is set to %s. Drop --global to edit %s, or drop %s to edit the global file",
				explicitSource(), explicit, explicit, explicitSource())
		}
		return explicit, nil
	}
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

// explicitSource names what set the explicit config path, for a message about it.
func explicitSource() string {
	if rootConfigPath != "" {
		return "--config"
	}
	return config.EnvVar
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
		Long:  "Print the resolved configuration, naming the file each value came from.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			wd, err := os.Getwd()
			if err != nil {
				return err
			}
			res, err := loadConfig(wd)
			if err != nil {
				return err
			}
			writeConfigShow(cmd.OutOrStdout(), res, wd)
			return nil
		},
	}
}

// writeConfigShow renders the resolved settings with their provenance. wd is the directory the
// project file is looked for in, named when there is none there.
func writeConfigShow(w io.Writer, res config.Resolved, wd string) {
	col := tui.For(w)
	// The project file is read from the working directory and nowhere else, so a command run from a
	// parent directory reads none. Said whenever it happens, because the listing alone cannot show
	// a file that was never read.
	noProject := ""
	if config.Explicit(rootConfigPath) == "" && !readFrom(res, config.ProjectFile(wd)) {
		noProject = fmt.Sprintf("No %s in %s (the working directory).", config.FileName, shortHome(wd))
	}
	if len(res.Sources) == 0 {
		_, _ = fmt.Fprintln(w, col.Paint(tui.StyleMuted,
			"No configuration found. Draugr's built-in defaults are in effect."))
		if noProject != "" {
			_, _ = fmt.Fprintln(w, col.Paint(tui.StyleMuted, noProject))
		}
		_, _ = fmt.Fprintf(w, "\n%s\n", col.Paint(tui.StyleMuted,
			"`draugr config init` writes a starter file here; --global writes it to ~/.draugr."))
		return
	}

	_, _ = fmt.Fprintln(w, col.Paint(tui.StyleAccent, "Files, least specific first:"))
	for _, s := range res.Sources {
		_, _ = fmt.Fprintf(w, "  %s\n", displayPath(s.Path, wd))
	}
	// A file that exists and is not read is the answer to "why is my setting not in effect", and
	// the list above cannot show it.
	if skipped := skippedFiles(res, wd); len(skipped) > 0 {
		_, _ = fmt.Fprintf(w, "\n%s\n", col.Paint(tui.StyleAccent,
			fmt.Sprintf("Skipped while %s is set:", explicitSource())))
		for _, p := range skipped {
			_, _ = fmt.Fprintf(w, "  %s\n", displayPath(p, wd))
		}
	}
	if noProject != "" {
		_, _ = fmt.Fprintf(w, "\n%s\n", col.Paint(tui.StyleMuted, noProject))
	}

	// Provenance is computed by asking which is the *last* source to set a key, which is the one
	// that won, the same rule the merge follows, rather than a second implementation of it. A
	// one-way setting a later file turned off is the exception, and Overrides names the file that
	// kept it.
	rows := map[string]string{}
	for _, s := range res.Sources {
		for _, k := range flatten(s.File) {
			rows[k.key] = s.Path
		}
	}
	overrides := res.Overrides()
	for _, o := range overrides {
		rows[o.Key] = o.By
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
			tui.Styled(tui.StyleMuted, displayPath(rows[k.key], wd)))
	}
	t.Render(w)

	if len(overrides) == 0 {
		return
	}
	_, _ = fmt.Fprintln(w, "\n"+col.Paint(tui.StyleAccent, "Overridden:"))
	t = tui.NewTable(col, "Setting", "Value", "From", "Overridden by").Indent("  ")
	for _, o := range overrides {
		t.Row(tui.PlainCell(o.Key), tui.PlainCell("false"),
			tui.Styled(tui.StyleMuted, displayPath(o.Path, wd)), tui.Styled(tui.StyleMuted, displayPath(o.By, wd)))
	}
	t.Render(w)
	_, _ = fmt.Fprintf(w, "\n%s\n", col.Paint(tui.StyleMuted, oneWayRule))
}

// oneWayRule states how the one-way settings layer, under a table of overrides. Built from the list
// the merge reads, so a setting added to it is named here too.
var oneWayRule = english.And(config.OneWayKeys()) + " only turn on across files."

// skippedFiles lists the discovered files that exist and are not read, because --config or
// DRAUGR_CONFIG names the one file that is.
func skippedFiles(res config.Resolved, wd string) []string {
	explicit := config.Explicit(rootConfigPath)
	if explicit == "" {
		return nil
	}
	var out []string
	for _, p := range config.Discovered(wd) {
		if !readFrom(res, p) && !samePath(p, explicit) {
			out = append(out, p)
		}
	}
	return out
}

// samePath reports whether two paths name one file, either of them relative to the working
// directory.
func samePath(a, b string) bool {
	absA, errA := filepath.Abs(a)
	absB, errB := filepath.Abs(b)
	return errA == nil && errB == nil && absA == absB
}

// displayPath is how the config commands name a file: relative to wd, as ./draugr.config.yaml,
// when it is under wd, and otherwise under ~ when it is in the home directory, so a column of
// sources stays narrow and a path the reader is standing in reads as one.
func displayPath(path, wd string) string {
	abs, err := filepath.Abs(path)
	if err == nil && wd != "" {
		rel, err := filepath.Rel(wd, abs)
		if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return "." + string(filepath.Separator) + rel
		}
	}
	return shortHome(path)
}

// herePath is displayPath from the working directory.
func herePath(path string) string {
	wd, err := os.Getwd()
	if err != nil {
		return shortHome(path)
	}
	return displayPath(path, wd)
}

// readFrom reports whether path is one of the files res was read from.
func readFrom(res config.Resolved, path string) bool {
	for _, s := range res.Sources {
		if s.Path == path {
			return true
		}
	}
	return false
}

// shortHome trims a home path to ~ so the column stays readable.
func shortHome(path string) string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return path
	}
	if path == home || strings.HasPrefix(path, home+string(filepath.Separator)) {
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
	// Only what was actually set. A zero field here is the absence of a setting, not a setting
	// whose value is zero, and printing `cache.ttl 0s` beside a file that never mentions caching
	// would invite someone to wonder why their cache expires immediately.
	//
	// Every field of the config has to be reachable from here, though. This is the command that
	// answers "why is my setting not taking effect", and one it cannot see reports that the file
	// sets nothing, which sends somebody looking everywhere except at the one place that would have
	// told them. TestConfigShowReachesEveryField holds it to that.
	if c := f.Cache; c != (config.CacheSettings{}) {
		if c.Dir != "" {
			out = append(out, kv{"cache.dir", c.Dir})
		}
		if c.TTL != nil {
			out = append(out, kv{"cache.ttl", feeds.ShortDuration(*c.TTL)})
		}
		if c.ReadOnly != nil {
			out = append(out, kv{"cache.readOnly", strconv.FormatBool(*c.ReadOnly)})
		}
		if c.RequireDigest != nil {
			out = append(out, kv{"cache.requireDigest", strconv.FormatBool(*c.RequireDigest)})
		}
	}
	if pb := f.Publish; pb != (config.PublishSettings{}) {
		if pb.APIURL != "" {
			out = append(out, kv{"publish.apiUrl", pb.APIURL})
		}
	}
	if o := f.Output; o != (config.OutputSettings{}) {
		if o.View != "" {
			out = append(out, kv{"output.view", o.View})
		}
		if o.Evidence != nil {
			out = append(out, kv{"output.evidence", strconv.FormatBool(*o.Evidence)})
		}
		if o.Top != 0 {
			out = append(out, kv{"output.top", strconv.Itoa(o.Top)})
		}
		if o.OfferInstall != nil {
			out = append(out, kv{"output.offerInstall", strconv.FormatBool(*o.OfferInstall)})
		}
		if o.Tips != nil {
			out = append(out, kv{"output.tips", strconv.FormatBool(*o.Tips)})
		}
	}
	if j := f.Scan.Jobs; j != nil {
		out = append(out, kv{"scan.jobs", strconv.Itoa(*j)})
	}
	if l := f.Log; l != (config.LogSettings{}) {
		if l.Level != "" {
			out = append(out, kv{"log.level", l.Level})
		}
		if l.Format != "" {
			out = append(out, kv{"log.format", l.Format})
		}
	}
	if f.Offline != nil {
		out = append(out, kv{"offline", strconv.FormatBool(*f.Offline)})
	}
	for control, settings := range f.Controls {
		out = append(out, flattenAny("controls."+control, settings)...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].key < out[j].key })
	return out
}

func flattenAny(prefix string, v any) []kv {
	// Both shapes: YAML decodes a nested mapping as the enclosing named type, so matching only
	// map[string]any prints a whole subtree as one unreadable value. Which is what the first
	// version of this did.
	var m map[string]any
	switch t := v.(type) {
	case saga.ControllerSettings:
		m = t
	case map[string]any:
		m = t
	case []any:
		// Written as `config set` takes it, so a value read here can be typed back.
		items := make([]string, len(t))
		for i, item := range t {
			items[i] = fmt.Sprintf("%v", item)
		}
		return []kv{{prefix, "[" + strings.Join(items, ", ") + "]"}}
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
			res, err := loadConfig(wd)
			if err != nil {
				return err
			}
			key := config.CurrentKey(args[0])
			for _, k := range flatten(res.File) {
				if k.key == key {
					_, _ = fmt.Fprintln(cmd.OutOrStdout(), k.value)
					return nil
				}
			}
			// A key nobody set and a key that does not exist are different answers. The first is a
			// choice and the second is a typo, and somebody who has just mistyped a setting is the
			// reader least able to tell.
			if !isSetting(args[0]) {
				return unknownSetting(args[0])
			}
			return fmt.Errorf("%q is not set (see `draugr config show`)", args[0])
		},
	}
}

// unknownSetting is the error for a dotted key the file cannot hold.
func unknownSetting(key string) error {
	return fmt.Errorf("%q is not a setting Draugr has. `draugr config show` lists "+
		"what is set; every key is listed at %s", key, config.KeysURL)
}

func newConfigSetCommand() *cobra.Command {
	var global bool
	cmd := &cobra.Command{
		Use:   "set <key> <value>",
		Short: "Set a value, keeping the file valid and its comments intact",
		Long: "Write a value into a config file at a dotted key.\n\n" +
			"A value starting with [ or { is a YAML flow list or mapping, such as [library, os].\n" +
			"Any other value is one string, number or boolean, written as typed. Quote a flow\n" +
			"value for the shell, as in the second example.\n\n" +
			"Comments are preserved. The result is parsed before it is saved, so this never\n" +
			"leaves a file Draugr cannot load.",
		Example: "  draugr config set controls.sast.semgrep.config p/owasp-top-ten\n" +
			"  draugr config set controls.sca.trivyFs.pkgTypes '[library, os]'\n" +
			"  draugr config set --global tools.trivy.version 0.69.3",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			w := cmd.OutOrStdout()
			if err := editConfig(w, global, func(doc []byte) ([]byte, error) {
				return config.Set(doc, args[0], args[1])
			}); err != nil {
				return err
			}
			path, err := configPath(global)
			if err != nil {
				return err
			}
			writeOverridden(w, path, args[0])
			return nil
		},
	}
	globalFlag(cmd, &global)
	return cmd
}

// writeOverridden says so when the value just written to path does not take effect because a less
// specific file outranks it, which `wrote` alone would leave the reader to discover.
func writeOverridden(w io.Writer, path, key string) {
	wd, err := os.Getwd()
	if err != nil {
		return
	}
	// A file that fails to load is reported by the next command that reads it; the write itself
	// succeeded, and this notice is about precedence only.
	res, err := config.Load(rootConfigPath, wd)
	if err != nil {
		return
	}
	for _, o := range res.Overrides() {
		if o.Key == key && o.Path == path {
			_, _ = fmt.Fprintf(w, "overridden: %s stays true; %s sets it\n", key, displayPath(o.By, wd))
		}
	}
}

func newConfigUnsetCommand() *cobra.Command {
	var global bool
	cmd := &cobra.Command{
		Use:   "unset <key>",
		Short: "Remove a setting, pruning anything it leaves empty",
		Long: "Remove a setting from a config file, pruning anything it leaves empty.\n\n" +
			"A key the file does not set is refused, and nothing is written.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := configPath(global)
			if err != nil {
				return err
			}
			return editConfig(cmd.OutOrStdout(), global, func(doc []byte) ([]byte, error) {
				out, err := config.Unset(doc, args[0])
				var notSet *config.NotSetError
				if !errors.As(err, &notSet) {
					return out, err
				}
				if !isSetting(args[0]) {
					return nil, unknownSetting(args[0])
				}
				return nil, fmt.Errorf("%q is not set in %s, so nothing was written", args[0], herePath(path))
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
	if err := editConfigAt(path, apply); err != nil {
		return err
	}
	// Which file, always. With two possible destinations, a silent success is a guess.
	_, _ = fmt.Fprintf(w, "wrote %s\n", herePath(path))
	// An edit to a file that already had problems is accepted when it adds none, and the ones left
	// are said, or `wrote` reads as a file that now loads.
	if n := remainingProblems(path); n > 0 {
		_, _ = fmt.Fprintf(w, "%s still has %s; `draugr config validate` lists them\n",
			herePath(path), english.Count(n, "problem"))
	}
	return nil
}

// editConfigAt applies an edit to the file at path and writes it back, refusing to save anything
// Draugr cannot load.
func editConfigAt(path string, apply func([]byte) ([]byte, error)) error {
	doc, err := os.ReadFile(path) // #nosec G304 -- a path this command owns
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	out, err := apply(doc)
	if err != nil {
		return err
	}
	// Refused only for a problem the edit adds. A file that already has two is then mended one
	// `unset` at a time, rather than locked until somebody edits it by hand.
	reg := builtins.Registry()
	if _, after := parseConfig(reg, path, out); after != nil {
		_, before := parseConfig(reg, path, doc)
		if added := addedProblems(before, after); len(added) > 0 {
			msg := "that edit would add a problem to the file, so nothing was written:\n  " +
				strings.Join(added, "\n  ")
			if h := problemHint(after); h != "" {
				msg += "\n\n" + h
			}
			return errors.New(msg)
		}
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	return os.WriteFile(path, out, 0o600)
}

// addedProblems lists the problems after reports that before does not. An error that is not a
// *config.Problems is one problem of its own.
func addedProblems(before, after error) []string {
	var b, a *config.Problems
	if !errors.As(after, &a) {
		return []string{after.Error()}
	}
	had := map[string]bool{}
	if errors.As(before, &b) {
		for _, p := range b.List {
			had[p] = true
		}
	}
	var out []string
	for _, p := range a.List {
		if !had[p] {
			out = append(out, p)
		}
	}
	return out
}

// remainingProblems counts what is still wrong with the file at path after an edit was accepted.
func remainingProblems(path string) int {
	var p *config.Problems
	if errors.As(validateConfigFile(builtins.Registry(), path), &p) {
		return len(p.List)
	}
	return 0
}

func newConfigInitCommand() *cobra.Command {
	var global, force bool
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Write a starter config, or reset a broken one",
		Long: "Write a commented starter configuration.\n\n" +
			"--force replaces a file that no longer loads. A file Draugr cannot parse is never\n" +
			"repaired in place.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			path, err := configPath(global)
			if err != nil {
				return err
			}
			if _, err := os.Stat(path); err == nil && !force {
				return fmt.Errorf("%s already exists; pass --force to replace it with the "+
					"built-in defaults", herePath(path))
			}
			if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
				return err
			}
			if err := os.WriteFile(path, []byte(starterConfig), 0o600); err != nil {
				return err
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n", herePath(path))
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
				// Listed rather than loaded, so one broken file does not stop the rest being checked.
				paths = config.Files(rootConfigPath, wd)
				if len(paths) == 0 {
					_, _ = fmt.Fprintln(w, col.Paint(tui.StyleMuted,
						"No configuration found, nothing to check."))
					return nil
				}
			}
			reg := builtins.Registry()
			failed := 0
			hints := map[string]bool{}
			var order []string
			for _, p := range paths {
				err := validateConfigFile(reg, p)
				if err == nil {
					_, _ = fmt.Fprintf(w, "%s %s\n", col.Paint(tui.StylePass, "✓"), herePath(p))
					continue
				}
				failed++
				_, _ = fmt.Fprintf(w, "%s %s\n%s\n", col.Paint(tui.StyleFail, "✗"), herePath(p), problemLines(err))
				if h := problemHint(err); h != "" && !hints[h] {
					hints[h] = true
					order = append(order, h)
				}
			}
			if failed == 0 {
				return nil
			}
			for _, h := range order {
				_, _ = fmt.Fprintf(w, "\n%s\n", col.Paint(tui.StyleMuted, h))
			}
			return fmt.Errorf("%d of %s did not validate", failed, english.Count(len(paths), "file"))
		},
	}
}

// validateConfigFile reads one file and holds it to every check a scan makes of it.
func validateConfigFile(reg *engine.Registry, path string) error {
	data, err := os.ReadFile(path) // #nosec G304 -- operator-provided path
	if err != nil {
		return err
	}
	_, err = parseConfig(reg, path, data)
	return err
}

// problemLines renders a configuration error as indented lines, one per problem, without the file
// name a caller has already printed. An error of another kind is one line.
func problemLines(err error) string {
	var p *config.Problems
	if !errors.As(err, &p) {
		return "  " + err.Error()
	}
	return "  " + strings.Join(p.List, "\n  ")
}

// problemHint is where a configuration error sends the reader next, or "" for an error of another
// kind.
func problemHint(err error) string {
	var p *config.Problems
	if errors.As(err, &p) {
		return p.Hint
	}
	return ""
}

// isSetting reports whether a dotted key names something the config file may hold.
//
// Asked by writing it into an empty document and parsing the result, which is the same check
// `config set` already makes, so the two cannot disagree about what a setting is. A second list of
// valid keys kept by hand is the one that goes stale the first time somebody adds a field.
//
// Probed with a value of each scalar kind, because a key whose field is a boolean, a number or a
// duration refuses a string, and a probe of one kind only reports those keys as settings Draugr
// does not have.
func isSetting(key string) bool {
	for _, probe := range []string{"probe", "true", "1", "1h"} {
		doc, err := config.Set(nil, key, probe)
		if err != nil {
			return false
		}
		if _, err := config.Parse(doc, ""); err == nil {
			return true
		}
	}
	return false
}
