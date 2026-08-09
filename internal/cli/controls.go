package cli

import (
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/draugr-dev/draugr/internal/builtins"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"

	"github.com/draugr-dev/draugr/pkg/tui"
)

func newControlsCommand() *cobra.Command {
	var showOptions bool
	cmd := &cobra.Command{
		Use:   "controls [control]",
		Short: "List the security controls Draugr can run, their purpose, and scanners",
		Long: "List every security control Draugr can run — what it checks, its scope, and which\n" +
			"scanner(s) implement it (default, plus any opt-in alternatives). Enable a control in\n" +
			"your Saga under config.controllers.<name> (or per component).\n\n" +
			"--options adds what each scanner accepts in its Saga block. A scanner listed there\n" +
			"with no options is configured by choosing it: anything else written under its block\n" +
			"is rejected before the scan runs, rather than accepted and ignored.\n\n" +
			"Name a control to see only that one:\n\n" +
			"  draugr controls sast --options",
		// One control narrows everything below, because `--options` over eleven controls is a
		// screenful you scroll past to find the one you were writing.
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			only := ""
			if len(args) == 1 {
				only = args[0]
			}
			return runControls(cmd.OutOrStdout(), builtins.Registry(), showOptions, only)
		},
	}
	cmd.Flags().BoolVar(&showOptions, "options", false,
		"also list the Saga options each scanner accepts")
	return cmd
}

func runControls(w io.Writer, reg *engine.Registry, showOptions bool, only string) error {
	if only != "" {
		if err := knownControl(reg, only); err != nil {
			return err
		}
	}
	// Which scanners serve each control (by scanner name).
	serving := map[string][]string{}
	for _, s := range reg.Scanners() {
		info := s.Info()
		for _, c := range info.Controls {
			serving[c] = append(serving[c], info.Name)
		}
	}

	col := tui.For(w)

	// Scope earns a column only when it distinguishes one control from another. Every controller
	// is component-scoped today, so the column repeated "component" ten times and cost width the
	// Purpose column wanted — the same reasoning that hides the Component column in a report of a
	// single-component scan. The engine still supports project scope; if one ever ships, the
	// column comes back on its own.
	varyingScope := false
	if all := reg.Controllers(); len(all) > 1 {
		first := all[0].Info().Scope
		for _, c := range all[1:] {
			if c.Info().Scope != first {
				varyingScope = true
				break
			}
		}
	}

	headers := []string{"Control", "Scanners", "Purpose"}
	if varyingScope {
		headers = []string{"Control", "Scope", "Scanners", "Purpose"}
	}
	t := tui.NewTable(col, headers...)
	optIn := false
	for _, ctrl := range reg.Controllers() {
		info := ctrl.Info()
		if only != "" && info.Name != only {
			continue
		}
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
		cells := []tui.Cell{tui.Styled(tui.StyleAccent, info.Name)}
		if varyingScope {
			cells = append(cells, tui.PlainCell(string(info.Scope)))
		}
		cells = append(cells,
			tui.PlainCell(scanners),
			tui.Styled(tui.StyleMuted, info.Summary),
		)
		t.Row(cells...)
	}
	t.Render(w)

	writeScannerOrigins(w, col, reg, only)

	if optIn {
		_, _ = fmt.Fprintln(w, "\n"+col.Paint(tui.StyleMuted,
			"* opt-in scanner — enable with controllers.<control>.<scanner>.enabled: true in the Saga."))
	}
	writeEffects(w, col, reg, only)
	if showOptions {
		writeScannerOptions(w, col, reg, only)
	}
	_, _ = fmt.Fprintln(w, "\n"+col.Paint(tui.StyleMuted,
		"Enable a control under config.controllers.<name> (or per component) in your Saga."))
	if !showOptions {
		_, _ = fmt.Fprintln(w, col.Paint(tui.StyleMuted,
			"Run `draugr controls --options` for what each scanner accepts in its block."))
	}
	return nil
}

// writeScannerOptions lists what each scanner accepts under its own block in the Saga.
//
// Behind a flag because it is reference material and the table above it is an overview; a reader
// choosing which controls to enable does not need the option list, and a reader writing the block
// needs all of it.
//
// A scanner with nothing to list still gets a line saying so. The alternative — omitting it —
// leaves a reader unable to tell "accepts nothing" from "not documented yet", and those two
// answers lead to opposite next steps.
func writeScannerOptions(w io.Writer, col tui.Painter, reg *engine.Registry, only string) {
	serves := func(info plugin.ScannerInfo) bool {
		if only == "" {
			return true
		}
		return slices.Contains(info.Controls, only)
	}
	_, _ = fmt.Fprintln(w, "\n"+col.Paint(tui.StyleAccent, "What each scanner accepts in its Saga block:"))
	scanners := reg.Scanners()
	sort.Slice(scanners, func(i, j int) bool { return scanners[i].Info().Name < scanners[j].Info().Name })
	for _, s := range scanners {
		info := s.Info()
		if !serves(info) {
			continue
		}
		opts := plugin.Options(info.ConfigSchema)
		_, _ = fmt.Fprintln(w, "\n  "+col.Paint(tui.StyleAccent, info.Name))
		if len(opts) == 0 {
			_, _ = fmt.Fprintln(w, "    "+col.Paint(tui.StyleMuted,
				"no options — configured by choosing it; any other key is an error"))
			continue
		}
		t := tui.NewTable(col, "Option", "Type", "What it does").Indent("    ")
		for _, o := range opts {
			name := o.Name
			if o.Required {
				name += " (required)"
			}
			desc := o.Description
			if len(o.Enum) > 0 {
				desc += " One of: " + strings.Join(o.Enum, ", ") + "."
			}
			t.Row(
				tui.PlainCell(name),
				tui.Styled(tui.StyleMuted, o.Type),
				tui.Styled(tui.StyleMuted, desc),
			)
		}
		t.Render(w)
	}
}

// writeEffects lists the scanners that do more to a target than read it.
//
// Before a scan rather than during one: which controls send traffic, need elevated access, or
// create something is a question to answer while choosing what to enable. A scanner that only
// reads an artifact says nothing here, so the list stays short enough to read.
func writeEffects(w io.Writer, col tui.Painter, reg *engine.Registry, only string) {
	type row struct{ scanner, kind, detail string }
	var rows []row
	needsConsent := false
	for _, s := range reg.Scanners() {
		info := s.Info()
		if only != "" && !slices.Contains(info.Controls, only) {
			continue
		}
		for _, e := range info.Effects {
			rows = append(rows, row{info.Name, string(e.Kind), e.Detail})
			needsConsent = needsConsent || e.Kind.RequiresConsent()
		}
	}
	if len(rows) == 0 {
		return
	}
	_, _ = fmt.Fprintln(w, "\n"+col.Paint(tui.StyleAccent, "Scanners that do more than read:"))
	t := tui.NewTable(col, "Scanner", "Effect", "What happens").Indent("  ")
	for _, r := range rows {
		t.Row(
			tui.PlainCell(r.scanner),
			tui.Styled(tui.StyleMedium, r.kind),
			tui.Styled(tui.StyleMuted, r.detail),
		)
	}
	t.Render(w)
	if needsConsent {
		_, _ = fmt.Fprintln(w, col.Paint(tui.StyleMuted,
			"Effects marked mutate or privilege do not run until accepted — list them under\n"+
				"config.allowEffects in your Saga, or pass --allow-effects."))
	}
}

// writeScannerOrigins lists who publishes each scanner's tool.
//
// A roster answers a question the per-control table cannot: which of these is a third party
// executing on this machine, and whose. Reading that table, `draugr-headers` and `gitleaks` look
// alike — one is Draugr's own detection logic and the other is somebody else's binary, and
// nothing on the row says so.
//
// Grouped by origin rather than listed per scanner, because the question is usually about the
// publisher: four of these come from Aqua, and a supply-chain review wants to see that at once.
func writeScannerOrigins(w io.Writer, col tui.Painter, reg *engine.Registry, only string) {
	byOrigin := map[string][]string{}
	for _, s := range reg.Scanners() {
		info := s.Info()
		if only != "" && !slices.Contains(info.Controls, only) {
			continue
		}
		origin := info.Origin
		if origin == "" {
			// Never silently attributed to us. An unlabelled scanner is a gap in the roster, and
			// showing it as one is the only way it gets fixed.
			origin = "unknown"
		}
		byOrigin[origin] = append(byOrigin[origin], info.Name)
	}
	if len(byOrigin) == 0 {
		return
	}

	origins := make([]string, 0, len(byOrigin))
	for o := range byOrigin {
		origins = append(origins, o)
	}
	// Draugr first — the reader is usually asking which are not ours, and the answer is
	// everything below the first row.
	sort.Slice(origins, func(i, j int) bool {
		if (origins[i] == plugin.OriginDraugr) != (origins[j] == plugin.OriginDraugr) {
			return origins[i] == plugin.OriginDraugr
		}
		return origins[i] < origins[j]
	})

	_, _ = fmt.Fprintln(w, "\n"+col.Paint(tui.StyleAccent, "Who publishes each scanner:"))
	t := tui.NewTable(col, "Origin", "Scanners").Indent("  ")
	for _, o := range origins {
		names := byOrigin[o]
		sort.Strings(names)
		style := tui.StyleMuted
		if o == plugin.OriginDraugr {
			style = tui.StyleAccent
		}
		t.Row(tui.Styled(style, o), tui.PlainCell(strings.Join(names, ", ")))
	}
	t.Render(w)
	_, _ = fmt.Fprintln(w, col.Paint(tui.StyleMuted,
		"Draugr executes third-party tools rather than bundling them, so each stays under its own\n"+
			"licence. `draugr tools list` shows which are installed and where."))
}

// knownControl rejects a name no controller answers to, naming the closest match.
//
// Silently printing an empty table would read as "this control has no scanners", which is a
// different and worse answer than "there is no such control".
func knownControl(reg *engine.Registry, name string) error {
	known := map[string]bool{}
	var names []string
	for _, c := range reg.Controllers() {
		known[c.Info().Name] = true
		names = append(names, c.Info().Name)
	}
	if known[name] {
		return nil
	}
	sort.Strings(names)
	msg := fmt.Sprintf("%q is not a control this build provides", name)
	if near := nearestControl(name, known); near != "" {
		msg += fmt.Sprintf(" — did you mean %q?", near)
	}
	return fmt.Errorf("%s\n\nit has: %s", msg, strings.Join(names, ", "))
}
