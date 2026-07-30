package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/draugr-dev/draugr/internal/builtins"
	"github.com/draugr-dev/draugr/pkg/engine"

	"github.com/draugr-dev/draugr/pkg/tui"
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

	col := tui.For(w)
	t := tui.NewTable(col, "Control", "Scope", "Scanners", "Purpose")
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
		t.Row(
			tui.Styled(tui.StyleAccent, info.Name),
			tui.PlainCell(string(info.Scope)),
			tui.PlainCell(scanners),
			tui.Styled(tui.StyleMuted, info.Summary),
		)
	}
	t.Render(w)

	if optIn {
		_, _ = fmt.Fprintln(w, "\n"+col.Paint(tui.StyleMuted,
			"* opt-in scanner — enable with controllers.<control>.<scanner>.enabled: true in the Saga."))
	}
	writeEffects(w, col, reg)
	_, _ = fmt.Fprintln(w, "\n"+col.Paint(tui.StyleMuted,
		"Enable a control under config.controllers.<name> (or per component) in your Saga."))
	return nil
}

// writeEffects lists the scanners that do more to a target than read it.
//
// Before a scan rather than during one: which controls send traffic, need elevated access, or
// create something is a question to answer while choosing what to enable. A scanner that only
// reads an artifact says nothing here, so the list stays short enough to read.
func writeEffects(w io.Writer, col tui.Painter, reg *engine.Registry) {
	type row struct{ scanner, kind, detail string }
	var rows []row
	needsConsent := false
	for _, s := range reg.Scanners() {
		info := s.Info()
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
