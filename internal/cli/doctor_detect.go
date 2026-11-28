package cli

import (
	"fmt"
	"io"
	"slices"

	"github.com/draugr-dev/draugr/internal/detect"
	"github.com/draugr-dev/draugr/internal/needs"
	"github.com/draugr-dev/draugr/internal/tools"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/tui"
)

// detectedNote is what doctor's DETECTED heading says about its rows.
const detectedNote = "config.detect turned these on, from the files that call for them"

// detectIn turns on the controls config.detect calls for in model, and returns what it read, nil
// for a descriptor that does not set it.
func detectIn(model *saga.Model) (*detection, error) {
	result, err := detect.Apply(model)
	if err != nil || result == nil {
		return nil, err
	}
	return &detection{result: result, model: model}, nil
}

// optionalTools marks optional each tool in required that only a scanner detect chose needs: one
// neither the base nor the descriptor names. A scan turns such a scanner off where it cannot run and
// names the files it would have read, so its tool missing is a gap in coverage and not a scan that
// fails, and doctor says the same. Required is returned as it is for a descriptor without detect.
func (d *detection) optionalTools(reg *engine.Registry, required []tools.Tool) []tools.Tool {
	if d == nil {
		return required
	}
	named := map[string]bool{}
	if base, err := zeroConfigBase(); err == nil {
		for _, t := range needs.Tools(reg, base) {
			named[t.Binary] = true
		}
	}
	for _, t := range needs.Tools(reg, d.result.AsWritten(d.model)) {
		named[t.Binary] = true
	}
	out := make([]tools.Tool, len(required))
	for i, t := range required {
		t.Optional = !named[t.Binary]
		out[i] = t
	}
	return out
}

// writeDoctor prints doctor's DETECTED block: for each component, each repository it names, the
// controls every repository gets, and a row per kind of file naming the files and what they turned
// on. A repository an earlier component names is not listed again, and one detect could not read
// says so. Nothing for a descriptor without detect.
func (d *detection) writeDoctor(w io.Writer, reg *engine.Registry) {
	if d == nil {
		return
	}
	col := tui.For(w)
	off := d.off(reg)
	base := foundRow{on: zeroConfigControls()}
	_, _ = fmt.Fprintf(w, "\n%s  %s\n", doctorHeading(col, "Detected"), col.Paint(tui.StyleMuted, detectedNote))
	// Read off the result rather than the model, whose urls a later step may root at their work
	// tree: the urls here are the ones the descriptor wrote, which is how a reader finds them.
	for _, c := range d.model.Components {
		t := tui.NewTable(col).Indent("    ").Fit(tui.Columns(w))
		rows := 0
		for _, r := range d.result.Read {
			switch {
			case !slices.Contains(r.Components, c.Name):
				continue
			case r.Components[0] != c.Name:
				t.Row(tui.PlainCell("repository"), tui.PlainCell(r.URL), tui.Styled(tui.StyleMuted, "as for "+r.Components[0]))
				rows++
				continue
			}
			t.Row(tui.PlainCell("repository"), tui.PlainCell(r.URL), tui.Styled(tui.StyleMuted, base.scanSays(off)))
			rows++
			for _, row := range foundRows(r.Tree) {
				t.Row(tui.PlainCell(row.kind), row.whereCell(), tui.Styled(tui.StyleMuted, row.scanSays(off)))
				rows++
			}
		}
		for _, u := range d.result.Unread {
			if slices.Contains(u.Components, c.Name) {
				t.Row(tui.PlainCell("repository"), tui.PlainCell(u.URL), tui.Styled(tui.StyleMuted, "not read · "+detect.UnreadReason))
				rows++
			}
		}
		if rows == 0 {
			continue
		}
		_, _ = fmt.Fprintf(w, "  %s\n", c.Name)
		t.Render(w)
	}
}
