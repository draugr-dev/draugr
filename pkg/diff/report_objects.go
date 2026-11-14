package diff

import (
	"fmt"
	"io"
	"strings"

	"github.com/draugr-dev/draugr/pkg/tui"
)

// objectHalf is the objects that joined the checks, or the objects that left them.
type objectHalf struct {
	joined  bool
	objects func(ObjectChange) []string
}

// mark is what an object's line opens with, the mark a change wears in CHANGED and the word, padded
// to one width so the objects after it line up.
func (h objectHalf) mark() string {
	if h.joined {
		return ChangeNew.Mark() + " joined"
	}
	return ChangeFixed.Mark() + " left  "
}

// style is bold for an object that joined, which is what the change brought in, and muted for one
// that left, as CHANGED draws a new row and a fixed one.
func (h objectHalf) style() tui.Style {
	if h.joined {
		return tui.StyleStrong
	}
	return tui.StyleMuted
}

// objectHalves is the order every rendering lists the objects in: every one that joined a check,
// then every one that left one.
//
// Joined first, because an object that joined a failing check is something the change brought in
// and one that left is good news. Listed check by check instead, a check that lost an object sits
// above one that gained one further down, and a reader looking for what the change brought in has
// to read the whole block to be sure they found it all.
var objectHalves = []objectHalf{
	{joined: true, objects: func(c ObjectChange) []string { return c.Joined }},
	{joined: false, objects: func(c ObjectChange) []string { return c.Left }},
}

// where is the check's component and place, the component first where it has one.
func (c ObjectChange) where() string {
	if c.Component == "" {
		return c.Location.URI
	}
	return c.Component + " · " + c.Location.URI
}

// objectsHeading is what the block says beside its title: how many objects joined and how many left.
// It counts objects and states no state of a check, since a check here can also be a new row above:
// one that gained an object is new to the gate and failed at the base too.
func objectsHeading(cs []ObjectChange) string {
	joined, left := 0, 0
	for _, c := range cs {
		joined += len(c.Joined)
		left += len(c.Left)
	}
	var parts []string
	if joined > 0 {
		parts = append(parts, fmt.Sprintf("%d joined", joined))
	}
	if left > 0 {
		parts = append(parts, fmt.Sprintf("%d left", left))
	}
	return strings.Join(parts, ", ")
}

// writeObjects lists, per check that lists objects and changed, the objects that joined it and
// left it, every object that joined before any that left. The full view names the check's rule and
// place, then a line per object marked as a change is, so a check that both gained and lost objects
// is named twice, once in each half. The compact view is a line per object, with its check and
// place on the same line.
//
// Apart from the CHANGED table, which keeps a row per check and counts checks: a check is what the
// gate judges, and its row quotes the whole list of objects failing it, most of them there before the
// change. Here is which of them the change touched, a check that only lost objects included, which
// is not a change the table lists. first is where nothing is listed above the block, which then
// opens without the blank line that would set it apart from the table.
func writeObjects(w io.Writer, col tui.Painter, r Result, opts Options, first bool) {
	if len(r.Objects) == 0 {
		return
	}
	if !first {
		_, _ = fmt.Fprintln(w)
	}
	_, _ = fmt.Fprintf(w, "%s  %s\n", col.Paint(tui.StyleMuted, "OBJECTS"),
		col.Paint(tui.StyleMuted, objectsHeading(r.Objects)))
	if opts.View == ViewCompact {
		t := tui.NewTable(col).Indent("  ")
		for _, half := range objectHalves {
			for _, c := range r.Objects {
				for _, o := range half.objects(c) {
					t.Row(tui.Styled(half.style(), half.mark()), tui.PlainCell(o), tui.PlainCell(c.RuleID),
						tui.Styled(tui.StyleMuted, c.where()))
				}
			}
		}
		t.Render(w)
		return
	}
	for _, half := range objectHalves {
		for _, c := range r.Objects {
			objects := half.objects(c)
			if len(objects) == 0 {
				continue
			}
			_, _ = fmt.Fprintf(w, "  %s  %s\n", c.RuleID, col.Paint(tui.StyleMuted, c.where()))
			for _, o := range objects {
				_, _ = fmt.Fprintf(w, "    %s %s\n", col.Paint(half.style(), half.mark()), o)
			}
		}
	}
}

// writeMarkdownObjects is writeObjects for the pull-request comment: a list after the table, one
// item per object, every object that joined before any that left.
//
// A list rather than a table, because each item is one sentence about one object, and a reader of a
// comment reads it down rather than across.
func writeMarkdownObjects(w io.Writer, r Result) {
	if len(r.Objects) == 0 {
		return
	}
	_, _ = fmt.Fprintf(w, "\n### Objects · %s\n\n", objectsHeading(r.Objects))
	for _, half := range objectHalves {
		mark := "left"
		if half.joined {
			mark = "**joined**"
		}
		for _, c := range r.Objects {
			id := "`" + c.RuleID + "`"
			if u := r.HelpURI(c.RuleID); u != "" {
				id = "[" + id + "](" + u + ")"
			}
			for _, o := range half.objects(c) {
				_, _ = fmt.Fprintf(w, "- %s `%s` · %s · %s\n", mark, o, id, c.where())
			}
		}
	}
}
