package cli

import (
	"fmt"
	"io"
	"sync"
	"sync/atomic"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/tui"
)

// progressLine renders what a run is doing, in place, on one line.
//
// Written to stderr and only when stderr is a terminal. A scan's report goes to stdout and is
// piped, redirected and diffed; a progress line that reached it would corrupt every one of those.
// And a line that redraws itself is noise in a CI log, where the file keeps every frame — so the
// same output that helps a person watching costs a reader of the log a screen of carriage returns.
//
// Suppressed by --no-tips and DRAUGR_NO_TIPS alongside the other advisory output: somebody who has
// turned that off has said they want the report and nothing else.
type progressLine struct {
	w io.Writer
	// mu serialises writes. The engine reports under its own lock, but nothing promises the same
	// goroutine each time, and two interleaved writes to one line produce something unreadable.
	mu sync.Mutex
	// drawn is how many lines are on the terminal, so the next update can move back over them
	// and the erase can clear all of them. Without it a shorter frame leaves the tail of a longer
	// one behind, and the display reads as two states at once.
	drawn int
	// painter decides whether the frame carries colour, which depends on the same writer.
	painter tui.Painter
}

// active is the progress line currently drawn on the terminal, if any.
//
// Package-level because it models something that is genuinely single: there is one terminal, and
// anything writing to it has to agree about whose line is on it. The logger is configured before a
// scan exists and writes from wherever a warning happens, so passing the renderer down to it is
// not available — the alternative is a log line landing in the middle of the progress line, which
// is what happens without this.
var active atomic.Pointer[progressLine]

// LogWriter wraps stderr so a log line erases the progress line before printing.
//
// The erase and the write happen under the renderer's own lock, so an update cannot redraw between
// them and leave the two interleaved.
func LogWriter(w io.Writer) io.Writer { return coordinatedWriter{w: w} }

// coordinatedWriter is the writer LogWriter returns.
type coordinatedWriter struct{ w io.Writer }

func (c coordinatedWriter) Write(b []byte) (int, error) {
	if p := active.Load(); p != nil {
		return p.writeThrough(b)
	}
	return c.w.Write(b)
}

// writeThrough erases the line, writes b, and lets the next update redraw.
func (p *progressLine) writeThrough(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.erase()
	return p.w.Write(b)
}

// erase clears every drawn line. Callers hold mu.
//
// Moves back over the frame and clears each row rather than overwriting with spaces: the frame is
// several lines now, and a terminal that has scrolled since would otherwise have blanks written
// over whatever moved into their place.
func (p *progressLine) erase() {
	if p.drawn == 0 {
		return
	}
	for range p.drawn {
		_, _ = fmt.Fprint(p.w, "\r\033[2K\033[1A")
	}
	_, _ = fmt.Fprint(p.w, "\r\033[2K")
	p.drawn = 0
}

// newProgressLine returns a renderer, or nil when nothing should be drawn.
func newProgressLine(w io.Writer, opts scanOptions) *progressLine {
	if opts.noTips || tipsDisabled() || !tui.IsTerminal(w) {
		return nil
	}
	return newProgressLineFor(w)
}

// newProgressLineFor builds a renderer for w unconditionally, and registers it as the one on the
// terminal. Separated from newProgressLine so a test can exercise the drawing without a terminal.
func newProgressLineFor(w io.Writer) *progressLine {
	p := &progressLine{w: w, painter: tui.For(w)}
	active.Store(p)
	return p
}

// update draws a snapshot.
func (p *progressLine) update(ev engine.ProgressEvent) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	lines := progressFrame(ev, p.painter)
	if len(lines) == 0 {
		return
	}
	p.erase()
	for i, line := range lines {
		if i > 0 {
			_, _ = fmt.Fprint(p.w, "\n")
		}
		_, _ = fmt.Fprintf(p.w, "\r\033[2K%s", line)
	}
	p.drawn = len(lines)
}

// done erases the line, so the report starts on a clean one.
//
// Erased rather than left in place: it describes a run in progress, and the run is over. A final
// "11 of 11" above the report is a second, worse summary of what the report already says.
func (p *progressLine) done() {
	if p == nil {
		return
	}
	active.Store(nil)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.erase()
}

// progressFrame renders the whole display: a headline, then a row per control/scanner.
//
// Several lines rather than one, because the interesting question changes as a run goes on. At
// the start it is "will this finish"; a minute in it is "what is it waiting on"; and after a
// failure it is "what already worked". One line can answer the first, and answers the others by
// listing what is in flight — which changes constantly and drops each scanner the moment it
// finishes, so the reader watches work disappear and cannot tell finished from not started.
//
// A row that stays, and changes state, answers all three.
func progressFrame(ev engine.ProgressEvent, col tui.Painter) []string {
	if ev.Total == 0 {
		return nil
	}
	lines := []string{progressHeadline(ev, col)}
	for _, st := range ev.Steps {
		lines = append(lines, progressStepLine(st, col))
	}
	return lines
}

// progressHeadline is the count, and the failures if there are any.
func progressHeadline(ev engine.ProgressEvent, col tui.Painter) string {
	line := fmt.Sprintf("Scanning %d/%d", ev.Complete, ev.Total)
	if ev.Failed > 0 {
		line += "  " + col.Paint(tui.StyleFail, fmt.Sprintf("%d failed", ev.Failed))
	}
	return line
}

// progressStepLine renders one control/scanner: a mark, the name, and where its jobs have got to.
//
// The mark carries the state and the colour reinforces it, rather than the colour carrying it
// alone — the same output goes to terminals with no colour, and to people who cannot distinguish
// the ones it uses.
func progressStepLine(st engine.ProgressStep, col tui.Painter) string {
	mark, style := "·", tui.StyleMuted // planned, not started
	switch {
	case st.Failed > 0 && st.Done == st.Total:
		mark, style = "✗", tui.StyleFail
	case st.Done == st.Total:
		mark, style = "✓", tui.StylePass
	case st.Running > 0:
		mark, style = "▸", tui.StyleAccent
	}

	name := st.Name()
	detail := fmt.Sprintf("%d/%d", st.Done, st.Total)
	if st.Failed > 0 {
		detail += fmt.Sprintf(", %d failed", st.Failed)
	}
	return fmt.Sprintf("  %s %-*s %s",
		col.Paint(style, mark), progressNameWidth, name, col.Paint(tui.StyleMuted, detail))
}

// progressNameWidth keeps the counts in a column. Names are "control/scanner" and the longest
// built-in pair is a little under this.
const progressNameWidth = 34
