package cli

import (
	"fmt"
	"io"
	"sort"
	"strings"
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
	// width is the last line's length, so the next one can clear what it does not overwrite.
	// Without it, a shorter line leaves the tail of a longer one behind and the display reads as
	// two states at once.
	width int
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

// erase clears the drawn line. Callers hold mu.
func (p *progressLine) erase() {
	if p.width > 0 {
		_, _ = fmt.Fprintf(p.w, "\r%s\r", strings.Repeat(" ", p.width))
		p.width = 0
	}
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
	p := &progressLine{w: w}
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
	line := progressText(ev)
	pad := max(p.width-len(line), 0)
	_, _ = fmt.Fprintf(p.w, "\r%s%s", line, strings.Repeat(" ", pad))
	p.width = len(line)
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

// progressText renders one snapshot.
//
// Counts first, because "will this finish" is the question being asked. Then what is in flight,
// which answers the second question — whether the wait is one slow job or many.
func progressText(ev engine.ProgressEvent) string {
	if ev.Total == 0 {
		return ""
	}
	line := fmt.Sprintf("scanning %d/%d", ev.Complete, ev.Total)
	// Immediately after the count, before what is in flight. A run whose jobs are failing is one
	// a reader may want to stop rather than wait out, and that decision is worth nothing once the
	// report explains it — by then they have already waited.
	if ev.Failed > 0 {
		line += fmt.Sprintf(" · %d failed", ev.Failed)
	}
	if len(ev.Running) == 0 {
		return line
	}
	return line + " · " + strings.Join(collapse(ev.Running), ", ")
}

// collapse folds repeats into a count, so six image scans read as one item rather than six.
//
// A run's slow jobs are usually many of one kind — an image per container, a repository per
// component — and listing each by name fills the line with the same word and pushes off the one
// job that is different.
func collapse(running []string) []string {
	counts := map[string]int{}
	var order []string
	for _, name := range running {
		if counts[name] == 0 {
			order = append(order, name)
		}
		counts[name]++
	}
	sort.Strings(order)
	out := make([]string, 0, len(order))
	for _, name := range order {
		if counts[name] > 1 {
			out = append(out, fmt.Sprintf("%s ×%d", name, counts[name]))
			continue
		}
		out = append(out, name)
	}
	return out
}
