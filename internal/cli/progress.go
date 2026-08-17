package cli

import (
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

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
	// mu serializes writes. The engine reports under its own lock, but nothing promises the same
	// goroutine each time, and two interleaved writes to one line produce something unreadable.
	mu sync.Mutex
	// drawn is how many lines are on the terminal, so the next update can move back over them
	// and the erase can clear all of them. Without it a shorter frame leaves the tail of a longer
	// one behind, and the display reads as two states at once.
	drawn int
	// painter decides whether the frame carries color, which depends on the same writer.
	painter tui.Painter
	// last is the most recent snapshot, kept so the ticker can repaint it with the clocks moved
	// on. Progress is reported when a job starts or finishes, so a step with one slow job
	// produces no events while it runs — and a frozen display during a long job is exactly when
	// somebody starts wondering whether anything is happening.
	last  engine.ProgressEvent
	start time.Time
	// stop ends the repaint loop. Buffered so done never blocks on a ticker that has already
	// gone away.
	stop chan struct{}
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
	p := &progressLine{
		w: w, painter: tui.For(w), start: time.Now(), stop: make(chan struct{}, 1),
	}
	active.Store(p)
	go p.tick()
	return p
}

// tick repaints once a second so the clocks move while a job runs.
//
// A second because that is the resolution the figures are shown at; faster would rewrite the
// screen for no visible change, and slower makes a reader wonder whether the display has stopped
// along with the scan.
func (p *progressLine) tick() {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-p.stop:
			return
		case <-t.C:
			p.repaint()
		}
	}
}

// repaint redraws the last snapshot. Does nothing before the first one arrives, so a run that
// fails during planning never draws a frame at all.
func (p *progressLine) repaint() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.last.Total == 0 {
		return
	}
	p.draw(p.last)
}

// update draws a snapshot.
func (p *progressLine) update(ev engine.ProgressEvent) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.last = ev
	p.draw(ev)
}

// draw renders one frame. Callers hold mu.
func (p *progressLine) draw(ev engine.ProgressEvent) {
	lines := progressFrame(ev, p.painter, time.Since(p.start))
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
	select {
	case p.stop <- struct{}{}:
	default: // already stopped; done is idempotent
	}
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
func progressFrame(ev engine.ProgressEvent, col tui.Painter, elapsed time.Duration) []string {
	if ev.Total == 0 {
		return nil
	}
	lines := []string{progressHeadline(ev, col, elapsed)}
	for _, st := range ev.Steps {
		lines = append(lines, progressStepLine(st, col))
	}
	return lines
}

// progressHeadline is the count, and the failures if there are any.
func progressHeadline(ev engine.ProgressEvent, col tui.Painter, elapsed time.Duration) string {
	line := fmt.Sprintf("Scanning %d/%d", ev.Complete, ev.Total)
	if elapsed >= time.Second {
		line += "  " + col.Paint(tui.StyleMuted, shortDuration(elapsed))
	}
	if ev.Failed > 0 {
		line += "  " + col.Paint(tui.StyleFail, fmt.Sprintf("%d failed", ev.Failed))
	}
	return line
}

// progressStepLine renders one control/scanner: a mark, the name, and where its jobs have got to.
//
// The mark carries the state and the color reinforces it, rather than the color carrying it
// alone — the same output goes to terminals with no color, and to people who cannot distinguish
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
	// How long this step's oldest running job has been going. The question a reader has about a
	// step that has not moved is whether it is working, and a figure that keeps climbing answers
	// it — a stuck run and a slow one look identical without it.
	//
	// Not for the first couple of seconds. A job that finishes quickly would otherwise flash a
	// "0s" on its way past, and a figure that appears and disappears draws the eye to the steps
	// that need it least.
	if since := st.RunningSince; !since.IsZero() {
		if elapsed := time.Since(since); elapsed >= slowEnoughToTime {
			detail += "  " + shortDuration(elapsed)
		}
	}
	return fmt.Sprintf("  %s %-*s %s",
		col.Paint(style, mark), progressNameWidth, name, col.Paint(tui.StyleMuted, detail))
}

// progressNameWidth keeps the counts in a column. Names are "control/scanner" and the longest
// built-in pair is a little under this.
const progressNameWidth = 34

// slowEnoughToTime is how long a step runs before its clock appears.
const slowEnoughToTime = 2 * time.Second

// shortDuration renders an elapsed time in the units a reader is thinking in.
//
// Seconds up to a minute, then minutes and seconds — "94s" makes somebody do arithmetic to decide
// whether to wait, and a scanner that pulls a database or waits on a cluster runs into minutes.
func shortDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	return fmt.Sprintf("%dm%02ds", int(d.Minutes()), int(d.Seconds())%60)
}
