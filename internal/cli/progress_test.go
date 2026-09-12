package cli

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/tui"
)

// A shorter line must not leave the tail of a longer one behind, or the display reads as two
// states at once, "scanning 9/11" followed by the debris of six scanner names.
func TestProgressClearsWhatItNoLongerCovers(t *testing.T) {
	var buf bytes.Buffer
	p := &progressLine{w: &buf}
	t.Cleanup(func() { active.Store(nil) })

	p.update(engine.ProgressEvent{Total: 9, Complete: 1, Running: []string{"images/trivy", "sca/trivy-fs"}})
	long := buf.Len()
	buf.Reset()
	p.update(engine.ProgressEvent{Total: 9, Complete: 9})

	out := buf.String()
	if !strings.HasPrefix(out, "\r") {
		t.Errorf("an update should redraw in place: %q", out)
	}
	if len(out) < long-1 {
		t.Errorf("the shorter line did not pad over the longer one: %q", out)
	}
	if strings.Contains(out, "trivy") {
		t.Errorf("the previous line's content survived: %q", out)
	}
}

// The logger and the progress line both own stderr. Without coordination a warning lands in the
// middle of the drawn line, which is what a scanner reporting a contended cache does.
func TestALogLineErasesTheProgressLineFirst(t *testing.T) {
	var buf bytes.Buffer
	p := newProgressLineFor(&buf)
	t.Cleanup(func() { active.Store(nil) })

	p.update(engine.ProgressEvent{Total: 6, Complete: 2, Running: []string{"images/trivy"}})
	buf.Reset()

	if _, err := LogWriter(&buf).Write([]byte("WARN something happened\n")); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.HasPrefix(out, "\r") {
		t.Errorf("the log did not erase the drawn line first: %q", out)
	}
	if !strings.HasSuffix(out, "WARN something happened\n") {
		t.Errorf("the log line was mangled: %q", out)
	}
	if strings.Contains(strings.TrimSuffix(out, "WARN something happened\n"), "scanning") {
		t.Errorf("the progress line survived alongside the log: %q", out)
	}
}

// With no line drawn, piped output, --no-tips. The writer must not touch what it passes through.
func TestLogWriterIsTransparentWithoutAProgressLine(t *testing.T) {
	active.Store(nil)
	var buf bytes.Buffer
	if _, err := LogWriter(&buf).Write([]byte("plain\n")); err != nil {
		t.Fatal(err)
	}
	if got := buf.String(); got != "plain\n" {
		t.Errorf("writer altered the output: %q", got)
	}
}

// Not a terminal means not drawn: a report on stdout stays parseable, and a CI log keeps one line
// per event rather than a frame per update.
func TestNoProgressWhenItWouldBeNoise(t *testing.T) {
	var buf bytes.Buffer // not a terminal
	if p := newProgressLine(&buf, scanOptions{}); p != nil {
		t.Error("a non-terminal should draw nothing")
	}
	if p := newProgressLine(&buf, scanOptions{noTips: true}); p != nil {
		t.Error("--no-tips should draw nothing")
	}
}

// TestProgressDoneIsIdempotent covers the shape the fix depends on.
//
// The line is erased when the run finishes, so the report starts on a clean row, and again on the
// way out for a path that returned early. Erasing twice must be harmless. And the second must not
// emit a second row of blanks, which on a terminal is an empty line nobody asked for.
func TestProgressDoneIsIdempotent(t *testing.T) {
	var buf bytes.Buffer
	p := newProgressLineFor(&buf)
	t.Cleanup(func() { active.Store(nil) })

	p.update(engine.ProgressEvent{Total: 4, Complete: 1})
	p.done()
	afterFirst := buf.String()

	p.done()
	if got := buf.String(); got != afterFirst {
		t.Errorf("the second erase wrote %q", got[len(afterFirst):])
	}
	// And nothing is left registered, so a log line afterwards is not routed through a line that
	// is no longer on the terminal.
	if active.Load() != nil {
		t.Error("the finished line is still registered as the one on the terminal")
	}
}

// TestProgressFrameMarksEachStepsState covers what the display is for: telling finished from not
// started, and both from in flight.
//
// The one-line version listed what was running, so a scanner vanished the moment it finished and
// a reader watching could not tell work that had completed from work that had not been reached.
// Those call for different patience.
func TestProgressFrameMarksEachStepsState(t *testing.T) {
	ev := engine.ProgressEvent{
		Total: 9, Complete: 4, Failed: 2,
		Steps: []engine.ProgressStep{
			{Control: "sast", Scanner: "semgrep", Total: 1, Done: 1},
			{Control: "images", Scanner: "trivy", Total: 5, Done: 2, Failed: 2, Running: 1},
			{Control: "sca", Scanner: "trivy-fs", Total: 3},
		},
	}
	got := progressFrame(ev, tui.Painter{}, 0)

	if len(got) != 4 {
		t.Fatalf("want a headline and a row per step, got %d lines: %q", len(got), got)
	}
	if !strings.Contains(got[0], "Scanning 4/9") || !strings.Contains(got[0], "2 failed") {
		t.Errorf("headline = %q", got[0])
	}
	// Finished, and still on the screen rather than gone.
	if !strings.Contains(got[1], "✓") || !strings.Contains(got[1], "sast/semgrep") {
		t.Errorf("a finished step should be marked complete: %q", got[1])
	}
	// In flight, with its failures visible while the rest of it runs.
	if !strings.Contains(got[2], "▸") || !strings.Contains(got[2], "2/5, 2 failed") {
		t.Errorf("a running step should show where it has got to: %q", got[2])
	}
	// Planned and not started, which is not the same as finished with nothing to say.
	if !strings.Contains(got[3], "·") || !strings.Contains(got[3], "0/3") {
		t.Errorf("a step that has not begun should say so: %q", got[3])
	}
}

// TestProgressStepMarksSurviveWithoutColor: the mark carries the state and color reinforces it.
// The same output goes to terminals with no color, and to people who cannot tell these apart.
func TestProgressStepMarksSurviveWithoutColor(t *testing.T) {
	plain := tui.Painter{}
	for _, c := range []struct {
		name, want string
		step       engine.ProgressStep
	}{
		{"done", "✓", engine.ProgressStep{Control: "a", Scanner: "b", Total: 2, Done: 2}},
		{"failed", "✗", engine.ProgressStep{Control: "a", Scanner: "b", Total: 2, Done: 2, Failed: 2}},
		{"running", "▸", engine.ProgressStep{Control: "a", Scanner: "b", Total: 2, Running: 1}},
		{"pending", "·", engine.ProgressStep{Control: "a", Scanner: "b", Total: 2}},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := progressStepLine(c.step, plain); !strings.Contains(got, c.want) {
				t.Errorf("got %q, want the %s mark %q", got, c.name, c.want)
			}
		})
	}
}

// TestProgressFrameIsEmptyBeforeAnythingIsPlanned keeps the display off the screen until there is
// something to say about.
func TestProgressFrameIsEmptyBeforeAnythingIsPlanned(t *testing.T) {
	if got := progressFrame(engine.ProgressEvent{}, tui.Painter{}, 0); got != nil {
		t.Errorf("drew %q before the plan existed", got)
	}
}

// TestProgressShowsHowLongAStepHasBeenRunning answers the question a stalled-looking scan
// provokes: is this working?
//
// A step with one slow job produces no progress events at all while it runs, a scanner that
// creates a Job in a cluster and waits for it can take minutes. So a stuck run and a slow one look
// identical unless something keeps counting.
func TestProgressShowsHowLongAStepHasBeenRunning(t *testing.T) {
	ev := engine.ProgressEvent{
		Total: 2, Complete: 1,
		Steps: []engine.ProgressStep{
			{Control: "infrastructure", Scanner: "kube-bench-job", Total: 1, Running: 1,
				RunningSince: time.Now().Add(-95 * time.Second)},
			{Control: "sast", Scanner: "semgrep", Total: 1, Done: 1},
		},
	}
	got := progressFrame(ev, tui.Painter{}, 100*time.Second)

	if !strings.Contains(got[1], "1m35s") {
		t.Errorf("a running step should say how long it has been going: %q", got[1])
	}
	// A finished step has no clock to show: it is done, and a figure beside it reads as still
	// counting. Matched on the shape of an elapsed figure rather than on letters, since the
	// scanner names contain plenty of both.
	if elapsedFigure.MatchString(got[2]) {
		t.Errorf("a finished step should not carry an elapsed figure: %q", got[2])
	}
	if !strings.Contains(got[0], "1m40s") {
		t.Errorf("the headline should carry the run's own elapsed time: %q", got[0])
	}
}

func TestShortDuration(t *testing.T) {
	for _, c := range []struct {
		in   time.Duration
		want string
	}{
		{500 * time.Millisecond, "0s"},
		{45 * time.Second, "45s"},
		{95 * time.Second, "1m35s"},
		{62 * time.Minute, "62m00s"},
	} {
		// Minutes and seconds past a minute: "94s" makes a reader do arithmetic to decide
		// whether to keep waiting.
		if got := shortDuration(c.in); got != c.want {
			t.Errorf("shortDuration(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestProgressHeadlineStaysQuietForAFastRun: a scan that takes under a second has nothing to say
// about how long it took, and a "0s" beside the count is noise.
func TestProgressHeadlineStaysQuietForAFastRun(t *testing.T) {
	got := progressHeadline(engine.ProgressEvent{Total: 3, Complete: 1}, tui.Painter{}, 200*time.Millisecond)
	if strings.Contains(got, "0s") {
		t.Errorf("a sub-second run should not report its duration: %q", got)
	}
}

// elapsedFigure matches the durations the display renders, "45s", "1m35s", and nothing else.
var elapsedFigure = regexp.MustCompile(`\b\d+(m\d{2})?s\b`)

// TestProgressDoesNotTimeAJobThatJustStarted: a job that finishes quickly would flash a "0s" on
// its way past, and a figure that appears and disappears draws the eye to the steps needing it
// least.
func TestProgressDoesNotTimeAJobThatJustStarted(t *testing.T) {
	line := progressStepLine(engine.ProgressStep{
		Control: "sca", Scanner: "trivy-fs", Total: 3, Running: 1,
		RunningSince: time.Now(),
	}, tui.Painter{})
	if elapsedFigure.MatchString(line) {
		t.Errorf("a step that just started should not carry a clock: %q", line)
	}
}

// A frame is erased by moving the cursor up once per line it drew. That arithmetic is only true
// while every line occupies one row, and a terminal wraps a line it cannot fit onto two. The
// repaint then stops one row short, and `\033[2K` clears whatever is there, which is the reader's
// own output rather than anything this program wrote. Every repaint after it drifts one row
// further up the screen.
func TestAFrameNeverOccupiesMoreRowsThanItErases(t *testing.T) {
	const width = 40
	var buf bytes.Buffer
	p := &progressLine{w: &buf, columns: func() int { return width }}
	t.Cleanup(func() { active.Store(nil) })

	p.update(engine.ProgressEvent{
		Total: 9, Complete: 1,
		Steps: []engine.ProgressStep{
			{Control: "images", Scanner: "trivy", Total: 4, Done: 1, Running: 2},
			{Control: "infrastructure", Scanner: "kube-bench", Total: 5, Done: 0, Running: 1, Failed: 2},
		},
	})

	var rows int
	for _, line := range strings.Split(buf.String(), "\n") {
		rows++
		if cells := visibleCells(line); cells > width {
			t.Errorf("a line of %d cells wraps in a %d-column window: %q", cells, width, line)
		}
	}
	if rows != p.drawn {
		t.Errorf("drew %d rows and recorded %d, so the erase will land on the wrong lines", rows, p.drawn)
	}
}

// Nothing to measure against, so nothing is cut: a line is better long than truncated on a guess.
func TestAnUnknownWidthCutsNothing(t *testing.T) {
	var full, unknown bytes.Buffer
	ev := engine.ProgressEvent{
		Total: 9, Complete: 1,
		Steps: []engine.ProgressStep{{Control: "infrastructure", Scanner: "kube-bench", Total: 5, Running: 1}},
	}
	t.Cleanup(func() { active.Store(nil) })
	(&progressLine{w: &full, columns: func() int { return 200 }}).update(ev)
	(&progressLine{w: &unknown}).update(ev)
	if full.String() != unknown.String() {
		t.Errorf("a window too wide to matter and no window at all should render the same:\n%q\n%q",
			full.String(), unknown.String())
	}
}

// visibleCells counts the character cells a rendered line occupies, ignoring the escapes that
// carry color and the control sequence each line is prefixed with.
func visibleCells(line string) int {
	line = strings.TrimPrefix(line, "\r\033[2K")
	line = strings.TrimPrefix(line, "\r")
	return len([]rune(tui.Truncate(line, 1<<30))) - escapeRunes(line)
}

func escapeRunes(s string) int {
	var n int
	for _, m := range regexp.MustCompile("\x1b\\[[0-9;]*[a-zA-Z]").FindAllString(s, -1) {
		n += len([]rune(m))
	}
	return n
}

// countingWriter records how many Write calls it received, which is what decides whether a
// terminal can render half a frame.
// Not an embedded bytes.Buffer: that promotes WriteString, which io.WriteString prefers over
// Write, so every frame would arrive uncounted.
type countingWriter struct {
	buf    bytes.Buffer
	writes int
}

func (c *countingWriter) Write(b []byte) (int, error) {
	c.writes++
	return c.buf.Write(b)
}

// A frame the terminal receives in pieces is a frame it can draw in pieces, and the pieces are
// what a reader sees as flicker.
func TestAFrameReachesTheTerminalInOneWrite(t *testing.T) {
	var w countingWriter
	p := &progressLine{w: &w}
	t.Cleanup(func() { active.Store(nil) })

	p.update(engine.ProgressEvent{
		Total: 9, Complete: 1,
		Steps: []engine.ProgressStep{
			{Control: "images", Scanner: "trivy", Total: 4, Done: 1, Running: 2},
			{Control: "sca", Scanner: "trivy-fs", Total: 5, Done: 0, Running: 1},
		},
	})
	if w.writes != 1 {
		t.Errorf("a repaint took %d writes, so the terminal can render a frame it has only half received", w.writes)
	}
}

// The ticker repaints while a slow job runs. A frame that says exactly what is already on the
// terminal costs a write and buys nothing.
func TestARepaintWithNothingNewSaysNothing(t *testing.T) {
	var w countingWriter
	// Started just now, so the headline stays quiet and the frame carries no clock. A duration is
	// legitimately part of a frame, and two repaints either side of a second really are different.
	p := &progressLine{w: &w, start: time.Now()}
	t.Cleanup(func() { active.Store(nil) })

	ev := engine.ProgressEvent{
		Total: 9, Complete: 1,
		Steps: []engine.ProgressStep{{Control: "sca", Scanner: "trivy-fs", Total: 5, Running: 1}},
	}
	p.update(ev)
	first := w.writes
	p.update(ev)
	if w.writes != first {
		t.Errorf("an identical frame was written again (%d writes, want %d)", w.writes, first)
	}
}

// A row cleared and then filled is a row that was briefly empty, and because the old erase walked
// up a line at a time the emptiness climbed the block in front of whoever was watching. Content
// first, erase to the end of the line after it, so no row is ever blank between two states.
func TestARepaintNeverBlanksARowItIsAboutToFill(t *testing.T) {
	var buf bytes.Buffer
	p := &progressLine{w: &buf}
	t.Cleanup(func() { active.Store(nil) })

	p.update(engine.ProgressEvent{Total: 9, Complete: 1,
		Steps: []engine.ProgressStep{{Control: "sca", Scanner: "trivy-fs", Total: 5, Running: 1}}})
	buf.Reset()
	p.update(engine.ProgressEvent{Total: 9, Complete: 4,
		Steps: []engine.ProgressStep{{Control: "sca", Scanner: "trivy-fs", Total: 5, Done: 3, Running: 1}}})

	if out := buf.String(); strings.Contains(out, "\x1b[2K") {
		t.Errorf("a repaint blanks a whole row before rewriting it: %q", out)
	}
}

// A frame with fewer rows than the last leaves the surplus behind unless it clears them, and a
// stale row under a live frame reads as part of it.
func TestAShorterFrameClearsTheRowsItGaveUp(t *testing.T) {
	var buf bytes.Buffer
	p := &progressLine{w: &buf}
	t.Cleanup(func() { active.Store(nil) })

	p.update(engine.ProgressEvent{Total: 9, Complete: 1,
		Steps: []engine.ProgressStep{
			{Control: "images", Scanner: "trivy", Total: 4, Running: 2},
			{Control: "sca", Scanner: "trivy-fs", Total: 5, Running: 1},
		}})
	tall := p.drawn
	buf.Reset()
	p.update(engine.ProgressEvent{Total: 9, Complete: 9})

	if p.drawn >= tall {
		t.Fatalf("the frame did not shrink: %d rows then %d", tall, p.drawn)
	}
	if out := buf.String(); !strings.Contains(out, "\x1b[K") {
		t.Errorf("the rows it gave up were not cleared: %q", out)
	}
}
