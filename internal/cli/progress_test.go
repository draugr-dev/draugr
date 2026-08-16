package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/tui"
)

// A shorter line must not leave the tail of a longer one behind, or the display reads as two
// states at once — "scanning 9/11" followed by the debris of six scanner names.
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

// With no line drawn — piped output, --no-tips — the writer must not touch what it passes through.
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
// way out for a path that returned early. Erasing twice must be harmless — and the second must
// not emit a second row of blanks, which on a terminal is an empty line nobody asked for.
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
	got := progressFrame(ev, tui.Painter{})

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

// TestProgressStepMarksSurviveWithoutColour: the mark carries the state and colour reinforces it.
// The same output goes to terminals with no colour, and to people who cannot tell these apart.
func TestProgressStepMarksSurviveWithoutColour(t *testing.T) {
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
	if got := progressFrame(engine.ProgressEvent{}, tui.Painter{}); got != nil {
		t.Errorf("drew %q before the plan existed", got)
	}
}
