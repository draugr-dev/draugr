package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
)

func TestProgressText(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		ev   engine.ProgressEvent
		want string
	}{
		{
			// Nothing planned is not a run to describe.
			name: "no jobs draws nothing",
			ev:   engine.ProgressEvent{},
		},
		{
			name: "counts come first, because the question is whether it will finish",
			ev:   engine.ProgressEvent{Total: 11, Complete: 3, Running: []string{"sca/trivy-fs"}},
			want: "scanning 3/11 · sca/trivy-fs",
		},
		{
			// Six image scans are one kind of work, and naming each fills the line with the same
			// word while pushing off the job that is different.
			name: "repeats collapse into a count",
			ev: engine.ProgressEvent{Total: 8, Complete: 1, Running: []string{
				"images/trivy", "images/trivy", "images/trivy", "sca/trivy-fs",
			}},
			want: "scanning 1/8 · images/trivy ×3, sca/trivy-fs",
		},
		{
			// Between the last job finishing and the report being rendered.
			name: "nothing in flight still reports the count",
			ev:   engine.ProgressEvent{Total: 4, Complete: 4},
			want: "scanning 4/4",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := progressText(tc.ev); got != tc.want {
				t.Errorf("progressText = %q, want %q", got, tc.want)
			}
		})
	}
}

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

// TestProgressTextShowsFailuresAsTheyHappen: a run whose jobs are failing is one a reader may
// want to stop rather than wait out, and that choice is worth nothing once the report explains
// it — by then they have already waited.
func TestProgressTextShowsFailuresAsTheyHappen(t *testing.T) {
	for _, c := range []struct {
		name, want string
		ev         engine.ProgressEvent
	}{
		{
			name: "no failures says nothing about them",
			ev:   engine.ProgressEvent{Total: 17, Complete: 3, Running: []string{"sast/semgrep"}},
			want: "scanning 3/17 · sast/semgrep",
		},
		{
			name: "failures come before what is in flight",
			ev: engine.ProgressEvent{Total: 17, Complete: 9, Failed: 8,
				Running: []string{"sast/semgrep"}},
			want: "scanning 9/17 · 8 failed · sast/semgrep",
		},
		{
			name: "failures with nothing left running",
			ev:   engine.ProgressEvent{Total: 17, Complete: 17, Failed: 8},
			want: "scanning 17/17 · 8 failed",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := progressText(c.ev); got != c.want {
				t.Errorf("got  %q\nwant %q", got, c.want)
			}
		})
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
