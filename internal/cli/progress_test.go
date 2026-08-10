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
