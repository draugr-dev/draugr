package toolexec

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"
)

// A bound is a whole number of a binary unit. A decimal unit, a bare number and a fraction are
// refused, since each could mean two sizes, and 0 or nothing is no bound.
func TestAMemoryBoundIsAWholeNumberOfABinaryUnit(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]uint64{
		"512MiB": 512 << 20, "8GiB": 8 << 30, " 1TiB ": 1 << 40, "64KiB": 64 << 10,
		"": 0, "0": 0, "0GiB": 0,
	} {
		got, err := ParseMemoryBound(in)
		if err != nil || got.Bytes != want {
			t.Errorf("ParseMemoryBound(%q) = %+v, %v; want %d bytes", in, got, err, want)
		}
		if want > 0 && got.Text != strings.TrimSpace(in) {
			t.Errorf("ParseMemoryBound(%q) keeps the text %q, want it as written", in, got.Text)
		}
	}
	for _, in := range []string{"8G", "8GB", "8", "1.5GiB", "-1GiB", "8 GiB", "8gib", "99999999999999999999GiB", "17179869184GiB"} {
		if got, err := ParseMemoryBound(in); err == nil {
			t.Errorf("ParseMemoryBound(%q) = %+v, want it refused", in, got)
		}
	}
	_, err := ParseMemoryBound("8G")
	if err == nil || !strings.Contains(err.Error(), MemoryBoundAccepts) {
		t.Errorf("the refusal %v does not say what a bound takes", err)
	}
}

// A run's bound travels on its context, and a context without one has none.
func TestTheMemoryBoundTravelsOnTheContext(t *testing.T) {
	t.Parallel()
	if b := MemoryBoundOf(context.Background()); b.Bytes != 0 {
		t.Errorf("a context with no bound has %+v", b)
	}
	want := MemoryBound{Bytes: 1 << 30, Text: "1GiB"}
	if got := MemoryBoundOf(WithMemoryBound(context.Background(), want)); got != want {
		t.Errorf("MemoryBoundOf = %+v, want %+v", got, want)
	}
}

// A tool stopped at the bound says so, quoting the bound and naming the setting, in one clause, and
// is a kill to every caller that handles one. Without the watch's stop, or once the run was canceled,
// the error is left as it was.
func TestAToolStoppedAtTheBoundSaysWhy(t *testing.T) {
	t.Parallel()
	ctx := WithMemoryBound(context.Background(), MemoryBound{Bytes: 1 << 30, Text: "1GiB"})
	cause := errors.New("signal: killed")
	err := stopped(ctx, true, cause)
	for _, target := range []error{ErrOverMemoryBound, ErrKilled, cause} {
		if !errors.Is(err, target) {
			t.Errorf("%v is not %v", err, target)
		}
	}
	msg := err.Error()
	if !strings.Contains(msg, "1GiB") || !strings.Contains(msg, "--tool-memory") || strings.Contains(msg, ": ") {
		t.Errorf("%q should quote the bound and the flag in one clause", msg)
	}
	if got := explain(ctx, "tool", err); got != err {
		t.Errorf("explain rewrote the stop to %v", got)
	}
	if got := stopped(ctx, false, cause); got != cause {
		t.Errorf("a tool the watch did not stop became %v", got)
	}
	if got := stopped(ctx, true, nil); got != nil {
		t.Errorf("a tool that succeeded became %v", got)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if got := stopped(canceled, true, cause); got != cause {
		t.Errorf("a canceled run's kill became %v", got)
	}
}

// Stderr nobody reads is kept at both ends, the first lines and the last, as exec.Cmd.Output
// keeps it, with what fell between counted.
func TestUnreadStderrKeepsBothEnds(t *testing.T) {
	t.Parallel()
	h := &headTail{room: 4}
	for _, p := range []string{"ab", "cd", "ef", "gh", "ij", "kl"} {
		if n, err := h.Write([]byte(p)); n != len(p) || err != nil {
			t.Fatalf("Write(%q) = %d, %v", p, n, err)
		}
	}
	if got, want := string(h.Bytes()), "abcd\n... omitting 4 bytes ...\nijkl"; got != want {
		t.Errorf("kept %q, want %q", got, want)
	}

	short := &headTail{room: 4}
	_, _ = short.Write([]byte("abc"))
	_, _ = short.Write([]byte("de"))
	if got := string(short.Bytes()); got != "abcde" {
		t.Errorf("a stream within both ends kept %q, want all of it", got)
	}

	long := &headTail{room: 4}
	_, _ = long.Write([]byte("abcd"))
	_, _ = long.Write([]byte("ef"))
	_, _ = long.Write([]byte("0123456789"))
	if got, want := string(long.Bytes()), "abcd\n... omitting 8 bytes ...\n6789"; got != want {
		t.Errorf("a write longer than the room kept %q, want %q", got, want)
	}
}

// A failing tool's stderr still reaches the error, as it did through exec.Cmd.Output, both from a
// run that reads only stdout and from one whose output is combined.
func TestAFailingToolStillSaysWhy(t *testing.T) {
	t.Parallel()
	_, err := Run(context.Background(), "", []string{"sh", "-c", "echo 'nothing to scan here' >&2; exit 3"})
	if exit, ok := errors.AsType[*exec.ExitError](err); !ok || !bytes.Contains(exit.Stderr, []byte("nothing to scan")) {
		t.Fatalf("err = %v, want the exit with its stderr", err)
	}
	if !strings.Contains(err.Error(), "nothing to scan here") {
		t.Errorf("err = %v, want the tool's words", err)
	}
	out, err := RunCombined(context.Background(), "", []string{"sh", "-c", "echo out; echo err >&2"})
	if err != nil || !bytes.Contains(out, []byte("out")) || !bytes.Contains(out, []byte("err")) {
		t.Errorf("RunCombined = %q, %v; want both streams", out, err)
	}
	if _, err := Run(context.Background(), "", []string{"draugr-no-such-tool"}); !errors.Is(err, exec.ErrNotFound) {
		t.Errorf("a missing tool: %v, want exec.ErrNotFound", err)
	}
}
