package toolexec

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// When memory runs out, the kernel kills a process to free some: the one it scores highest, which
// is mostly the one using the most. A scan is Draugr and the tools it runs, and Draugr holds every
// result the finished controls returned. Killed, it takes them all with it, where a killed tool
// fails one control and the rest are reported. So every tool Draugr starts on Linux is made the
// kernel's first choice over Draugr (preferKilled).
//
// That covers the kernel choosing. It does not cover whoever set the limit acting on the kill: a
// systemd unit left at OOMPolicy=stop, the default, stops every process in it once the kernel has
// killed one, Draugr included. A memory bound (WithMemoryBound) is how a scan keeps a tool under a
// limit like that one. Draugr watches each tool's resident memory, with the processes it starts,
// and stops the tool itself once it passes the bound, before the limit is reached.

// MemoryBound is the most resident memory one tool run may use, with the processes it starts,
// before Draugr stops it.
type MemoryBound struct {
	// Bytes is the bound. Zero means none.
	Bytes uint64
	// Text is the bound as it was written, such as 8GiB, which an error quotes.
	Text string
}

// memoryUnits are the suffixes a bound takes, and the bytes each stands for.
var memoryUnits = map[string]uint64{"KiB": 1 << 10, "MiB": 1 << 20, "GiB": 1 << 30, "TiB": 1 << 40}

// memoryText is a bound as ParseMemoryBound reads it: a whole number and a unit.
var memoryText = regexp.MustCompile(`^([0-9]+)(KiB|MiB|GiB|TiB)$`)

// MemoryBoundAccepts is what a memory bound takes, in the words a refusal of one uses.
const MemoryBoundAccepts = "a size such as 512MiB or 8GiB, or 0 for none"

// ParseMemoryBound reads a bound written as a whole number of KiB, MiB, GiB or TiB, such as 8GiB.
// "0" and "" mean no bound. The units are binary only: "8G" and "8GB" are refused rather than read
// as one of the two sizes each could mean.
func ParseMemoryBound(s string) (MemoryBound, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "0" {
		return MemoryBound{}, nil
	}
	m := memoryText.FindStringSubmatch(s)
	if m == nil {
		return MemoryBound{}, fmt.Errorf("expected %s, got %q", MemoryBoundAccepts, s)
	}
	n, err := strconv.ParseUint(m[1], 10, 64)
	unit := memoryUnits[m[2]]
	if err != nil || n > ^uint64(0)/unit {
		return MemoryBound{}, fmt.Errorf("%q is larger than any machine's memory", s)
	}
	if n == 0 {
		return MemoryBound{}, nil
	}
	return MemoryBound{Bytes: n * unit, Text: s}, nil
}

// memoryBoundKey is the context key under which a run's memory bound travels.
type memoryBoundKey struct{}

// WithMemoryBound returns a context under which every tool run is stopped once its resident
// memory, with that of the processes it starts, passes b. A zero bound is none.
//
// It is a choice for the operator, off by default: with no bound a tool may use all the memory the
// machine gives it, and the kernel kills it only when that runs out. A bound is for a run inside a
// limit whose owner ends every process once one is killed, and for a run that should leave the rest
// of the machine its memory.
func WithMemoryBound(ctx context.Context, b MemoryBound) context.Context {
	return context.WithValue(ctx, memoryBoundKey{}, b)
}

// MemoryBoundOf is the bound tool runs under ctx are held to, zero where there is none.
func MemoryBoundOf(ctx context.Context) MemoryBound {
	b, _ := ctx.Value(memoryBoundKey{}).(MemoryBound)
	return b
}

// CanBoundMemory reports whether this platform enforces a memory bound. Where it does not, a run
// given one says so and runs its tools unbounded.
func CanBoundMemory() bool { return canWatch }

// ErrOverMemoryBound is a tool Draugr stopped because it used more memory than the run's bound
// (WithMemoryBound). It is ErrKilled too: the tool was ended by SIGKILL for its memory, and what a
// caller does about a kill, such as naming what went unread, it does about this.
var ErrOverMemoryBound = errors.New("used more memory than its bound")

// overBoundError is a tool stopped at the bound: one clause, because a report shows a failure's
// last clause as its reason.
type overBoundError struct {
	bound MemoryBound
	err   error
}

func (e overBoundError) Error() string {
	return fmt.Sprintf("used more than the %s of memory --tool-memory allows, so Draugr stopped it", e.bound.Text)
}

func (e overBoundError) Unwrap() []error { return []error{ErrOverMemoryBound, ErrKilled, e.err} }

// wait starts cmd and waits for it, as cmd.Run does, with the tool made the kernel's first choice
// when memory runs out and, under a bound, watched and stopped once it passes it. over says the
// watch stopped it.
func wait(ctx context.Context, cmd *exec.Cmd) (over bool, err error) {
	if err := cmd.Start(); err != nil {
		return false, err
	}
	pid := cmd.Process.Pid
	preferKilled(ctx, pid)
	stop := func() bool { return false }
	if b := MemoryBoundOf(ctx); b.Bytes > 0 && canWatch {
		stop = watch(pid, b.Bytes)
	}
	err = cmd.Wait()
	return stop(), err
}

// output is cmd.Output run through wait: stdout returned, and, where the caller set no Stderr,
// the start and end of stderr kept in the exit error as Output keeps them.
func output(ctx context.Context, cmd *exec.Cmd) (over bool, out []byte, err error) {
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	var stderr *headTail
	if cmd.Stderr == nil {
		stderr = &headTail{room: stderrKept}
		cmd.Stderr = stderr
	}
	over, err = wait(ctx, cmd)
	if exit, ok := errors.AsType[*exec.ExitError](err); ok && stderr != nil {
		exit.Stderr = stderr.Bytes()
	}
	return over, stdout.Bytes(), err
}

// stopped is err as the watch's stop explains it, where the watch stopped the tool and the run was
// not canceled meanwhile.
func stopped(ctx context.Context, over bool, err error) error {
	if !over || err == nil || ctx.Err() != nil {
		return err
	}
	return overBoundError{bound: MemoryBoundOf(ctx), err: err}
}

// stderrKept is how much of each end of stderr a run keeps where the caller does not read the
// stream, the room exec.Cmd.Output gives it. explain reads the first lines and the last.
const stderrKept = 32 << 10

// headTail keeps the first room bytes written to it and the last room, and counts what fell
// between, as exec.Cmd.Output does with stderr.
type headTail struct {
	room    int
	head    []byte
	tail    []byte
	dropped int64
}

func (h *headTail) Write(p []byte) (int, error) {
	n := len(p)
	if fill := min(h.room-len(h.head), len(p)); fill > 0 {
		h.head = append(h.head, p[:fill]...)
		p = p[fill:]
	}
	if len(p) == 0 {
		return n, nil
	}
	if len(p) >= h.room {
		h.dropped += int64(len(h.tail) + len(p) - h.room)
		h.tail = append(h.tail[:0], p[len(p)-h.room:]...)
		return n, nil
	}
	// The tail grows to twice its room before the oldest part is cut, so a tool writing many short
	// lines costs one copy of the room per room written rather than one per line.
	h.tail = append(h.tail, p...)
	if over := len(h.tail) - h.room; over >= h.room {
		h.dropped += int64(over)
		h.tail = append(h.tail[:0], h.tail[over:]...)
	}
	return n, nil
}

// Bytes is what was kept, with a line saying how much was left out between the two ends.
func (h *headTail) Bytes() []byte {
	tail := h.tail
	dropped := h.dropped
	if over := len(tail) - h.room; over > 0 {
		tail, dropped = tail[over:], dropped+int64(over)
	}
	out := append([]byte{}, h.head...)
	if dropped > 0 {
		out = fmt.Appendf(out, "\n... omitting %d bytes ...\n", dropped)
	}
	return append(out, tail...)
}
