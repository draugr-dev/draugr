package toolexec

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// hog is a tool whose group holds about 200 MiB for as long as the test waits: head writes it into
// a pipe and tail, which keeps the last ten lines and finds no newline, holds all of it until the
// stream ends, which sleep puts off.
var hog = []string{"sh", "-c", "{ head -c 209715200 /dev/zero; sleep 30; } | tail > /dev/null"}

// A tool whose group passes the bound is stopped, every process of it, and the error names the
// bound. The sum is across the group: no single process but tail holds the memory, and the shell
// that leads the group holds almost none.
func TestAToolPastItsBoundIsStopped(t *testing.T) {
	ctx := WithMemoryBound(context.Background(), MemoryBound{Bytes: 64 << 20, Text: "64MiB"})
	_, err := Run(ctx, "", hog)
	if !errors.Is(err, ErrOverMemoryBound) || !errors.Is(err, ErrKilled) {
		t.Fatalf("err = %v, want the tool stopped at its bound", err)
	}
	if !strings.Contains(err.Error(), "64MiB") {
		t.Errorf("err = %v, want the bound quoted", err)
	}

	_, _, err = RunWithStderr(ctx, "", hog, nil)
	if !errors.Is(err, ErrOverMemoryBound) {
		t.Errorf("RunWithStderr: err = %v, want the tool stopped at its bound", err)
	}
	_, err = RunCombined(ctx, "", hog)
	if !errors.Is(err, ErrOverMemoryBound) {
		t.Errorf("RunCombined: err = %v, want the tool stopped at its bound", err)
	}
}

// A tool within its bound runs to the end and returns what it wrote, and the watch ends with it.
func TestAToolWithinItsBoundRuns(t *testing.T) {
	ctx := WithMemoryBound(context.Background(), MemoryBound{Bytes: 1 << 30, Text: "1GiB"})
	out, err := Run(ctx, "", []string{"sh", "-c", "sleep 0.6; echo done"})
	if err != nil || strings.TrimSpace(string(out)) != "done" {
		t.Errorf("Run = %q, %v; want the tool's output", out, err)
	}
}

// Every tool is made the kernel's first choice over Draugr, whether or not a bound is set.
func TestEveryToolIsTheKernelsFirstChoice(t *testing.T) {
	t.Parallel()
	out, err := Run(context.Background(), "", []string{"sh", "-c", "sleep 0.3; cat /proc/$$/oom_score_adj"})
	if err != nil || strings.TrimSpace(string(out)) != killedFirst {
		t.Errorf("the tool's oom_score_adj = %q, %v; want %s", out, err, killedFirst)
	}
	preferKilled(context.Background(), -1) // a process that cannot exist: logged, not fatal
}

// A process's group and resident pages are read from its stat line, counting from the last
// parenthesis, since a command name may hold both a space and a parenthesis.
func TestTheStatLineIsReadPastTheCommandName(t *testing.T) {
	t.Parallel()
	line := "4242 (we ird) (name) S 1 4240 4240 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 100 1000000 777 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 3 0 0 0 0 0\n"
	pgrp, rss, ok := parseStat([]byte(line))
	if !ok || pgrp != 4240 || rss != 777 {
		t.Errorf("parseStat = %d, %d, %v; want 4240, 777", pgrp, rss, ok)
	}
	for _, bad := range []string{"no parenthesis", "1 (x) S 1", "1 (x) S 1 notanumber " + strings.Repeat("0 ", 20), "1 (x) S 1 5 " + strings.Repeat("0 ", 18) + "x"} {
		if _, _, ok := parseStat([]byte(bad)); ok {
			t.Errorf("parseStat(%q) read a line it should refuse", bad)
		}
	}
}

// A group's memory is the sum of its processes', and a process of another group, an entry that is
// no process and one whose stat cannot be read count for nothing.
func TestAGroupsMemoryIsTheSumOfItsProcesses(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	stat := func(pid, pgrp, rss string) {
		dir := filepath.Join(root, pid)
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatal(err)
		}
		fields := []string{pid, "(tool)", "S", "1", pgrp}
		for i := len(fields); i < 23; i++ {
			fields = append(fields, "0")
		}
		fields = append(fields, rss, "0")
		if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(strings.Join(fields, " ")), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	stat("100", "100", "10")
	stat("101", "100", "5")
	stat("200", "200", "1000")
	if err := os.MkdirAll(filepath.Join(root, "self"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "300"), 0o750); err != nil {
		t.Fatal(err)
	}
	page := uint64(os.Getpagesize()) // #nosec G115 -- a page size is positive
	used := groupMemory(root, map[int]*watched{100: {}})
	if used[100] != 15*page || len(used) != 1 {
		t.Errorf("groupMemory = %v, want group 100 at %d bytes and nothing else", used, 15*page)
	}
	if got := groupMemory(filepath.Join(root, "missing"), map[int]*watched{100: {}}); got != nil {
		t.Errorf("an unreadable process table gave %v", got)
	}
}
