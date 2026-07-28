package toolexec

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/draugr-dev/draugr/internal/observability"
)

func TestRunReturnsStdout(t *testing.T) {
	out, err := Run(context.Background(), "", []string{"echo", "hi"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := strings.TrimSpace(string(out)); got != "hi" {
		t.Errorf("stdout = %q, want %q", got, "hi")
	}
}

func TestRunUsesTheWorkingDirectory(t *testing.T) {
	// Not cosmetic: gosec resolves `./...` against the cwd, so a scanner handed the wrong
	// directory silently analyses the wrong tree rather than failing.
	dir := t.TempDir()
	out, err := Run(context.Background(), dir, []string{"pwd"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	got, err := filepath.EvalSymlinks(strings.TrimSpace(string(out)))
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	want, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	if got != want {
		t.Errorf("cwd = %q, want %q", got, want)
	}
}

func TestRunRejectsAnEmptyCommand(t *testing.T) {
	if _, err := Run(context.Background(), "", nil); err == nil {
		t.Error("want an error for an empty argv")
	}
}

func TestRunSurfacesTheExitError(t *testing.T) {
	// The caller has to be able to tell "the tool ran and said no" from "the tool is missing",
	// so the *exec.ExitError must survive rather than being flattened into a generic error.
	_, err := Run(context.Background(), "", []string{"false"})
	if err == nil {
		t.Fatal("want an error from a non-zero exit")
	}
	if _, ok := errors.AsType[*exec.ExitError](err); !ok {
		t.Errorf("err = %T, want *exec.ExitError", err)
	}
}

func TestRunReportsAMissingBinary(t *testing.T) {
	_, err := Run(context.Background(), "", []string{"draugr-no-such-tool-exists"})
	if err == nil {
		t.Fatal("want an error for a missing binary")
	}
	if _, ok := errors.AsType[*exec.ExitError](err); ok {
		t.Error("a missing binary should not look like a tool that ran and failed")
	}
}

func TestRunHonoursContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Run(ctx, "", []string{"sleep", "10"}); err == nil {
		t.Error("want an error when the context is already cancelled")
	}
}

// A scan used to be a black box: you could see that a tool failed but not what was run, where,
// for how long, or what the tool itself said. These assert the record that answers that.
func TestLogRecordsTheCommand(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(prev)

	log(context.Background(), []string{"trivy", "fs", "--quiet", "/src"}, "/work",
		time.Now().Add(-50*time.Millisecond), []byte("output"), nil)

	out := buf.String()
	for _, want := range []string{`tool=trivy`, `argv="trivy fs --quiet /src"`, `dir=/work`, "stdout_bytes=6", "duration="} {
		if !strings.Contains(out, want) {
			t.Errorf("debug record missing %s\n%s", want, out)
		}
	}
}

// The tool's own stderr is usually where the answer is, so trace must relay it — and debug must
// not, since it's verbose.
func TestLogRelaysStderrAtTraceOnly(t *testing.T) {
	run := func(level slog.Level) string {
		var buf bytes.Buffer
		prev := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: level})))
		defer slog.SetDefault(prev)
		err := &exec.ExitError{ProcessState: &os.ProcessState{}, Stderr: []byte("boom: bad flag")}
		log(context.Background(), []string{"gitleaks", "dir", "."}, "", time.Now(), nil, err)
		return buf.String()
	}
	if got := run(observability.LevelTrace); !strings.Contains(got, "boom: bad flag") {
		t.Errorf("trace should relay the tool's stderr:\n%s", got)
	}
	if got := run(slog.LevelDebug); strings.Contains(got, "boom: bad flag") {
		t.Errorf("debug should not include the tool's full stderr:\n%s", got)
	}
}
