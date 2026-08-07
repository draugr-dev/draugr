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

// Without this record a scan is a black box: you can see that a tool failed, but not what was
// run, where, for how long, or what the tool itself said. These assert the record that answers
// those.
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

// `exit status 1` on its own is what reaches the terminal, the report and the PR comment. The
// tool almost always said why on stderr; that line has to travel with the error.
func TestRunPutsTheToolsOwnMessageInTheError(t *testing.T) {
	_, err := Run(context.Background(), "", []string{"sh", "-c", "echo 'could not read templates' >&2; exit 1"})
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "could not read templates") {
		t.Errorf("the tool's own explanation should be in the error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "exit status 1") {
		t.Errorf("the exit status should survive too, got: %v", err)
	}
}

// Some tools print a usage screen on failure. A report is not the place for it.
func TestRunClampsAVerboseComplaint(t *testing.T) {
	long := strings.Repeat("x", 400)
	_, err := Run(context.Background(), "", []string{"sh", "-c", "echo '" + long + "' >&2; exit 2"})
	if err == nil {
		t.Fatal("expected an error")
	}
	if len(err.Error()) > 300 {
		t.Errorf("error should be clamped, got %d chars", len(err.Error()))
	}
	if !strings.Contains(err.Error(), "…") {
		t.Errorf("a clamped message should say it was clamped, got: %v", err)
	}
}

// A tool that fails silently leaves nothing to add; the exit status is all there is.
func TestRunWithNoStderrKeepsTheBareError(t *testing.T) {
	_, err := Run(context.Background(), "", []string{"false"})
	if err == nil || !strings.Contains(err.Error(), "exit status 1") {
		t.Errorf("want the bare exit status, got %v", err)
	}
}

// A tool that shells out to another tool cannot be told which target to use through argv —
// kube-bench invokes kubectl, which reads its cluster from the environment.
func TestRunWithEnvReachesTheChild(t *testing.T) {
	out, err := RunWithEnv(context.Background(), "", []string{"sh", "-c", "printf %s \"$DRAUGR_TEST_VAR\""},
		[]string{"DRAUGR_TEST_VAR=hello"})
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "hello" {
		t.Errorf("child saw %q, want hello", out)
	}
}

// The parent's environment still applies; the override is layered over it, not a replacement.
func TestRunWithEnvKeepsTheParentEnvironment(t *testing.T) {
	t.Setenv("DRAUGR_PARENT_VAR", "inherited")
	out, err := RunWithEnv(context.Background(), "",
		[]string{"sh", "-c", "printf %s \"$DRAUGR_PARENT_VAR-$DRAUGR_CHILD_VAR\""},
		[]string{"DRAUGR_CHILD_VAR=added"})
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "inherited-added" {
		t.Errorf("child env = %q, want inherited-added", out)
	}
}

func TestRunCombinedReadsStderrToo(t *testing.T) {
	// The case it exists for: a tool asked a question that answers on stderr. Nuclei prints
	// `-templates-version` entirely there and nothing to stdout, so reading stdout alone
	// reported no templates however many were installed.
	out, err := RunCombined(context.Background(), "", []string{"sh", "-c", "echo answer >&2"})
	if err != nil {
		t.Fatalf("RunCombined: %v", err)
	}
	if !strings.Contains(string(out), "answer") {
		t.Errorf("stderr should be in the output, got %q", out)
	}
}

func TestRunDoesNotReadStderr(t *testing.T) {
	// The reason RunCombined is separate: a scanner's stdout is a report to be parsed, and
	// folding stderr into it would corrupt the parse for every tool that logs while it works.
	out, err := Run(context.Background(), "", []string{"sh", "-c", "echo noise >&2; echo report"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if strings.Contains(string(out), "noise") {
		t.Errorf("stderr must not reach a parsed report: %q", out)
	}
	if !strings.Contains(string(out), "report") {
		t.Errorf("stdout missing: %q", out)
	}
}

func TestRunCombinedRejectsAnEmptyCommand(t *testing.T) {
	if _, err := RunCombined(context.Background(), "", nil); err == nil {
		t.Error("expected an error for an empty command")
	}
}

func TestRunCombinedUsesTheWorkingDirectory(t *testing.T) {
	dir := t.TempDir()
	out, err := RunCombined(context.Background(), dir, []string{"pwd"})
	if err != nil {
		t.Fatalf("RunCombined: %v", err)
	}
	if got := strings.TrimSpace(string(out)); !strings.HasSuffix(got, filepath.Base(dir)) {
		t.Errorf("ran in %q, want %q", got, dir)
	}
}

func TestRunCombinedSurfacesAFailure(t *testing.T) {
	if _, err := RunCombined(context.Background(), "", []string{"sh", "-c", "exit 3"}); err == nil {
		t.Error("expected the non-zero exit to surface")
	}
}

func TestLogRelaysStdoutAtTrace(t *testing.T) {
	// Not every tool explains itself on stderr, and ours are configured not to fail on findings
	// — so err == nil is the normal path, and a tool that produced nothing useful looked
	// identical to one that found nothing.
	var buf bytes.Buffer
	restore := captureLogs(t, &buf, observability.LevelTrace)
	defer restore()

	// The marker is assembled by the command rather than written in it: argv is logged at debug,
	// so anything typed into the command appears whether stdout was relayed or not.
	if _, err := Run(context.Background(), "", []string{"sh", "-c", `printf "REPORT%s" 42`}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !strings.Contains(buf.String(), "REPORT42") {
		t.Errorf("stdout should be relayed at trace:\n%s", buf.String())
	}
}

func TestLogDoesNotRelayStdoutAboveTrace(t *testing.T) {
	// A scanner's stdout is its whole report. At debug it must stay a byte count.
	var buf bytes.Buffer
	restore := captureLogs(t, &buf, slog.LevelDebug)
	defer restore()

	if _, err := Run(context.Background(), "", []string{"sh", "-c", `printf "REPORT%s" 42`}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if strings.Contains(buf.String(), "REPORT42") {
		t.Errorf("debug should say how much, not what:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "stdout_bytes") {
		t.Errorf("the byte count should still be there:\n%s", buf.String())
	}
}

func TestClampForLogTrimsAHugeReport(t *testing.T) {
	// A SARIF report can be megabytes; a log line that large is scrolled past, or makes the file
	// too big to open.
	got := clampForLog(strings.Repeat("x", maxTraceOutput+500))
	if len(got) >= maxTraceOutput+500 {
		t.Errorf("not trimmed: %d bytes", len(got))
	}
	if !strings.Contains(got, "500 bytes truncated") {
		t.Errorf("it should say what was left out: %q", got[len(got)-80:])
	}
	if short := clampForLog("small"); short != "small" {
		t.Errorf("a short stream should pass through, got %q", short)
	}
}

// captureLogs redirects slog to buf at the given level, restoring the previous default.
func captureLogs(t *testing.T, buf *bytes.Buffer, level slog.Level) func() {
	t.Helper()
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: level})))
	return func() { slog.SetDefault(prev) }
}
