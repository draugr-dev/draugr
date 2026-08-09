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

func TestRelayedStreamIsPassedWhole(t *testing.T) {
	// How much of a stream a reader sees is the log handler's decision. Clamping here would put
	// a ceiling on every destination, including --log-file, which exists to have none.
	var buf bytes.Buffer
	defer captureLogs(t, &buf, observability.LevelTrace)()

	big := strings.Repeat("x", 12000)
	log(t.Context(), []string{"tool"}, "", time.Now(), []byte(big), nil)
	if !strings.Contains(buf.String(), big) {
		t.Errorf("the stream reached the handler trimmed; it should arrive whole (%d bytes logged)", buf.Len())
	}
}

// captureLogs redirects slog to buf at the given level, restoring the previous default.
func captureLogs(t *testing.T, buf *bytes.Buffer, level slog.Level) func() {
	t.Helper()
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: level})))
	return func() { slog.SetDefault(prev) }
}

func notFound() error {
	return &exec.Error{Name: "x", Err: exec.ErrNotFound}
}

func TestExplainNamesTheFixForAMissingTool(t *testing.T) {
	// A missing binary is the one failure whose fix is a single command, and it is the likeliest
	// state for somebody on their first scan — Draugr installed, nothing else yet. The error said
	// only that the file was not found.
	//
	// Built from a synthetic not-found rather than by running a binary that is absent: whether
	// gitleaks is installed is a property of the machine, and a test that passes only on a clean
	// one is a test that stops running.
	err := explain("gitleaks", notFound())
	if !strings.Contains(err.Error(), "draugr tools install gitleaks") {
		t.Errorf("a tool Draugr distributes should name the command that installs it: %v", err)
	}
}

func TestExplainDoesNotOfferToInstallWhatWeDoNotShip(t *testing.T) {
	// Suggesting `tools install` for a tool Draugr does not distribute is worse than saying
	// nothing: the command runs, finds no such tool, and the reader concludes the fix is broken.
	err := explain("semgrep", notFound())
	if strings.Contains(err.Error(), "tools install") {
		t.Errorf("semgrep is not ours to install, so this must not suggest it: %v", err)
	}
	for _, want := range []string{"does not distribute", "draugr doctor"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("want %q in: %v", want, err)
		}
	}
}

func TestExplainLeavesOtherFailuresAlone(t *testing.T) {
	// A tool that ran and failed already explains itself on stderr; adding installation advice
	// there would be answering a question nobody asked.
	_, err := Run(t.Context(), "", []string{"sh", "-c", "echo 'bad flag' >&2; exit 2"})
	if err == nil {
		t.Fatal("want the non-zero exit as an error")
	}
	if strings.Contains(err.Error(), "tools install") || strings.Contains(err.Error(), "does not distribute") {
		t.Errorf("an exit failure is not a missing tool: %v", err)
	}
	if !strings.Contains(err.Error(), "bad flag") {
		t.Errorf("the tool's own first line should still travel: %v", err)
	}
}

// A tool's error runs from general to specific, and Draugr has already said which scanner, which
// control and which component. So what has to survive is the end of the chain — the part naming
// this failure rather than the tool's own account of what it was doing.
func TestFirstLineKeepsWhatIdentifiesTheFailure(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "a cache held by another scan",
			raw: "2026-08-09T14:06:25-05:00\tFATAL\tFatal error\trun error: image scan error: " +
				"scan error: unable to initialize a scan service: unable to initialize cache: " +
				"unable to initialize fs cache: cache may be in use by another process: timeout",
			want: "cache may be in use by another process: timeout",
		},
		{
			// The complaint this shape was reported for: the words naming the failure sat behind
			// four links of the tool restating that a scan was scanning.
			name: "an image that cannot be pulled",
			raw: "2026-08-09T15:37:55-05:00\tFATAL\tFatal error\trun error: image scan error: " +
				"scan error: unable to initialize a scan service: unable to find the specified " +
				`image "ghcr.io/draugr-dev/does-not-exist:9.9.9" in ["docker" "containerd" "podman" "remote"]`,
			want: "unable to find the specified image",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := firstLine(tc.raw)
			if !strings.Contains(got, tc.want) {
				t.Errorf("want %q in:\n%s", tc.want, got)
			}
			// The log preamble is the tool's, and it is the same on every failure it reports.
			for _, noise := range []string{"FATAL", "2026-08-09T"} {
				if strings.Contains(got, noise) {
					t.Errorf("the log preamble survived (%q):\n%s", noise, got)
				}
			}
			if n := len([]rune(got)); n > maxErrDetail {
				t.Errorf("shortened to %d runes, want at most %d", n, maxErrDetail)
			}
		})
	}
}

// Shortening has to be visible. A chain silently missing its opening reads as the whole message,
// and a reader chasing the missing context has nothing telling them there was any.
func TestFirstLineMarksWhatItDropped(t *testing.T) {
	t.Parallel()
	long := "run error: image scan error: scan error: " + strings.Repeat("wrapped: ", 12) + "the actual cause"
	got := firstLine(long)
	if !strings.HasPrefix(got, "… ") {
		t.Errorf("a shortened chain should say so:\n%s", got)
	}
	if !strings.HasSuffix(got, "the actual cause") {
		t.Errorf("the cause was lost:\n%s", got)
	}
}

// A message with no chain to cut on still has to fit, and the cause is still at the end.
func TestFirstLineElidesAnUnbreakableMessage(t *testing.T) {
	t.Parallel()
	got := firstLine("prefix " + strings.Repeat("x", maxErrDetail*2) + " the cause")
	if n := len([]rune(got)); n > maxErrDetail {
		t.Errorf("elided to %d runes, want at most %d", n, maxErrDetail)
	}
	if !strings.Contains(got, "the cause") {
		t.Errorf("the cause was lost:\n%s", got)
	}
}

// A line that is not a log line keeps all of itself: several tools write a bare sentence, and one
// containing a tab must not be mistaken for structured output.
func TestMessageOnlyStripsARealPreamble(t *testing.T) {
	t.Parallel()
	for _, line := range []string{
		"trivy: no such image",
		"could not open\tthe file",
	} {
		if got := message(line); got != line {
			t.Errorf("message(%q) = %q, want it unchanged", line, got)
		}
	}
	const logged = "2026-08-09T14:06:25-05:00\tFATAL\tsomething broke"
	if got := message(logged); got != "something broke" {
		t.Errorf("message(logged) = %q", got)
	}
}

// A byte offset can land inside a multi-byte character, and the replacement glyph lands in the
// one message somebody is reading closely.
func TestFirstLineClampsOnRunes(t *testing.T) {
	t.Parallel()
	line := strings.Repeat("é", maxErrDetail*2)
	got := firstLine(line)
	if strings.ContainsRune(got, '�') {
		t.Errorf("clamping split a character: %q", got)
	}
	if n := len([]rune(got)); n > maxErrDetail {
		t.Errorf("clamped to %d runes, want at most %d", n, maxErrDetail)
	}
}

// A line that fits is returned whole — no ellipsis on a message that was never shortened.
func TestFirstLineLeavesAShortLineAlone(t *testing.T) {
	t.Parallel()
	const short = "trivy: no such image"
	if got := firstLine(short); got != short {
		t.Errorf("firstLine(%q) = %q", short, got)
	}
}

// A tool that tried several ways to do one thing reports the attempt and then the reasons, and the
// reasons are the answer. Given only the first line, a reader is told an image could not be found
// in any of four places — not that the registry answered 401, which is the difference between
// checking the image name and logging in.
func TestFirstLineKeepsTheCausesOfAMultiError(t *testing.T) {
	t.Parallel()
	const trivy = "2026-08-09T15:51:30-05:00\tFATAL\tFatal error\trun error: image scan error: " +
		"unable to find the specified image \"reg.example.com/app:1\" in " +
		"[\"docker\" \"containerd\" \"podman\" \"remote\"]: 4 errors occurred:\n" +
		"\t* docker error: No such image: reg.example.com/app:1\n" +
		"\t* containerd error: connect: permission denied\n" +
		"\t* podman error: no podman socket found\n" +
		"\t* remote error: POST https://reg.example.com/oauth2/token: unexpected status code 401 Unauthorized"

	got := firstLine(trivy)
	if !strings.Contains(got, "401 Unauthorized") {
		t.Errorf("the cause was dropped:\n%s", got)
	}
	if n := len([]rune(got)); n > maxErrDetail {
		t.Errorf("shortened to %d runes, want at most %d", n, maxErrDetail)
	}
}

func TestWithCauses(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		first string
		rest  []string
		want  string
	}{
		{
			name:  "a line promising a list gets it",
			first: "2 errors occurred:",
			rest:  []string{"* first cause", "* second cause"},
			want:  "2 errors occurred: first cause; second cause",
		},
		{
			// No colon, no promise. Whatever follows is a separate message.
			name:  "a line promising nothing is left alone",
			first: "could not open the file",
			rest:  []string{"* not a cause of that"},
			want:  "could not open the file",
		},
		{
			// A tool printing usage after its error is not enumerating causes, and a report is
			// not the place for a usage screen.
			name:  "following lines that are not items are not folded in",
			first: "bad flag:",
			rest:  []string{"Usage: tool [options]", "* too late to count"},
			want:  "bad flag:",
		},
		{
			name:  "items stop where the list stops",
			first: "1 error occurred:",
			rest:  []string{"* the cause", "trailing prose"},
			want:  "1 error occurred: the cause",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := withCauses(tc.first, tc.rest); got != tc.want {
				t.Errorf("withCauses = %q, want %q", got, tc.want)
			}
		})
	}
}
