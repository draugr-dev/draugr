// Package toolexec runs the external tools Draugr orchestrates, and reports what it ran.
//
// It exists so that every external invocation — scanners today, SBOM generation and whatever
// comes next — narrates itself the same way. Without that, a run is a black box: you can see
// that something failed but not the command, the directory, how long it took, or what the tool
// itself said about it.
package toolexec

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/draugr-dev/draugr/internal/observability"
)

// Run executes argv and returns its stdout. dir sets the working directory; empty inherits the
// current one. Some tools resolve their target relative to the working directory rather than
// from an argument (gosec loads Go packages via `./...`), so for those the checkout has to be
// the cwd, not just a path passed in.
//
// No shell is involved — exec.CommandContext, not "sh -c" — and argv is built from typed config
// by the caller, never from user shell input.
func Run(ctx context.Context, dir string, argv []string) ([]byte, error) {
	return RunWithEnv(ctx, dir, argv, nil)
}

// RunCombined is Run capturing stderr alongside stdout.
//
// For a tool asked a question rather than told to scan. Several write their answer to stderr —
// `nuclei -templates-version` prints its whole reply there and nothing at all to stdout — so a
// caller reading only stdout gets an empty string and concludes the wrong thing. Keeping this
// separate from Run is deliberate: a scanner's stdout is a report to be parsed, and folding
// stderr into it would corrupt the parse for every tool that logs while it works.
func RunCombined(ctx context.Context, dir string, argv []string) ([]byte, error) {
	if len(argv) == 0 {
		return nil, errors.New("empty command")
	}
	started := time.Now()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) // #nosec G204 -- configured tool invocation // nosem: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	log(ctx, argv, dir, started, out, err)
	return out, explain(err)
}

// RunWithEnv is Run with extra environment variables layered over the parent's, each "K=V".
//
// A tool that shells out to another tool cannot be told which context to work in through argv —
// kube-bench invokes kubectl itself, and kubectl takes its cluster from the environment. This is
// how a scanner points such a tool at the right target rather than whatever the machine happens
// to be configured for.
func RunWithEnv(ctx context.Context, dir string, argv, env []string) ([]byte, error) {
	if len(argv) == 0 {
		return nil, errors.New("empty command")
	}
	started := time.Now()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) // #nosec G204 -- configured tool invocation // nosem: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	cmd.Dir = dir
	if len(env) > 0 {
		cmd.Env = append(os.Environ(), env...)
	}
	out, err := cmd.Output()
	log(ctx, argv, dir, started, out, err)
	return out, explain(err)
}

// explain puts the tool's own first words into the error.
//
// `exit status 1` tells a reader nothing they can act on, and it is what reaches the terminal,
// the HTML report and the pull-request comment. The tool almost always said why on stderr —
// `--log-level trace` relays all of it, but nobody reaches for that before they know something
// is worth investigating. So the first line travels with the error, where it is seen.
//
// One line, clamped: some tools print a usage screen on failure, and a report is not the place
// for it. Trace still has the rest.
func explain(err error) error {
	exit, ok := errors.AsType[*exec.ExitError](err)
	if !ok || len(exit.Stderr) == 0 {
		return err
	}
	detail := firstLine(string(exit.Stderr))
	if detail == "" {
		return err
	}
	// No tool name here: every caller already wraps this with one ("run nuclei: …"), and
	// repeating it reads as a stutter in the place a reader is trying to parse quickly.
	return fmt.Errorf("%w: %s", err, detail)
}

// firstLine returns the first non-blank line of a tool's stderr, clamped.
func firstLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if len(line) > maxErrDetail {
			line = strings.TrimSpace(line[:maxErrDetail-1]) + "…"
		}
		return line
	}
	return ""
}

// maxErrDetail keeps a tool's complaint to something that fits on a terminal line.
const maxErrDetail = 160

// log records what was actually run. At trace level the tool's own stderr is relayed, which is
// usually where the answer is when something has gone wrong.
func log(ctx context.Context, argv []string, dir string, started time.Time, out []byte, err error) {
	attrs := []any{
		"tool", argv[0],
		"argv", strings.Join(argv, " "),
		"duration", time.Since(started).Round(time.Millisecond).String(),
		"stdout_bytes", len(out),
	}
	if dir != "" {
		attrs = append(attrs, "dir", dir)
	}
	if exit, ok := errors.AsType[*exec.ExitError](err); ok {
		attrs = append(attrs, "exit_code", exit.ExitCode())
		// Output() captures the tool's stderr here; it explains failures far better than we can.
		if len(exit.Stderr) > 0 {
			slog.Log(ctx, observability.LevelTrace, "tool stderr",
				"tool", argv[0], "stderr", string(exit.Stderr))
		}
	} else if err != nil {
		attrs = append(attrs, "error", err.Error())
	}
	// Stdout too, and on success as well as failure. Not every tool explains itself on stderr,
	// and ours are deliberately configured not to fail on findings (--exit-code 0, -no-fail) —
	// so err == nil is the normal path, and a tool producing an empty report because it was
	// misconfigured looks exactly like one that found nothing. Trace is the level where a reader
	// has asked for everything; holding half of it back leaves them reproducing the run by
	// hand.
	if len(out) > 0 {
		slog.Log(ctx, observability.LevelTrace, "tool stdout",
			"tool", argv[0], "stdout", string(out))
	}
	slog.DebugContext(ctx, "ran external tool", attrs...)
}

// The relayed stream is passed whole. How much of it a reader sees is the log handler's decision,
// not this one's: a terminal clamps it to something readable, and --log-file keeps all of it.
// Clamping here would put a ceiling on both, and the file exists to have no ceiling.
