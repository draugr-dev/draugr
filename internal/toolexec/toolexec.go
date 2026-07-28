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
	"log/slog"
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
	if len(argv) == 0 {
		return nil, errors.New("empty command")
	}
	started := time.Now()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) //nolint:gosec // configured tool invocation // nosem: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	cmd.Dir = dir
	out, err := cmd.Output()
	log(ctx, argv, dir, started, out, err)
	return out, err
}

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
	slog.DebugContext(ctx, "ran external tool", attrs...)
}
