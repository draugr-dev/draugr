// Package observability provides Draugr's logging and telemetry foundations:
// structured logging via log/slog and distributed tracing via OpenTelemetry.
//
// Security note: logs and spans must never carry secrets (tokens, credentials,
// full request/response bodies). Scanners and plugins are responsible for
// redacting sensitive values before they reach a logger or span attribute.
package observability

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/draugr-dev/draugr/pkg/tui"
)

// LogOptions configures the structured logger.
type LogOptions struct {
	Level  string // trace | debug | info | warn | error
	Format string // console | json | text
	// File, when set, receives a second copy of every record at trace level, unclamped.
	//
	// Not a redirect and not another --log-level: the terminal keeps whatever level was asked
	// for, and the file gets everything. Trace output is larger than a terminal's scrollback and
	// is what someone attaches to a bug report, so the two destinations want different amounts
	// and neither should have to lose for the other to win.
	File string
}

// NewLogger builds a slog.Logger writing to w according to opts.
//
// The default format is a human-readable console: Draugr is developer-first, so a person
// running it in a terminal should see legible, colorized logs, not JSON. Color is emitted only
// when w is an interactive terminal (and NO_COLOR is unset), so piped or redirected output
// stays plain text. Structured JSON is available on demand (Format "json") for CI and
// observability pipelines that consume machine-readable logs.
func NewLogger(w io.Writer, opts LogOptions) (*slog.Logger, func() error, error) {
	lvl, err := parseLevel(opts.Level)
	if err != nil {
		return nil, nil, err
	}
	format := strings.ToLower(strings.TrimSpace(opts.Format))
	term, err := handlerFor(format, w, &slog.HandlerOptions{Level: lvl}, tui.ColorEnabled(w), maxTerminalValue)
	if err != nil {
		return nil, nil, err
	}
	if opts.File == "" {
		return slog.New(term), func() error { return nil }, nil
	}

	// Appended rather than truncated: a second run is usually the one that reproduces the
	// problem, and losing the first would be losing the comparison. 0600 because a trace log
	// holds whatever the scanners printed, and one of them may have printed something the
	// operator would not choose to share with every account on the machine.
	f, err := os.OpenFile(opts.File, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		// Named, and fatal. A log file silently not written is the class of failure this project
		// refuses: the run would look normal and the evidence someone asked for would not exist.
		return nil, nil, fmt.Errorf("open --log-file %q: %w", opts.File, err)
	}
	// Never coloured and never clamped: a file is not a terminal, and the reason to write one is
	// to keep the part a terminal had no room for.
	file, err := handlerFor(format, f, &slog.HandlerOptions{Level: LevelTrace}, false, 0)
	if err != nil {
		_ = f.Close()
		return nil, nil, err
	}
	return slog.New(newMultiHandler(term, file)), f.Close, nil
}

// maxTerminalValue clamps a rendered value on a terminal. A SARIF report can be megabytes, and a
// log line that large is not read — it is scrolled past. --log-file has no such ceiling.
const maxTerminalValue = 4000

// handlerFor builds one destination's handler.
func handlerFor(format string, w io.Writer, opts *slog.HandlerOptions, color bool, maxValue int) (slog.Handler, error) {
	switch format {
	case "", "console":
		return newConsoleHandler(w, opts, color, maxValue), nil
	case "json":
		return slog.NewJSONHandler(w, opts), nil
	case "text":
		return slog.NewTextHandler(w, opts), nil
	}
	return nil, fmt.Errorf("unknown log format %q (want console, json, or text)", format)
}

// SetDefault installs l as the process-wide default slog logger.
func SetDefault(l *slog.Logger) { slog.SetDefault(l) }

// LevelTrace is below debug: it relays what Draugr's dependencies print, which is verbose and
// only wanted when debug hasn't answered the question.
const LevelTrace = slog.LevelDebug - 4

func parseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "info":
		return slog.LevelInfo, nil
	case "trace":
		return LevelTrace, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	}
	return 0, fmt.Errorf("unknown log level %q (want trace, debug, info, warn, error)", s)
}
