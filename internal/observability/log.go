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
	"strings"

	"github.com/draugr-dev/draugr/pkg/tui"
)

// LogOptions configures the structured logger.
type LogOptions struct {
	Level  string // trace | debug | info | warn | error
	Format string // console | json | text
}

// NewLogger builds a slog.Logger writing to w according to opts.
//
// The default format is a human-readable console: Draugr is developer-first, so a person
// running it in a terminal should see legible, colorized logs, not JSON. Color is emitted only
// when w is an interactive terminal (and NO_COLOR is unset), so piped or redirected output
// stays plain text. Structured JSON is available on demand (Format "json") for CI and
// observability pipelines that consume machine-readable logs.
func NewLogger(w io.Writer, opts LogOptions) (*slog.Logger, error) {
	lvl, err := parseLevel(opts.Level)
	if err != nil {
		return nil, err
	}
	handlerOpts := &slog.HandlerOptions{Level: lvl}

	var h slog.Handler
	switch strings.ToLower(strings.TrimSpace(opts.Format)) {
	case "", "console":
		h = newConsoleHandler(w, handlerOpts, tui.ColorEnabled(w))
	case "json":
		h = slog.NewJSONHandler(w, handlerOpts)
	case "text":
		h = slog.NewTextHandler(w, handlerOpts)
	default:
		return nil, fmt.Errorf("unknown log format %q (want console, json, or text)", opts.Format)
	}
	return slog.New(h), nil
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
