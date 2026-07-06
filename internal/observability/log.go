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
)

// LogOptions configures the structured logger.
type LogOptions struct {
	Level  string // debug | info | warn | error
	Format string // json | text
}

// NewLogger builds a slog.Logger writing to w according to opts.
// JSON is the default format because structured, machine-readable logs are the
// baseline for observability pipelines.
func NewLogger(w io.Writer, opts LogOptions) (*slog.Logger, error) {
	lvl, err := parseLevel(opts.Level)
	if err != nil {
		return nil, err
	}
	handlerOpts := &slog.HandlerOptions{Level: lvl}

	var h slog.Handler
	switch strings.ToLower(strings.TrimSpace(opts.Format)) {
	case "", "json":
		h = slog.NewJSONHandler(w, handlerOpts)
	case "text":
		h = slog.NewTextHandler(w, handlerOpts)
	default:
		return nil, fmt.Errorf("unknown log format %q (want json or text)", opts.Format)
	}
	return slog.New(h), nil
}

// SetDefault installs l as the process-wide default slog logger.
func SetDefault(l *slog.Logger) { slog.SetDefault(l) }

func parseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	}
	return 0, fmt.Errorf("unknown log level %q (want debug, info, warn, error)", s)
}
