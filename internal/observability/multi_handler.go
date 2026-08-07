package observability

import (
	"context"
	"errors"
	"log/slog"
)

// multiHandler sends every record to each of its handlers.
//
// It exists so a log file can be more verbose than the terminal above it. The terminal is a
// summary someone is reading now; the file is the thing they attach to a bug report, where the
// answer is more often in the part a terminal had no room for. One `--log-level` cannot serve
// both, so the destinations hold their own thresholds and this fans the record out.
//
// Each handler decides for itself whether a record is for it, which is what keeps the terminal's
// level honest: raising the file to trace must not put trace on screen.
type multiHandler struct{ handlers []slog.Handler }

// newMultiHandler returns a handler writing to all of hs. With one handler it returns that
// handler, so the ordinary single-destination case costs nothing.
func newMultiHandler(hs ...slog.Handler) slog.Handler {
	if len(hs) == 1 {
		return hs[0]
	}
	return multiHandler{handlers: hs}
}

// Enabled reports whether any destination wants this level.
//
// Any rather than all: slog skips building a record that nothing is enabled for, and asking for
// unanimity here would let the quietest destination silence the loudest.
func (m multiHandler) Enabled(ctx context.Context, l slog.Level) bool {
	for _, h := range m.handlers {
		if h.Enabled(ctx, l) {
			return true
		}
	}
	return false
}

// Handle writes the record to every destination that wants it.
//
// Every one is attempted even after a failure, and the errors are joined. A file that has filled
// its disk must not cost the reader the line on their terminal — the record is the same record,
// and the destinations do not depend on each other.
func (m multiHandler) Handle(ctx context.Context, r slog.Record) error {
	var errs []error
	for _, h := range m.handlers {
		if !h.Enabled(ctx, r.Level) {
			continue
		}
		if err := h.Handle(ctx, r.Clone()); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (m multiHandler) WithAttrs(as []slog.Attr) slog.Handler {
	out := make([]slog.Handler, len(m.handlers))
	for i, h := range m.handlers {
		out[i] = h.WithAttrs(as)
	}
	return multiHandler{handlers: out}
}

func (m multiHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return m
	}
	out := make([]slog.Handler, len(m.handlers))
	for i, h := range m.handlers {
		out[i] = h.WithGroup(name)
	}
	return multiHandler{handlers: out}
}
