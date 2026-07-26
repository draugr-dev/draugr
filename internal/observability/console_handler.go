package observability

import (
	"context"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"sync"

	"github.com/draugr-dev/draugr/pkg/tui"
)

// consoleHandler renders log records as compact, human-readable lines:
//
//	15:04:05 LEVEL  message key=value key2="a value"
//
// It colorizes the level and dims timestamps and attribute keys when color is enabled. It's a
// deliberately small handler for interactive use; JSON remains the format for machine and
// observability pipelines.
type consoleHandler struct {
	opts         slog.HandlerOptions
	mu           *sync.Mutex
	w            io.Writer
	paint        tui.Painter
	groupPrefix  string
	preformatted []byte // attributes accumulated via WithAttrs, already rendered
}

// newConsoleHandler builds a consoleHandler writing to w. color is decided by the caller (see
// tui.ColorEnabled) so it stays testable without a real terminal.
func newConsoleHandler(w io.Writer, opts *slog.HandlerOptions, color bool) *consoleHandler {
	painter := tui.Plain()
	if color {
		painter = tui.Colored()
	}
	h := &consoleHandler{mu: &sync.Mutex{}, w: w, paint: painter}
	if opts != nil {
		h.opts = *opts
	}
	return h
}

func (h *consoleHandler) Enabled(_ context.Context, level slog.Level) bool {
	threshold := slog.LevelInfo
	if h.opts.Level != nil {
		threshold = h.opts.Level.Level()
	}
	return level >= threshold
}

func (h *consoleHandler) Handle(_ context.Context, r slog.Record) error {
	buf := make([]byte, 0, 128)

	if !r.Time.IsZero() {
		buf = h.paint.Append(buf, tui.StyleMuted, r.Time.Format("15:04:05"))
		buf = append(buf, ' ')
	}
	buf = h.paint.Append(buf, levelColor(r.Level), levelLabel(r.Level))
	buf = append(buf, ' ', ' ')
	buf = append(buf, r.Message...)

	buf = append(buf, h.preformatted...)
	r.Attrs(func(a slog.Attr) bool {
		buf = h.appendAttr(buf, a, h.groupPrefix)
		return true
	})
	buf = append(buf, '\n')

	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := h.w.Write(buf)
	return err
}

func (h *consoleHandler) WithAttrs(as []slog.Attr) slog.Handler {
	if len(as) == 0 {
		return h
	}
	h2 := h.clone()
	for _, a := range as {
		h2.preformatted = h2.appendAttr(h2.preformatted, a, h.groupPrefix)
	}
	return h2
}

func (h *consoleHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	h2 := h.clone()
	h2.groupPrefix = h.groupPrefix + name + "."
	return h2
}

func (h *consoleHandler) clone() *consoleHandler {
	pf := make([]byte, len(h.preformatted))
	copy(pf, h.preformatted)
	return &consoleHandler{
		opts:         h.opts,
		mu:           h.mu,
		w:            h.w,
		paint:        h.paint,
		groupPrefix:  h.groupPrefix,
		preformatted: pf,
	}
}

// appendAttr renders " key=value" (key dimmed when colored), recursing into groups. Values
// containing whitespace or quotes are quoted so each record stays on a single line.
func (h *consoleHandler) appendAttr(buf []byte, a slog.Attr, prefix string) []byte {
	a.Value = a.Value.Resolve()
	if a.Equal(slog.Attr{}) {
		return buf
	}
	if a.Value.Kind() == slog.KindGroup {
		gs := a.Value.Group()
		if len(gs) == 0 {
			return buf
		}
		np := prefix
		if a.Key != "" {
			np = prefix + a.Key + "."
		}
		for _, ga := range gs {
			buf = h.appendAttr(buf, ga, np)
		}
		return buf
	}
	buf = append(buf, ' ')
	buf = h.paint.Append(buf, tui.StyleMuted, prefix+a.Key+"=")
	val := a.Value.String()
	if strings.ContainsAny(val, " \t\n\"") {
		val = strconv.Quote(val)
	}
	return append(buf, val...)
}

// levelLabel returns a fixed-width (5-char) label so records align in a column.
func levelLabel(l slog.Level) string {
	switch {
	case l < slog.LevelDebug:
		return "TRACE"
	case l < slog.LevelInfo:
		return "DEBUG"
	case l < slog.LevelWarn:
		return "INFO "
	case l < slog.LevelError:
		return "WARN "
	default:
		return "ERROR"
	}
}

// levelColor maps a log level onto the shared palette, so a warning in the log reads the same
// as a warning anywhere else Draugr writes.
func levelColor(l slog.Level) tui.Style {
	switch {
	case l < slog.LevelInfo:
		return tui.StyleMuted
	case l < slog.LevelWarn:
		return tui.StylePass
	case l < slog.LevelError:
		return tui.StyleMedium
	default:
		return tui.StyleFail
	}
}
