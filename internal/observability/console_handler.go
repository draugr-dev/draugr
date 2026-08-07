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
// Four weights, so the shape of a line is readable before its content: the message strongest
// because it is what a reader scans for, the level coloured, timestamps and attribute keys
// dimmed, values plain — and an error or a non-zero exit coloured, because in a dense debug
// stream that is the line worth finding.
//
// A multi-line value is a relayed program output rather than a value, and is rendered as an
// indented block beneath the record instead of a quoted attribute. Colour never changes the
// text, only its rendering, so a record stays greppable and NO_COLOR output stays identical
// minus the escapes.
//
// A deliberately small handler for interactive use; JSON remains the format for machine and
// observability pipelines, and is not affected by any of this.
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
	// The message is what a reader scans for, so it is the one part of the line rendered
	// stronger than plain rather than weaker. Bold is deliberate over a colour: debug output is
	// already carrying level colours, and a fourth hue would compete with them for a job that
	// weight does better.
	buf = h.paint.Append(buf, tui.StyleStrong, r.Message)

	// Streams are collected rather than rendered inline: a tool's whole stdout as a quoted
	// attribute is the thing this handler exists not to do.
	var streams []slog.Attr
	buf = append(buf, h.preformatted...)
	r.Attrs(func(a slog.Attr) bool {
		if isStream(a) {
			streams = append(streams, a)
			return true
		}
		buf = h.appendAttr(buf, a, h.groupPrefix)
		return true
	})
	buf = append(buf, '\n')
	for _, a := range streams {
		buf = h.appendStream(buf, a)
	}

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
	return h.paint.Append(buf, valueStyle(a), val)
}

// isStream reports whether an attribute is a relayed program output rather than a value.
//
// Multi-line is the test, and it is the honest one: a value that spans lines cannot be rendered
// on a line. Naming the keys instead would work for the two Draugr emits today and be wrong for
// the next one.
func isStream(a slog.Attr) bool {
	return a.Value.Kind() == slog.KindString && strings.Contains(a.Value.String(), "\n")
}

// appendStream renders a relayed stream as an indented block beneath its record.
//
// The escapes are the unreadable part. A tool's stdout arriving as one quoted attribute is
// correct for --log-format json and wrong for the case a reader reaches trace in, which is
// sitting at a terminal trying to see what a scanner said. json and text are untouched: they
// have their own handlers, and this is the human one.
func (h *consoleHandler) appendStream(buf []byte, a slog.Attr) []byte {
	body := strings.TrimRight(a.Value.String(), "\n")
	buf = append(buf, ' ', ' ')
	buf = h.paint.Append(buf, tui.StyleMuted, "┌ "+h.groupPrefix+a.Key)
	buf = append(buf, '\n')
	for line := range strings.SplitSeq(body, "\n") {
		buf = append(buf, ' ', ' ')
		buf = h.paint.Append(buf, tui.StyleMuted, "│ ")
		buf = append(buf, line...)
		buf = append(buf, '\n')
	}
	buf = append(buf, ' ', ' ')
	buf = h.paint.Append(buf, tui.StyleMuted, "└")
	return append(buf, '\n')
}

// valueStyle picks the weight for an attribute's value.
//
// Only failure is called out, and only on keys Draugr itself chooses. In a debug stream every
// line looks alike, and the one worth finding is nearly always the one carrying an error or a
// non-zero exit — so those are the values that get a colour, and everything else stays plain.
// A rule that guessed from the value's shape would colour a tool's own prose.
func valueStyle(a slog.Attr) tui.Style {
	switch a.Key {
	case "error", "err":
		return tui.StyleFail
	case "exit_code":
		if a.Value.String() != "0" {
			return tui.StyleFail
		}
	}
	return tui.StyleNone
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
	// Trace is quieter than debug because it is noisier: a trace run carries both, and the
	// relayed streams are the part a reader is scrolling past to reach the record they want.
	case l < slog.LevelDebug:
		return tui.StyleMuted
	case l < slog.LevelInfo:
		return tui.StyleNone
	case l < slog.LevelWarn:
		return tui.StylePass
	case l < slog.LevelError:
		return tui.StyleMedium
	default:
		return tui.StyleFail
	}
}
