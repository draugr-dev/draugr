package observability

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/draugr-dev/draugr/pkg/tui"
)

func TestNewLoggerJSON(t *testing.T) {
	var buf bytes.Buffer
	logger, _, err := NewLogger(&buf, LogOptions{Level: "info", Format: "json"})
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	logger.Info("hello", "key", "value")

	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("output is not JSON: %v (%q)", err, buf.String())
	}
	if rec["msg"] != "hello" || rec["key"] != "value" {
		t.Fatalf("unexpected record: %v", rec)
	}
}

func TestNewLoggerLevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	logger, _, err := NewLogger(&buf, LogOptions{Level: "warn", Format: "text"})
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	logger.Info("should be filtered")
	if buf.Len() != 0 {
		t.Fatalf("info log should be filtered at warn level, got %q", buf.String())
	}
	logger.Warn("should appear")
	if !strings.Contains(buf.String(), "should appear") {
		t.Fatalf("warn log missing: %q", buf.String())
	}
}

func TestNewLoggerRejectsBadInput(t *testing.T) {
	if _, _, err := NewLogger(&bytes.Buffer{}, LogOptions{Level: "nope"}); err == nil {
		t.Fatal("expected error for bad level")
	}
	if _, _, err := NewLogger(&bytes.Buffer{}, LogOptions{Format: "xml"}); err == nil {
		t.Fatal("expected error for bad format")
	}
}

func TestParseLevelDefaults(t *testing.T) {
	lvl, err := parseLevel("")
	if err != nil || lvl != slog.LevelInfo {
		t.Fatalf("empty level = (%v,%v), want (info,nil)", lvl, err)
	}
}

func TestNewLoggerAllLevels(t *testing.T) {
	for _, lvl := range []string{"debug", "info", "warn", "warning", "error"} {
		if _, _, err := NewLogger(&bytes.Buffer{}, LogOptions{Level: lvl}); err != nil {
			t.Errorf("level %q: %v", lvl, err)
		}
	}
}

func TestSetDefault(t *testing.T) {
	l, _, err := NewLogger(&bytes.Buffer{}, LogOptions{})
	if err != nil {
		t.Fatal(err)
	}
	SetDefault(l) // must not panic
}

// TestNewLoggerDefaultIsConsole confirms the default (empty) format is the human-readable
// console — not JSON — so a terminal user sees legible logs. On a plain buffer (non-TTY) the
// output must be plain text with no ANSI escapes.
func TestNewLoggerDefaultIsConsole(t *testing.T) {
	var buf bytes.Buffer
	logger, _, err := NewLogger(&buf, LogOptions{})
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	logger.Warn("scan completed with issues", "error", "git clone: failed")
	s := buf.String()
	if json.Valid(bytes.TrimSpace(buf.Bytes())) {
		t.Errorf("default format should be console, not JSON: %q", s)
	}
	for _, want := range []string{"WARN", "scan completed with issues", `error="git clone: failed"`} {
		if !strings.Contains(s, want) {
			t.Errorf("console output missing %q\n%s", want, s)
		}
	}
	if strings.Contains(s, "\x1b[") {
		t.Errorf("no ANSI color expected on a non-TTY writer: %q", s)
	}
}

func TestConsoleHandlerColorWhenEnabled(t *testing.T) {
	var buf bytes.Buffer
	h := newConsoleHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}, true, 0)
	slog.New(h).Error("boom", "code", 7)
	s := buf.String()
	if !strings.Contains(s, "\x1b[") || !strings.Contains(s, "\x1b[0m") {
		t.Errorf("expected ANSI color with color enabled: %q", s)
	}
	// The level takes its colour from the shared palette, so an error in the log looks like a
	// failure everywhere else Draugr writes.
	if !strings.Contains(s, "\x1b["+string(tui.StyleFail)+"m") {
		t.Errorf("error level should use the shared fail style: %q", s)
	}
	// With color on, the dimmed key is reset before the value, so "code=" and "7" are not
	// contiguous — assert them separately.
	if !strings.Contains(s, "boom") || !strings.Contains(s, "code=") || !strings.Contains(s, "7") {
		t.Errorf("message/attr missing: %q", s)
	}
}

func TestConsoleHandlerLevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	h := newConsoleHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}, false, 0)
	log := slog.New(h)
	log.Info("dropped")
	if buf.Len() != 0 {
		t.Fatalf("info should be filtered at warn: %q", buf.String())
	}
	log.Warn("kept")
	if !strings.Contains(buf.String(), "WARN") || !strings.Contains(buf.String(), "kept") {
		t.Fatalf("warn record missing: %q", buf.String())
	}
}

func TestConsoleHandlerGroupsAndAttrs(t *testing.T) {
	var buf bytes.Buffer
	h := newConsoleHandler(&buf, nil, false, 0)
	log := slog.New(h).WithGroup("scan").With("scanner", "semgrep")
	log.Info("done", "findings", 3)
	s := buf.String()
	for _, want := range []string{"scan.scanner=semgrep", "scan.findings=3"} {
		if !strings.Contains(s, want) {
			t.Errorf("grouped attr %q missing\n%s", want, s)
		}
	}
}

func TestConsoleHandlerSkipsEmptyAndInlineGroup(t *testing.T) {
	var buf bytes.Buffer
	h := newConsoleHandler(&buf, nil, false, 0)
	// An empty attr is dropped; an inline group's members are prefixed and flattened.
	slog.New(h).Info("m", slog.Attr{}, slog.Group("g", "a", 1), slog.Group("empty"))
	s := buf.String()
	if !strings.Contains(s, "g.a=1") {
		t.Errorf("inline group member missing: %q", s)
	}
	if strings.Contains(s, "empty") {
		t.Errorf("empty group should be omitted: %q", s)
	}
}

func TestNewLoggerConsoleExplicit(t *testing.T) {
	var buf bytes.Buffer
	logger, _, err := NewLogger(&buf, LogOptions{Format: "console"})
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	logger.Info("hi", "k", "v")
	if !strings.Contains(buf.String(), "k=v") {
		t.Fatalf("console output missing attr: %q", buf.String())
	}
}

func TestColorEnabledAndIsTerminal(t *testing.T) {
	// A plain buffer is not a terminal, so color is off.
	if tui.IsTerminal(&bytes.Buffer{}) {
		t.Error("bytes.Buffer should not be a terminal")
	}
	if tui.ColorEnabled(&bytes.Buffer{}) {
		t.Error("color should be off for a non-terminal writer")
	}
	// An os.Pipe is an *os.File but not a character device.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	defer func() { _ = r.Close(); _ = w.Close() }()
	if tui.IsTerminal(w) {
		t.Error("a pipe is not a character device")
	}
	// NO_COLOR forces color off even for a terminal-like writer.
	t.Setenv("NO_COLOR", "1")
	if tui.ColorEnabled(os.Stdout) {
		t.Error("NO_COLOR must disable color")
	}
}

func TestTraceLevel(t *testing.T) {
	// trace sits below debug so relaying dependency output is opt-in.
	if LevelTrace >= slog.LevelDebug {
		t.Errorf("LevelTrace (%v) should be below debug", LevelTrace)
	}
	if _, _, err := NewLogger(&bytes.Buffer{}, LogOptions{Level: "trace"}); err != nil {
		t.Errorf("trace should be a valid level: %v", err)
	}
	var buf bytes.Buffer
	h := newConsoleHandler(&buf, &slog.HandlerOptions{Level: LevelTrace}, false, 0)
	slog.New(h).Log(context.Background(), LevelTrace, "relayed")
	if !strings.Contains(buf.String(), "TRACE") {
		t.Errorf("trace records should be labelled TRACE: %q", buf.String())
	}
	// A debug-level logger must not emit trace records.
	var quiet bytes.Buffer
	hq := newConsoleHandler(&quiet, &slog.HandlerOptions{Level: slog.LevelDebug}, false, 0)
	slog.New(hq).Log(context.Background(), LevelTrace, "relayed")
	if quiet.Len() != 0 {
		t.Errorf("debug should not emit trace records: %q", quiet.String())
	}
}

func TestConsoleHandlerRendersAStreamAsABlock(t *testing.T) {
	// A tool's whole stdout arriving as one quoted attribute is the thing this handler exists
	// not to do: the escapes are the unreadable part, and trace is reached by someone at a
	// terminal trying to see what a scanner said.
	var buf bytes.Buffer
	h := newConsoleHandler(&buf, &slog.HandlerOptions{Level: LevelTrace}, false, 0)
	slog.New(h).Log(t.Context(), LevelTrace, "tool stdout", "tool", "trivy", "stdout", "{\n  \"a\": 1\n}\n")
	s := buf.String()

	if strings.Contains(s, `\n`) {
		t.Errorf("a relayed stream must not be escaped onto one line:\n%s", s)
	}
	for _, want := range []string{"┌ stdout", "│ {", `│   "a": 1`, "│ }", "└"} {
		if !strings.Contains(s, want) {
			t.Errorf("block missing %q:\n%s", want, s)
		}
	}
	// The record's own line still carries its single-valued attributes, so it stays greppable.
	if !strings.Contains(s, "tool stdout tool=trivy\n") {
		t.Errorf("the record line should be intact above the block:\n%s", s)
	}
}

func TestConsoleHandlerLeavesSingleLineValuesInline(t *testing.T) {
	// Multi-line is the test for a stream, so a value that fits on a line is still a value.
	var buf bytes.Buffer
	h := newConsoleHandler(&buf, nil, false, 0)
	slog.New(h).Info("ran", "argv", "trivy fs --quiet .")
	s := buf.String()
	if strings.Contains(s, "┌") {
		t.Errorf("a single-line value is not a stream:\n%s", s)
	}
	if !strings.Contains(s, `argv="trivy fs --quiet ."`) {
		t.Errorf("a value with spaces is quoted inline:\n%s", s)
	}
}

func TestConsoleHandlerStreamSurvivesNoColor(t *testing.T) {
	// Colour changes the rendering, never the text: the plain block and the coloured one must
	// carry identical content, or grepping trace output stops working when a terminal is
	// attached.
	const body = "line one\nline two"
	render := func(color bool) string {
		var buf bytes.Buffer
		h := newConsoleHandler(&buf, &slog.HandlerOptions{Level: LevelTrace}, color, 0)
		slog.New(h).Log(t.Context(), LevelTrace, "tool stderr", "stderr", body)
		return buf.String()
	}
	plain, colored := render(false), stripANSI(render(true))
	if plain != colored {
		t.Errorf("colour changed the text:\nplain:   %q\ncoloured:%q", plain, colored)
	}
}

// stripANSI removes SGR escape sequences, so a coloured render can be compared with a plain one.
func stripANSI(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] == 0x1b && i+1 < len(s) && s[i+1] == '[' {
			j := i + 2
			for j < len(s) && s[j] != 'm' {
				j++
			}
			i = j + 1
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

func TestConsoleHandlerWeightsTheMessageAboveEverythingElse(t *testing.T) {
	// The message is what a reader scans for in a dense debug stream, so it is the one part of
	// the line rendered stronger than plain rather than weaker.
	var buf bytes.Buffer
	h := newConsoleHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}, true, 0)
	slog.New(h).Debug("ran external tool", "tool", "trivy")
	s := buf.String()
	if !strings.Contains(s, "\x1b["+string(tui.StyleStrong)+"mran external tool\x1b[0m") {
		t.Errorf("the message should carry the strong style: %q", s)
	}
	if !strings.Contains(s, "\x1b["+string(tui.StyleMuted)+"mtool=") {
		t.Errorf("attribute keys stay dimmed: %q", s)
	}
}

func TestConsoleHandlerColorsTheLineWorthFinding(t *testing.T) {
	// Every line in a debug stream looks alike, and the one worth finding is nearly always the
	// one carrying an error or a non-zero exit.
	for _, tc := range []struct {
		name    string
		attrs   []any
		colored bool
	}{
		{"an error value", []any{"error", "connection refused"}, true},
		{"the short spelling", []any{"err", "connection refused"}, true},
		{"a failing exit code", []any{"exit_code", 1}, true},
		{"a successful one", []any{"exit_code", 0}, false},
		{"an ordinary value", []any{"duration", "41ms"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			h := newConsoleHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}, true, 0)
			slog.New(h).Debug("ran external tool", tc.attrs...)
			got := strings.Count(buf.String(), "\x1b["+string(tui.StyleFail)+"m") > 0
			if got != tc.colored {
				t.Errorf("fail style present = %v, want %v: %q", got, tc.colored, buf.String())
			}
		})
	}
}

func TestConsoleHandlerSeparatesTraceFromDebug(t *testing.T) {
	// A trace run carries both levels, and the relayed streams are what a reader is scrolling
	// past to reach the record they want — so trace is the quieter of the two.
	if levelColor(LevelTrace) == levelColor(slog.LevelDebug) {
		t.Error("trace and debug rendering identically makes a trace run one flat block")
	}
	if levelColor(LevelTrace) != tui.StyleMuted {
		t.Errorf("trace should be the quietest level, got %q", levelColor(LevelTrace))
	}
}

func TestLogFileGetsEverythingTheTerminalDoesNot(t *testing.T) {
	// The point of the file: the terminal keeps the level that was asked for, and the file gets
	// the rest. One --log-level cannot serve a summary someone is reading now and the artefact
	// they attach to a bug report.
	path := filepath.Join(t.TempDir(), "draugr.log")
	var term bytes.Buffer
	logger, closeLog, err := NewLogger(&term, LogOptions{Level: "info", Format: "console", File: path})
	if err != nil {
		t.Fatal(err)
	}
	logger.Info("on screen")
	logger.Log(t.Context(), LevelTrace, "tool stdout", "stdout", "verbose")
	if err := closeLog(); err != nil {
		t.Fatal(err)
	}

	if strings.Contains(term.String(), "tool stdout") {
		t.Errorf("raising the file to trace must not put trace on screen:\n%s", term.String())
	}
	if !strings.Contains(term.String(), "on screen") {
		t.Errorf("the terminal keeps its own level:\n%s", term.String())
	}
	body, err := os.ReadFile(path) // #nosec G304 -- path is a t.TempDir() file this test just wrote
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"on screen", "tool stdout", "verbose"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("the file should hold %q:\n%s", want, body)
		}
	}
}

func TestLogFileIsUnclamped(t *testing.T) {
	// The reason to write one is to keep the part a terminal had no room for, so the ceiling
	// that makes the terminal readable must not follow the record into the file.
	path := filepath.Join(t.TempDir(), "draugr.log")
	var term bytes.Buffer
	logger, closeLog, err := NewLogger(&term, LogOptions{Level: "trace", Format: "console", File: path})
	if err != nil {
		t.Fatal(err)
	}
	big := strings.Repeat("x", maxTerminalValue+2000)
	logger.Log(t.Context(), LevelTrace, "tool stdout", "stdout", big)
	if err := closeLog(); err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(term.String(), "2000 bytes truncated") {
		t.Errorf("the terminal should clamp and say so:\n%s", term.String()[:min(300, term.Len())])
	}
	body, err := os.ReadFile(path) // #nosec G304 -- path is a t.TempDir() file this test just wrote
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), big) {
		t.Errorf("the file should hold the whole stream, got %d bytes", len(body))
	}
}

func TestLogFileAppendsRatherThanTruncates(t *testing.T) {
	// A second run is usually the one that reproduces the problem, and losing the first would
	// lose the comparison.
	path := filepath.Join(t.TempDir(), "draugr.log")
	for _, msg := range []string{"first run", "second run"} {
		logger, closeLog, err := NewLogger(io.Discard, LogOptions{Level: "info", File: path})
		if err != nil {
			t.Fatal(err)
		}
		logger.Info(msg)
		if err := closeLog(); err != nil {
			t.Fatal(err)
		}
	}
	body, err := os.ReadFile(path) // #nosec G304 -- path is a t.TempDir() file this test just wrote
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "first run") || !strings.Contains(string(body), "second run") {
		t.Errorf("both runs should be in the file:\n%s", body)
	}
}

func TestLogFileThatCannotBeOpenedIsFatal(t *testing.T) {
	// A log file silently not written would leave the run looking normal and the evidence
	// somebody asked for missing.
	_, _, err := NewLogger(io.Discard, LogOptions{Level: "info", File: filepath.Join(t.TempDir(), "no", "such", "dir", "x.log")})
	if err == nil {
		t.Fatal("an unopenable --log-file must fail the run, not be skipped")
	}
	if !strings.Contains(err.Error(), "--log-file") {
		t.Errorf("the error should name the flag that caused it: %v", err)
	}
}

func TestLogFileIsNotColoured(t *testing.T) {
	// A file is not a terminal. Escape codes in one make it unreadable in exactly the place it
	// is most likely to be read: pasted into an issue.
	path := filepath.Join(t.TempDir(), "draugr.log")
	logger, closeLog, err := NewLogger(io.Discard, LogOptions{Level: "info", Format: "console", File: path})
	if err != nil {
		t.Fatal(err)
	}
	logger.Error("boom", "error", "nope")
	if err := closeLog(); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path) // #nosec G304 -- path is a t.TempDir() file this test just wrote
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "\x1b[") {
		t.Errorf("the file should be plain text:\n%q", body)
	}
}

func TestMultiHandlerKeepsWritingAfterOneFails(t *testing.T) {
	// A file that has filled its disk must not cost the reader the line on their terminal. The
	// destinations carry the same record and do not depend on each other.
	var ok bytes.Buffer
	h := newMultiHandler(
		failingHandler{},
		newConsoleHandler(&ok, &slog.HandlerOptions{Level: slog.LevelInfo}, false, 0),
	)
	err := slog.New(h).Handler().Handle(t.Context(), slog.NewRecord(time.Time{}, slog.LevelInfo, "still written", 0))
	if err == nil {
		t.Error("the failure should be reported, not swallowed")
	}
	if !strings.Contains(ok.String(), "still written") {
		t.Errorf("the healthy destination should still have the record: %q", ok.String())
	}
}

func TestMultiHandlerWithOneDestinationIsThatDestination(t *testing.T) {
	// The ordinary single-destination case should cost nothing.
	var buf bytes.Buffer
	inner := newConsoleHandler(&buf, nil, false, 0)
	if got := newMultiHandler(inner); got != slog.Handler(inner) {
		t.Errorf("one handler should be returned unwrapped, got %T", got)
	}
}

func TestMultiHandlerCarriesAttrsAndGroupsToEveryDestination(t *testing.T) {
	var a, b bytes.Buffer
	h := newMultiHandler(
		newConsoleHandler(&a, nil, false, 0),
		newConsoleHandler(&b, nil, false, 0),
	)
	slog.New(h).WithGroup("scan").With("scanner", "trivy").Info("done", "findings", 2)
	for name, buf := range map[string]*bytes.Buffer{"first": &a, "second": &b} {
		if !strings.Contains(buf.String(), "scan.scanner=trivy") || !strings.Contains(buf.String(), "scan.findings=2") {
			t.Errorf("%s destination lost the group or attrs: %q", name, buf.String())
		}
	}
}

// failingHandler accepts every record and refuses to write it.
type failingHandler struct{}

func (failingHandler) Enabled(context.Context, slog.Level) bool  { return true }
func (failingHandler) Handle(context.Context, slog.Record) error { return errors.New("disk full") }
func (f failingHandler) WithAttrs([]slog.Attr) slog.Handler      { return f }
func (f failingHandler) WithGroup(string) slog.Handler           { return f }
