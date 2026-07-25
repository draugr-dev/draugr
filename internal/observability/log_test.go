package observability

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"os"
	"strings"
	"testing"
)

func TestNewLoggerJSON(t *testing.T) {
	var buf bytes.Buffer
	logger, err := NewLogger(&buf, LogOptions{Level: "info", Format: "json"})
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
	logger, err := NewLogger(&buf, LogOptions{Level: "warn", Format: "text"})
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
	if _, err := NewLogger(&bytes.Buffer{}, LogOptions{Level: "nope"}); err == nil {
		t.Fatal("expected error for bad level")
	}
	if _, err := NewLogger(&bytes.Buffer{}, LogOptions{Format: "xml"}); err == nil {
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
		if _, err := NewLogger(&bytes.Buffer{}, LogOptions{Level: lvl}); err != nil {
			t.Errorf("level %q: %v", lvl, err)
		}
	}
}

func TestSetDefault(t *testing.T) {
	l, err := NewLogger(&bytes.Buffer{}, LogOptions{})
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
	logger, err := NewLogger(&buf, LogOptions{})
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
	h := newConsoleHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}, true)
	slog.New(h).Error("boom", "code", 7)
	s := buf.String()
	if !strings.Contains(s, "\x1b[") || !strings.Contains(s, ansiReset) {
		t.Errorf("expected ANSI color with color enabled: %q", s)
	}
	if !strings.Contains(s, ansiRed) {
		t.Errorf("error level should be red: %q", s)
	}
	// With color on, the dimmed key is reset before the value, so "code=" and "7" are not
	// contiguous — assert them separately.
	if !strings.Contains(s, "boom") || !strings.Contains(s, "code=") || !strings.Contains(s, "7") {
		t.Errorf("message/attr missing: %q", s)
	}
}

func TestConsoleHandlerLevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	h := newConsoleHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}, false)
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
	h := newConsoleHandler(&buf, nil, false)
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
	h := newConsoleHandler(&buf, nil, false)
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
	logger, err := NewLogger(&buf, LogOptions{Format: "console"})
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
	if isTerminal(&bytes.Buffer{}) {
		t.Error("bytes.Buffer should not be a terminal")
	}
	if colorEnabled(&bytes.Buffer{}) {
		t.Error("color should be off for a non-terminal writer")
	}
	// An os.Pipe is an *os.File but not a character device.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	defer func() { _ = r.Close(); _ = w.Close() }()
	if isTerminal(w) {
		t.Error("a pipe is not a character device")
	}
	// NO_COLOR forces color off even for a terminal-like writer.
	t.Setenv("NO_COLOR", "1")
	if colorEnabled(os.Stdout) {
		t.Error("NO_COLOR must disable color")
	}
}
