package observability

import (
	"bytes"
	"encoding/json"
	"log/slog"
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
