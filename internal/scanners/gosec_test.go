package scanners

import (
	"context"
	"strings"
	"testing"
)

func TestGosecInfo(t *testing.T) {
	info := NewGosec().Info()
	if info.Name != "gosec" || info.Binary != "gosec" {
		t.Errorf("info = %+v", info)
	}
	if len(info.Controls) != 1 || info.Controls[0] != "sast" {
		t.Errorf("controls = %v, want [sast]", info.Controls)
	}
}

func TestGosecArgs(t *testing.T) {
	// gosec loads packages relative to the working directory, so the target is ./... and the
	// dir argument is unused (the repoScanner sets the cwd).
	argv := gosecArgs("/some/checkout", nil)
	want := []string{"gosec", "-fmt", "sarif", "-no-fail", "./..."}
	if strings.Join(argv, " ") != strings.Join(want, " ") {
		t.Errorf("gosecArgs = %v, want %v", argv, want)
	}
}

func TestExecArgvInDirSetsCwd(t *testing.T) {
	dir := t.TempDir()
	out, err := execArgvInDir(context.Background(), dir, []string{"pwd"})
	if err != nil {
		t.Fatalf("execArgvInDir: %v", err)
	}
	// macOS resolves /var → /private/var; compare on the base name to stay portable.
	if !strings.Contains(strings.TrimSpace(string(out)), strings.TrimPrefix(dir, "/private")) {
		t.Errorf("pwd = %q, want it to reflect dir %q", strings.TrimSpace(string(out)), dir)
	}
	if _, err := execArgvInDir(context.Background(), "", nil); err == nil {
		t.Error("empty argv should error")
	}
}
