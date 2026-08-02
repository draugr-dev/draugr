package cli

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/saga"
)

// dirtyRepo returns a repository path with one committed file and one uncommitted change.
func dirtyRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...) //nolint:gosec // test helper
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Skipf("git unavailable: %v: %s", err, out)
		}
	}
	run("init", "-q", "-b", "main")
	run("config", "user.email", "t@example.com")
	run("config", "user.name", "Tester")
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("one\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run("add", ".")
	run("commit", "-qm", "init")
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("two\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// capture collects the warnings warnUncommitted emits for a model.
func capture(t *testing.T, model *saga.Model) string {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	warnUncommitted(context.Background(), model)
	return buf.String()
}

func TestWarnUncommitted(t *testing.T) {
	repo := dirtyRepo(t)
	clean := t.TempDir() // not a repository: nothing to say about it

	model := &saga.Model{Components: []saga.Component{
		// The same repository on two components, as a monorepo produces. One checkout is one
		// fact, however many components and controls read it.
		{Name: "web", Repositories: []saga.Repository{{URL: repo}, {URL: clean}}},
		{Name: "api", Repositories: []saga.Repository{{URL: repo}}},
		{Name: "remote", Repositories: []saga.Repository{{URL: "https://github.com/acme/web.git"}}},
	}}

	out := capture(t, model)
	if got := strings.Count(out, "not your working tree"); got != 1 {
		t.Errorf("warned %d times, want exactly 1:\n%s", got, out)
	}
	if !strings.Contains(out, "uncommitted_files=1") {
		t.Errorf("missing the file count:\n%s", out)
	}
	if strings.Contains(out, "github.com/acme") {
		t.Errorf("warned about a remote, which has no working tree:\n%s", out)
	}
}

func TestWarnUncommittedQuiet(t *testing.T) {
	// A nil model and a model with nothing dirty both say nothing at all.
	if out := capture(t, nil); out != "" {
		t.Errorf("nil model: %s", out)
	}
	model := &saga.Model{Components: []saga.Component{
		{Name: "web", Repositories: []saga.Repository{{URL: "https://github.com/acme/web.git"}}},
	}}
	if out := capture(t, model); out != "" {
		t.Errorf("clean model: %s", out)
	}
}
