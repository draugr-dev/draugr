package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/tools"
)

// gotoolCopy copies the real gotool.go to a scratch file, so a bump is tested against the shape the
// constants actually have there.
func gotoolCopy(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "gotool.go"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "gotool.go")
	if err := os.WriteFile(path, raw, 0o600); err != nil { // #nosec G703 -- a path under the test's own temp dir
		t.Fatal(err)
	}
	return path
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path) // #nosec G304 -- a file under the test's own temp dir
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// A new Go release with no new govulncheck moves the toolchain alone, and leaves the tool's pin.
func TestBumpGoMovesTheToolchainAlone(t *testing.T) {
	path := gotoolCopy(t)
	pin, goPin := tools.PinnedVersion("govulncheck"), tools.GoToolchain("govulncheck")
	if err := bumpGo(path, pin, pin, goPin, "go1.99.0"); err != nil {
		t.Fatal(err)
	}
	got := readFile(t, path)
	for _, want := range []string{
		`const govulncheckToolchain = "go1.99.0"`, `const govulncheckVersion = "` + pin + `"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("gotool.go does not hold %s", want)
		}
	}
}

// Both pins moved, each to its own value.
func TestBumpGoMovesBothPins(t *testing.T) {
	path := gotoolCopy(t)
	pin, goPin := tools.PinnedVersion("govulncheck"), tools.GoToolchain("govulncheck")
	if err := bumpGo(path, pin, "99.0.0", goPin, "go1.99.0"); err != nil {
		t.Fatal(err)
	}
	got := readFile(t, path)
	for _, want := range []string{`const govulncheckToolchain = "go1.99.0"`, `const govulncheckVersion = "99.0.0"`} {
		if !strings.Contains(got, want) {
			t.Errorf("gotool.go does not hold %s", want)
		}
	}
}

// A pin that is not what the file says is an error, and the file is left as it was.
func TestBumpGoRefusesAPinTheFileDoesNotHold(t *testing.T) {
	path := gotoolCopy(t)
	before := readFile(t, path)
	pin := tools.PinnedVersion("govulncheck")
	if err := bumpGo(path, pin, pin, "go0.0.1", "go1.99.0"); err == nil {
		t.Error("a toolchain the file does not hold was moved")
	}
	if err := bumpGo(path, "0.0.1", "99.0.0", "", ""); err == nil {
		t.Error("a version the file does not hold was moved")
	}
	if readFile(t, path) != before {
		t.Error("a refused bump changed the file")
	}
}

func TestWithGo(t *testing.T) {
	if got := withGo("1.9.0", "go1.27.3"); got != "1.9.0 built with go1.27.3" {
		t.Errorf("withGo = %q", got)
	}
	if got := withGo("0.74.0", ""); got != "0.74.0" {
		t.Errorf("withGo with no Go = %q", got)
	}
}
