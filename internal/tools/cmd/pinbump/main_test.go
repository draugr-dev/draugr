package main

import (
	"context"
	"errors"
	"net/http"
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

// A bump's line in the release notes and its proof's heading name the Go where it moved, and say
// nothing about it where it did not.
func TestDescribeNamesTheGoWhereItMoved(t *testing.T) {
	cases := []struct {
		name                   string
		from, fromGo, to, toGo string
		wantEntry, wantHeading string
	}{
		{
			"the Go alone", "1.9.0", "go1.27.3", "1.9.0", "go1.27.4",
			"- **`draugr tools install` builds govulncheck 1.9.0 with go1.27.4**, which was built with go1.27.3.",
			"### `govulncheck` 1.9.0 built with go1.27.3 → 1.9.0 built with go1.27.4",
		},
		{
			"both", "1.9.0", "go1.27.3", "1.10.0", "go1.27.4",
			"- **`draugr tools install` builds govulncheck 1.10.0 with go1.27.4**, which was pinned at 1.9.0 and built with go1.27.3.",
			"### `govulncheck` 1.9.0 built with go1.27.3 → 1.10.0 built with go1.27.4",
		},
		{
			"the tool alone", "1.9.0", "go1.27.3", "1.10.0", "go1.27.3",
			"- **`draugr tools install` fetches govulncheck 1.10.0**, which was pinned at 1.9.0.",
			"### `govulncheck` 1.9.0 → 1.10.0",
		},
		{
			"a tool with no Go", "1.9.0", "", "1.10.0", "",
			"- **`draugr tools install` fetches govulncheck 1.10.0**, which was pinned at 1.9.0.",
			"### `govulncheck` 1.9.0 → 1.10.0",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for form, want := range map[string]string{"entry": c.wantEntry, "heading": c.wantHeading} {
				got, ok := describe([]string{form, "govulncheck", c.from, c.fromGo, c.to, c.toGo})
				if !ok || got != want {
					t.Errorf("%s = %q, %v, want %q", form, got, ok, want)
				}
			}
		})
	}
}

// Anything else on the command line is a bump, including a tool that shares no name with the forms.
func TestDescribeLeavesEveryOtherCommandLineAlone(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"govulncheck"},
		{"entry", "govulncheck", "1.9.0"},
		{"other", "govulncheck", "1.9.0", "", "1.10.0", ""},
	} {
		if got, ok := describe(args); ok {
			t.Errorf("describe(%q) = %q, want no text", args, got)
		}
	}
}

// The Go a proof ran is the one that goes in, and the newest is asked for only when none is named. A
// Go released between the proof and the assembly would otherwise go into the pull request unproven.
func TestNextGo(t *testing.T) {
	newest := func(context.Context, *http.Client) (string, error) { return "go1.99.0", nil }
	refuse := func(context.Context, *http.Client) (string, error) {
		t.Error("asked go.dev although the Go was named, or for a tool Go does not build")
		return "", nil
	}
	broken := func(context.Context, *http.Client) (string, error) { return "", errors.New("no answer") }
	cases := []struct {
		name    string
		goBuilt bool
		named   string
		latest  func(context.Context, *http.Client) (string, error)
		want    string
		wantErr string
	}{
		{"named", true, "go1.27.3", refuse, "go1.27.3", ""},
		{"not named", true, "", newest, "go1.99.0", ""},
		{"go.dev does not answer", true, "", broken, "", "the newest Go: no answer"},
		{"not a Go release", true, "1.27.3", refuse, "", "is not a Go release"},
		{"an option", true, "--upload-pack=x", refuse, "", "is not a Go release"},
		{"no Go, none named", false, "", refuse, "", ""},
		{"no Go, one named", false, "go1.27.3", refuse, "", "cannot be its Go"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := nextGo(context.Background(), c.goBuilt, c.named, c.latest)
			if got != c.want {
				t.Errorf("Go = %q, want %q", got, c.want)
			}
			if c.wantErr == "" && err != nil {
				t.Errorf("err = %v", err)
			}
			if c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)) {
				t.Errorf("err = %v, want it to hold %q", err, c.wantErr)
			}
		})
	}
}
