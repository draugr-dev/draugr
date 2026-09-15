package cli

import (
	"bytes"
	"context"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/draugr-dev/draugr/internal/builtins"
	"github.com/draugr-dev/draugr/internal/tools"
)

// update rewrites the golden files instead of comparing against them:
//
//	go test ./internal/cli -update
var update = flag.Bool("update", false, "rewrite the command golden files")

// Why every command has one, and not only `scan`.
//
// `scan` was the only console layout with a golden, and it is the only one that stopped drifting.
// Everything else was held by tests asserting that some fragment appeared somewhere in the output,
// which is a check on one sentence and no check at all on the screen it sits in. A heading can
// change case, a block can lose its title, a line can start naming a position, and every such test
// still passes.
//
// A golden is the whole screen. It fails on a change nobody meant, and a change somebody did mean
// is one line of `-update` and a diff in the pull request, which is where a layout should be argued
// about.
//
// These run the same functions the commands run, with the machine stubbed out: a golden that moved
// with the tools installed on a laptop would pin the laptop.
func TestCommandGolden(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func(t *testing.T, w *bytes.Buffer)
	}{
		{"controls", func(t *testing.T, w *bytes.Buffer) {
			if err := runControls(w, builtins.Registry(), false, ""); err != nil {
				t.Fatal(err)
			}
		}},
		{"controls-options", func(t *testing.T, w *bytes.Buffer) {
			if err := runControls(w, builtins.Registry(), true, ""); err != nil {
				t.Fatal(err)
			}
		}},
		{"tools-list", func(t *testing.T, w *bytes.Buffer) {
			stubDetect(t, map[string]string{"trivy": "0.74.0", "git": "2.55.0", "gosec": "2.28.0"})
			if err := runToolsList(context.Background(), w); err != nil {
				t.Fatal(err)
			}
		}},
		{"tools-install-plan", func(t *testing.T, w *bytes.Buffer) {
			stubDetect(t, map[string]string{"trivy": "0.74.0"})
			names := []string{"trivy", "gitleaks"}
			writeInstallPlan(w, names, false,
				present(context.Background(), names, toolsInstallOptions{}), toolsInstallOptions{})
		}},
		{"doctor-everything-present", func(t *testing.T, w *bytes.Buffer) {
			stubDetect(t, allToolsPresent())
			runDoctorForGolden(t, w, "")
		}},
		{"doctor-nothing-present", func(t *testing.T, w *bytes.Buffer) {
			stubDetect(t, map[string]string{})
			runDoctorForGolden(t, w, "")
		}},
		{"doctor-with-a-descriptor", func(t *testing.T, w *bytes.Buffer) {
			stubDetect(t, allToolsPresent())
			runDoctorForGolden(t, w, writeSaga(t, doctorSagaUncovered))
		}},
		{"feeds-status-empty", func(t *testing.T, w *bytes.Buffer) {
			// A fixed date, so the golden pins the layout rather than the day it ran.
			feedsStatus(w, filepath.Join(t.TempDir(), "feeds"),
				time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC))
		}},
		{"classify-nobody-answered", func(t *testing.T, w *bytes.Buffer) {
			path := writeSagaAt(t, t.TempDir(), "draugr.saga.yaml", classifySaga)
			if err := runClassify(path, classifyOptions{all: true}, strings.NewReader(""), w); err != nil {
				t.Fatal(err)
			}
		}},
		{"init", func(t *testing.T, w *bytes.Buffer) {
			dir := filepath.Join(t.TempDir(), "My.Service")
			if err := os.MkdirAll(dir, 0o750); err != nil {
				t.Fatal(err)
			}
			if err := runInit(dir, initOptions{output: filepath.Join(dir, "draugr.saga.yaml")}, w); err != nil {
				t.Fatal(err)
			}
			body, err := os.ReadFile(filepath.Join(dir, "draugr.saga.yaml")) // #nosec G304 -- this test wrote it
			if err != nil {
				t.Fatal(err)
			}
			w.WriteString("\n--- the file it wrote ---\n")
			w.Write(body)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// No terminal width, whatever the shell running the tests thinks, and no color. A
			// golden that moved with the window would pin the window.
			t.Setenv("COLUMNS", "")
			t.Setenv("NO_COLOR", "1")
			var b bytes.Buffer
			tc.run(t, &b)
			compareGolden(t, tc.name, scrub(b.String()))
		})
	}
}

// runDoctorForGolden drives doctor with the machine and the network both stubbed.
//
// `latest` returns a fixed version rather than asking GitHub: a golden that reached the network
// would fail on a plane and pass differently every release.
func runDoctorForGolden(t *testing.T, w *bytes.Buffer, sagaPath string) {
	t.Helper()
	err := runDoctor(context.Background(), w, builtins.Registry(), sagaPath, doctorRun{},
		detectTool, func(context.Context) (string, error) { return "v9.9.9", nil })
	// doctor exits non-zero when something it needs is missing, which is one of the states being
	// pinned. The output is the subject; the error is not.
	_ = err
}

// allToolsPresent is every tool Draugr knows about, at its pinned version, so the clean state is
// the one a reader sees after `draugr tools install`.
func allToolsPresent() map[string]string {
	out := map[string]string{"git": "2.55.0", "kubectl": "1.31.0"}
	for _, name := range tools.Installable() {
		out[name] = tools.PinnedVersion(name)
	}
	return out
}

// scrub removes what changes between machines and leaves the shape.
//
// A path, a home directory and a build stamp all differ per machine and none of them is the layout
// under test. Replaced rather than dropped, so a column that holds one keeps its width and the
// golden still fails if it stops being printed.
var scrubbers = []struct {
	re   *regexp.Regexp
	with string
}{
	// A path only. Versions are deliberately left alone: the stub supplies fixed ones, the pinned
	// column comes from the manifest, and a bump showing up here is the user-visible change it is.
	// Replacing them with a token of another length would also destroy the column alignment these
	// goldens exist to pin, which is most of what a table golden is for.
	{regexp.MustCompile(`(/(?:home|Users|tmp|var|private)|\bC:\\)[^\s,)"]*`), "<path>"},
}

func scrub(s string) string {
	for _, sc := range scrubbers {
		s = sc.re.ReplaceAllString(s, sc.with)
	}
	// Trailing spaces are invisible in a diff and a table writer emits them; they are not the
	// layout and a golden full of them is one nobody reads.
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = strings.TrimRight(l, " ")
	}
	return strings.Join(lines, "\n")
}

func compareGolden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", "golden", name+".golden")
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path) // #nosec G304 -- a path this test built
	if err != nil {
		t.Fatalf("no golden for %s: %v\nrun `go test ./internal/cli -update` to write it", name, err)
	}
	if got != string(want) {
		t.Errorf("%s output moved.\n\nIf you meant it: go test ./internal/cli -update\n\n"+
			"--- want ---\n%s\n--- got ---\n%s", name, want, got)
	}
}
