package scanners

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/toolexec"
)

// kept is what a run holds of log, written to stderr by a tool, when it holds only the lines keep
// accepts.
func kept(t *testing.T, log []byte, keep func([]byte) bool) []byte {
	t.Helper()
	file := filepath.Join(t.TempDir(), "log")
	if err := os.WriteFile(file, log, 0o600); err != nil {
		t.Fatal(err)
	}
	_, held, err := toolexec.RunWithLog(context.Background(), "", []string{"sh", "-c", `cat "$0" >&2`, file}, nil,
		toolexec.Log{Keep: keep})
	if err != nil {
		t.Fatal(err)
	}
	return held
}

// Every line a Trivy reader reads survives the filter, so each reads the same from the lines held
// as from the whole log, while the debug lines nobody reads are dropped.
func TestTrivyLogKeptHoldsWhatTheReadersRead(t *testing.T) {
	noise := strings.Repeat("2026-11-02T04:43:38-06:00\tDEBUG\t[npm] Parsing package\tfile_path=\"x/package.json\"\n", 200) +
		"2026-11-02T04:43:38-06:00\tINFO\tNumber of language-specific files\tnum=3\n"
	log := []byte(noise +
		string(readTrivyLog(t, "trivy-module-calls.log")) +
		string(readersFixture(t, "trivy-bun.log")) +
		"2026-11-02T04:43:38-06:00\tDEBUG\tWalk error\tfile_path=\"/checkout/b/poetry.lock\" err=\"parse error: toml: line 3\"\n" +
		"x\tWARN\t[helm scanner] Skipping chart\tfile_path=\"charts/app\" err=\"validation: chart.metadata.name is required\"\n" +
		"2026-11-02T04:43:40-05:00\tFATAL\tFatal error\n" +
		"- run error:\n" +
		"    github.com/aquasecurity/trivy/pkg/commands/artifact.run\n" +
		noise)
	held := kept(t, log, trivyLogKept)
	if len(held) >= len(log)/2 {
		t.Errorf("held %d of %d bytes, want the debug noise dropped", len(held), len(log))
	}
	for name, read := range map[string]func([]byte) any{
		"unloaded":    func(l []byte) any { return trivyUnloadedModules(l, "/checkout") },
		"unevaluated": func(l []byte) any { return trivyUnevaluatedModules(l, "/checkout") },
		"charts":      func(l []byte) any { return trivySkippedCharts(l, "/checkout") },
		"unparsed":    func(l []byte) any { return trivyUnparsedFiles(l, "/checkout") },
	} {
		if got, want := read(held), read(log); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: read %+v from the lines held, %+v from the whole log", name, got, want)
		}
	}
	if !bytes.Contains(held, []byte("FATAL\tFatal error\n- run error:\n")) {
		t.Errorf("the fatal line and the error after it were not held:\n%s", held)
	}
	for _, line := range []string{"- run error:", "    github.com/aquasecurity/trivy/pkg/commands/artifact.run", "a line with no tabs"} {
		if !trivyLogKept([]byte(line)) {
			t.Errorf("%q was dropped; a line naming no level continues an error", line)
		}
	}
}

// Gitleaks' trace lines for each file read and each candidate set aside are dropped, and the lines
// gitleaksUnread reads, the archives skipped and the bytes scanned, are held.
func TestGitleaksLogKeptHoldsWhatGitleaksUnreadReads(t *testing.T) {
	dir := writeTree(t, map[string]string{"README.md": "x\n"})
	noise := strings.Repeat("\x1b[90m9:41PM\x1b[0m \x1b[34mTRC\x1b[0m scanning path \x1b[36mpath=\x1b[0md/f.go\n", 200)
	for _, name := range []string{"gitleaks-skipped-archives.log", "gitleaks-only-archive.log", "gitleaks-nothing-read.log"} {
		log := append([]byte(noise), gitleaksLog(t, name, dir)...)
		held := kept(t, log, gitleaksLogKept)
		if got, want := gitleaksUnread(held, dir), gitleaksUnread(log, dir); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: %+v from the lines held, %+v from the whole log", name, got, want)
		}
		if bytes.Contains(held, []byte("scanning path")) {
			t.Errorf("%s: a trace line for a file read was held", name)
		}
	}
}

// Nuclei's banner and info lines are dropped; its warnings, errors, fatal lines and Skipped lines
// are held, so the skips read the same.
func TestNucleiLogKeptHoldsTheSkipsAndTheFailures(t *testing.T) {
	held := kept(t, []byte(nucleiSkipLog), nucleiLogKept)
	if got, want := nucleiSkips(held), nucleiSkips([]byte(nucleiSkipLog)); !reflect.DeepEqual(got, want) || len(got) != 4 {
		t.Errorf("skips %+v from the lines held, %+v from the whole log", got, want)
	}
	for _, line := range []string{"[FTL] no templates", "[ERR] Could not read", "[WRN] slow"} {
		if !nucleiLogKept([]byte(line)) {
			t.Errorf("%q was dropped", line)
		}
	}
	if bytes.Contains(held, []byte("Templates loaded")) || bytes.Contains(held, []byte("____")) {
		t.Errorf("an info line or the banner was held:\n%s", held)
	}
}
