package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadSagaValid(t *testing.T) {
	m, err := loadSaga(writeSaga(t, validSaga))
	if err != nil {
		t.Fatalf("loadSaga: %v", err)
	}
	if len(m.Components) != 1 {
		t.Errorf("components = %d, want 1", len(m.Components))
	}
}

func TestLoadSagaInvalidHasContextAndHint(t *testing.T) {
	path := writeSaga(t, invalidSaga)
	_, err := loadSaga(path)
	if err == nil {
		t.Fatal("expected error for invalid saga")
	}
	msg := err.Error()
	for _, want := range []string{
		"is not a valid Saga",         // states it's a descriptor problem
		"invalid exposure",            // includes the underlying validation detail
		"release.version is required", // aggregates all problems, not just the first
		"draugr validate " + path,     // points at the fix
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("error missing %q\ngot: %s", want, msg)
		}
	}
	// The aggregated detail is indented under the summary line.
	if !strings.Contains(msg, "\n  ") {
		t.Errorf("expected indented detail, got: %s", msg)
	}
}

// The zero-config control list appears in the scan help and the run notice. Both must render it
// from syntheticSaga's actual set — hard-coded copies drifted from reality twice before.
func TestZeroConfigControlsMatchSyntheticSaga(t *testing.T) {
	model := syntheticSaga(t.TempDir())
	for name := range model.Config.Controllers {
		if !strings.Contains(ZeroConfigControls("and"), name) {
			t.Errorf("control %q is enabled zero-config but missing from the rendered list %q",
				name, ZeroConfigControls("and"))
		}
	}
	if got := len(model.Config.Controllers); got != len(zeroConfigControls) {
		t.Errorf("synthesized saga enables %d controls, the list names %d", got, len(zeroConfigControls))
	}
	// The help text uses the "and" form; the run notice uses the plain list.
	if got := ZeroConfigControls("and"); got != "sca, secrets, sast, and iac" {
		t.Errorf("conjunction form = %q", got)
	}
	if got := ZeroConfigControls(""); got != "sca, secrets, sast, iac" {
		t.Errorf("plain form = %q", got)
	}
}

func TestScanHelpRendersTheDerivedControls(t *testing.T) {
	long := newScanCommand().Long
	if !strings.Contains(long, ZeroConfigControls("and")) {
		t.Errorf("scan help should render the derived control list, got:\n%s", long)
	}
}

// writeDescriptors creates a directory holding each named file as a minimal valid descriptor.
func writeDescriptors(t *testing.T, names ...string) string {
	t.Helper()
	dir := t.TempDir()
	for i, name := range names {
		body := fmt.Sprintf("release:\n  name: app-%d\n  version: \"1.0\"\ncomponents:\n  - name: c\n", i)
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestScanModelFindsAnyNamedDescriptor(t *testing.T) {
	// Our SchemaStore entry claims all of these, so an editor already validates them. A scan
	// that ignored three of the four would contradict our own editor integration.
	for _, name := range []string{"draugr.saga.yaml", "web.saga.yaml", ".saga.yaml", "api.saga.yml"} {
		t.Run(name, func(t *testing.T) {
			dir := writeDescriptors(t, name)
			m, synthesized, err := scanModel(dir)
			if err != nil {
				t.Fatalf("scanModel: %v", err)
			}
			if synthesized {
				t.Errorf("%s was ignored — the scan fell back to zero-config", name)
			}
			if m.Release.Name != "app-0" {
				t.Errorf("loaded the wrong file: %q", m.Release.Name)
			}
		})
	}
}

func TestScanModelRefusesTwoDescriptorsWithNobodyToAsk(t *testing.T) {
	// Picking one would produce a verdict about something the reader did not ask about, and
	// nothing in the output would say which.
	orig := chooser
	t.Cleanup(func() { chooser = orig })
	chooser = func([]string) (string, bool) { return "", false } // no terminal

	dir := writeDescriptors(t, "web.saga.yaml", "api.saga.yaml")
	_, _, err := scanModel(dir)
	if err == nil {
		t.Fatal("expected a refusal, not a guess")
	}
	for _, want := range []string{"web.saga.yaml", "api.saga.yaml", "draugr scan"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error should name %q and how to resolve it: %v", want, err)
		}
	}
}

func TestScanModelUsesAnInteractiveChoice(t *testing.T) {
	orig := chooser
	t.Cleanup(func() { chooser = orig })
	dir := writeDescriptors(t, "web.saga.yaml", "api.saga.yaml")
	chooser = func(found []string) (string, bool) {
		if len(found) != 2 {
			t.Errorf("the chooser should see both: %v", found)
		}
		return filepath.Join(dir, "web.saga.yaml"), true
	}
	m, synthesized, err := scanModel(dir)
	if err != nil || synthesized {
		t.Fatalf("scanModel: err=%v synthesized=%v", err, synthesized)
	}
	if m.Release.Name == "" {
		t.Error("the chosen descriptor should have been loaded")
	}
}

func TestScanModelStillFallsBackWithNoDescriptor(t *testing.T) {
	_, synthesized, err := scanModel(t.TempDir())
	if err != nil {
		t.Fatalf("scanModel: %v", err)
	}
	if !synthesized {
		t.Error("an empty directory is what zero-config is for")
	}
}

// `draugr scan` with no argument at all, which is the shortest way to run one. The synthesized
// Saga has to describe the current directory, not an empty path — the repository it names is what
// every scanner is then pointed at.
func TestScanModelWithNoTargetSynthesizesForHere(t *testing.T) {
	t.Chdir(t.TempDir())
	m, synthesized, err := scanModel("")
	if err != nil {
		t.Fatalf("scanModel: %v", err)
	}
	if !synthesized {
		t.Fatal("an empty directory is what zero-config is for")
	}
	if len(m.Components) != 1 || len(m.Components[0].Repositories) != 1 {
		t.Fatalf("want one repository to scan, got %+v", m.Components)
	}
	here, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if url := m.Components[0].Repositories[0].URL; url != here {
		t.Errorf("repository URL = %q, want the current directory %q", url, here)
	}
}

func TestDescriptorsInIgnoresDirectoriesAndOtherFiles(t *testing.T) {
	dir := writeDescriptors(t, "web.saga.yaml")
	for _, name := range []string{"notes.yaml", "saga.yaml", "README.md"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// A directory that happens to end in the suffix is not a descriptor.
	if err := os.Mkdir(filepath.Join(dir, "old.saga.yaml"), 0o750); err != nil {
		t.Fatal(err)
	}
	found, err := descriptorsIn(dir)
	if err != nil {
		t.Fatalf("descriptorsIn: %v", err)
	}
	if len(found) != 1 || filepath.Base(found[0]) != "web.saga.yaml" {
		t.Errorf("found %v, want only web.saga.yaml", found)
	}
}
