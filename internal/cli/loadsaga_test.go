package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/saga"
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
		"is not a valid Saga",     // states it's a descriptor problem
		"invalid exposure",        // includes the underlying validation detail
		"draugr validate " + path, // points at the fix
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

// The zero-config control list appears in the scan help. It is read off the model a tree holding
// nothing synthesizes, so it names exactly the controls that model enables.
func TestZeroConfigControlsMatchSyntheticSaga(t *testing.T) {
	model := zeroConfigModel(t, t.TempDir())
	var enabled []string
	for name := range model.Config.Controls {
		if model.Config.ControllerEnabled(name) {
			enabled = append(enabled, name)
		}
	}
	slices.Sort(enabled)
	if !slices.Equal(enabled, zeroConfigControls()) {
		t.Errorf("an empty tree enables %v, the list names %v", enabled, zeroConfigControls())
	}
	if got := ZeroConfigControls("and"); got != "iac, sast, sca, and secrets" {
		t.Errorf("conjunction form = %q", got)
	}
	if got := ZeroConfigControls(""); got != "iac, sast, sca, secrets" {
		t.Errorf("plain form = %q", got)
	}
}

// A finding's identity includes its component and its repository, so the first scan after `init`
// compares with a zero-config scan only when both name them alike. Two directories, so a name
// taken from the wrong one, or from the working directory, cannot pass.
func TestSyntheticSagaNamesWhatInitWrites(t *testing.T) {
	root := t.TempDir()
	dirs := []string{"My.Service", "Team Alpha"}
	for _, d := range dirs {
		if err := os.Mkdir(filepath.Join(root, d), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	for _, d := range dirs {
		t.Chdir(filepath.Join(root, d))
		var buf strings.Builder
		if err := runInit(".", initOptions{output: "-"}, &buf); err != nil {
			t.Fatal(err)
		}
		written, err := saga.Load([]byte(buf.String()))
		if err != nil {
			t.Fatalf("%s: init wrote a descriptor that does not load: %v", d, err)
		}
		synthesized := zeroConfigModel(t, ".")
		if synthesized.Project != written.Project {
			t.Errorf("%s: project %q, init writes %q", d, synthesized.Project, written.Project)
		}
		got, want := synthesized.Components[0], written.Components[0]
		if got.Name != want.Name {
			t.Errorf("%s: component %q, init writes %q", d, got.Name, want.Name)
		}
		if got.Repositories[0].URL != want.Repositories[0].URL {
			t.Errorf("%s: repository %q, init writes %q", d, got.Repositories[0].URL, want.Repositories[0].URL)
		}
	}
}

// Pointed at a directory from its parent, the synthesized url is that directory's path from the
// working directory, which is where the scan resolves a relative url.
func TestSyntheticSagaFromAParentNamesTheScannedDirectory(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"services/My.Service", "services/Team Alpha"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	t.Chdir(root)
	for dir, want := range map[string][2]string{
		"services/My.Service":   {"my-service", filepath.Join("services", "My.Service")},
		"./services/Team Alpha": {"team-alpha", filepath.Join("services", "Team Alpha")},
	} {
		m := zeroConfigModel(t, dir)
		c := m.Components[0]
		if m.Project != want[0] || c.Name != want[0] {
			t.Errorf("%s: project %q, component %q, want %q", dir, m.Project, c.Name, want[0])
		}
		if c.Repositories[0].URL != want[1] {
			t.Errorf("%s: repository %q, want %q", dir, c.Repositories[0].URL, want[1])
		}
		if notice, want := zeroConfigNotice(m), "No *.saga.yaml here, scanning "+filepath.Join(root, want[1])+".\n\n"; notice != want {
			t.Errorf("%s: notice = %q, want %q", dir, notice, want)
		}
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
		body := fmt.Sprintf("project: app-%d\nrelease:\n  version: \"1.0\"\ncomponents:\n  - name: c\n", i)
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
				t.Errorf("%s was ignored, the scan fell back to zero-config", name)
			}
			if m.Project != "app-0" {
				t.Errorf("loaded the wrong file: %q", m.Project)
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
	if m.Project == "" {
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
// Saga has to describe the current directory, not an empty path. The repository it names is what
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
	url := m.Components[0].Repositories[0].URL
	if abs, err := filepath.Abs(url); err != nil || abs != here {
		t.Errorf("repository URL = %q resolves to %q, want the current directory %q", url, abs, here)
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
