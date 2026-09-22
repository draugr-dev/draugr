package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/tools"
)

func TestRunToolsInstallSuccess(t *testing.T) {
	// Stubbed absent: these assert what happens when there is work to do, and without a
	// stub they ask the machine the tests run on.
	stubDetect(t, map[string]string{})
	var out bytes.Buffer
	install := func(name string) (tools.Installed, error) {
		i := tools.Installed{Name: name, Version: "1.2.3", Path: "/home/u/.draugr/bin/" + name}
		if name == "trivy" { // trivy carries cosign provenance
			i.SignatureVerified = true
			i.ProvenanceNote = "cosign signature verified"
		}
		return i, nil
	}
	if err := runToolsInstall(&out, nil, []string{"trivy", "gitleaks"}, false, toolsInstallOptions{yes: true}, install); err != nil {
		t.Fatalf("runToolsInstall: %v", err)
	}
	s := out.String()
	for _, want := range []string{"✓ trivy 1.2.3", "sha256 + cosign verified", "✓ gitleaks 1.2.3", "sha256 verified"} {
		if !strings.Contains(s, want) {
			t.Errorf("output missing %q\n%s", want, s)
		}
	}
}

func TestProvenanceLabel(t *testing.T) {
	cases := []struct {
		in   tools.Installed
		want string
	}{
		{tools.Installed{SignatureVerified: true, ProvenanceNote: "cosign signature verified"}, "sha256 + cosign verified"},
		{tools.Installed{ProvenanceNote: "cosign not installed, skipped signature check"}, "sha256 verified; cosign not installed, skipped signature check"},
		{tools.Installed{}, "sha256 verified"},
	}
	for _, c := range cases {
		if got := provenanceLabel(c.in); got != c.want {
			t.Errorf("provenanceLabel(%+v) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestRunToolsInstallPlanAndDryRun(t *testing.T) {
	var out bytes.Buffer
	called := false
	install := func(string) (tools.Installed, error) { called = true; return tools.Installed{}, nil }
	if err := runToolsInstall(&out, nil, []string{"trivy", "cosign"}, false, toolsInstallOptions{dryRun: true}, install); err != nil {
		t.Fatal(err)
	}
	if called {
		t.Error("--dry-run must not install anything")
	}
	s := out.String()
	for _, want := range []string{"PLAN", "trivy", "cosign", "scanner", "utility", "dry run"} {
		if !strings.Contains(s, want) {
			t.Errorf("plan output missing %q\n%s", want, s)
		}
	}
}

func TestRunToolsInstallInteractiveAbort(t *testing.T) {
	// Stubbed absent: these assert what happens when there is work to do, and without a
	// stub they ask the machine the tests run on.
	stubDetect(t, map[string]string{})
	orig := isTTY
	isTTY = func(io.Reader) bool { return true }
	t.Cleanup(func() { isTTY = orig })

	var out bytes.Buffer
	called := false
	install := func(string) (tools.Installed, error) { called = true; return tools.Installed{}, nil }
	// interactive + "n" → abort before installing.
	if err := runToolsInstall(&out, strings.NewReader("n\n"), []string{"trivy"}, false, toolsInstallOptions{}, install); err != nil {
		t.Fatal(err)
	}
	if called {
		t.Error("a declined prompt must not install anything")
	}
	if !strings.Contains(out.String(), "Aborted") {
		t.Errorf("expected abort, got:\n%s", out.String())
	}
}

func TestRunToolsInstallHandlesSemgrepLikeAnyOtherTool(t *testing.T) {
	// Stubbed absent. Without this the test asks the machine it runs on, and passes or fails
	// depending on whether the developer happens to have semgrep. Which is how it read as a
	// regression the first time the installer learned to check.
	stubDetect(t, map[string]string{})
	var out bytes.Buffer
	var got []string
	install := func(name string) (tools.Installed, error) {
		got = append(got, name)
		return tools.Installed{Name: name, Version: tools.SemgrepVersion(), Path: "/x/" + name}, nil
	}
	if err := runToolsInstall(&out, nil, []string{"semgrep"}, false, toolsInstallOptions{yes: true}, install); err != nil {
		t.Fatalf("runToolsInstall: %v", err)
	}
	if len(got) != 1 || got[0] != "semgrep" {
		t.Errorf("semgrep should go through the installer like anything else, got %v", got)
	}
	// The plan has to describe an install rather than an instruction to go elsewhere.
	if strings.Contains(out.String(), "pipx") {
		t.Errorf("the pipx instruction should be gone:\n%s", out.String())
	}
}

func TestRunToolsInstallFailure(t *testing.T) {
	// Stubbed absent: these assert what happens when there is work to do, and without a
	// stub they ask the machine the tests run on.
	stubDetect(t, map[string]string{})
	var out bytes.Buffer
	install := func(string) (tools.Installed, error) {
		return tools.Installed{}, errors.New("boom")
	}
	err := runToolsInstall(&out, nil, []string{"trivy"}, false, toolsInstallOptions{yes: true}, install)
	if err == nil {
		t.Fatal("expected error when an install fails")
	}
	if !strings.Contains(out.String(), "✗ trivy") {
		t.Errorf("output should flag the failed tool\n%s", out.String())
	}
}

func TestRunToolsInstallAllInstallsInstallable(t *testing.T) {
	// Stubbed absent: this asserts the bulk install reaches every installable tool, which it
	// only does when there is something to install.
	stubDetect(t, map[string]string{})
	var out bytes.Buffer
	var got []string
	install := func(name string) (tools.Installed, error) {
		got = append(got, name)
		return tools.Installed{Name: name, Version: "1.0.0", Path: "/x/" + name}, nil
	}
	// Empty names → install everything installable, semgrep included.
	if err := runToolsInstall(&out, nil, nil, true, toolsInstallOptions{yes: true}, install); err != nil {
		t.Fatalf("runToolsInstall: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("expected installable tools to be installed")
	}
	if !slices.Contains(got, "semgrep") {
		t.Errorf("installing everything should install semgrep too, got %v", got)
	}
}

func TestRunToolsList(t *testing.T) {
	var out bytes.Buffer
	if err := runToolsList(context.Background(), &out); err != nil {
		t.Fatalf("runToolsList: %v", err)
	}
	s := out.String()
	for _, want := range []string{
		"Tool", "Category", "Controls", "Pinned",
		"trivy", "gitleaks", "semgrep", "git",
		"secrets", // gitleaks → secrets control
		"utility", // cosign/git category
	} {
		if !strings.Contains(s, want) {
			t.Errorf("list output missing %q\n%s", want, s)
		}
	}
}

func TestToolsCommandWiring(t *testing.T) {
	cmd := newToolsCommand()
	sub := map[string]bool{}
	for _, c := range cmd.Commands() {
		sub[c.Name()] = true
	}
	if !sub["install"] || !sub["list"] {
		t.Errorf("tools command missing subcommands: %v", sub)
	}
}

// A misspelled tool has nothing to plan, so it renders as a row of dashes and then asks for
// confirmation of it. It is a typo. Say so and stop.
func TestToolsInstallRejectsUnknownTool(t *testing.T) {
	var out bytes.Buffer
	called := false
	install := func(string) (tools.Installed, error) {
		called = true
		return tools.Installed{}, nil
	}
	err := runToolsInstall(&out, nil, []string{"notarealtool"}, false, toolsInstallOptions{yes: true}, install)
	if err == nil {
		t.Fatal("an unknown tool should be an error")
	}
	if called {
		t.Error("nothing should be installed when a name is unknown")
	}
	if !strings.Contains(err.Error(), "installable:") {
		t.Errorf("the error should list what can be installed: %v", err)
	}
	if strings.Contains(out.String(), "Install plan") {
		t.Error("no plan should be printed for an unknown tool")
	}
}

func TestToolsInstallSuggestsNearMiss(t *testing.T) {
	err := runToolsInstall(&bytes.Buffer{}, nil, []string{"trivvy"}, false, toolsInstallOptions{yes: true},
		func(string) (tools.Installed, error) { return tools.Installed{}, nil })
	if err == nil || !strings.Contains(err.Error(), `did you mean "trivy"`) {
		t.Errorf("expected a suggestion for a near-miss, got %v", err)
	}
}

// One bad name fails the whole command: half-installing after a typo is the surprising outcome.
func TestToolsInstallRejectsMixedValidAndInvalid(t *testing.T) {
	installed := 0
	err := runToolsInstall(&bytes.Buffer{}, nil, []string{"trivy", "nope"}, false, toolsInstallOptions{yes: true},
		func(string) (tools.Installed, error) { installed++; return tools.Installed{}, nil })
	if err == nil {
		t.Fatal("a mix containing an unknown tool should fail")
	}
	if installed != 0 {
		t.Errorf("installed %d tool(s); a typo should stop the whole command", installed)
	}
}

func TestClosestName(t *testing.T) {
	known := []string{"trivy", "gitleaks", "gosec", "cosign"}
	if got := closestName("trivvy", known); got != "trivy" {
		t.Errorf("closestName(trivvy) = %q", got)
	}
	if got := closestName("gitleak", known); got != "gitleaks" {
		t.Errorf("closestName(gitleak) = %q", got)
	}
	// Nothing close enough shouldn't produce a misleading suggestion.
	if got := closestName("kubernetes", known); got != "" {
		t.Errorf("closestName(kubernetes) = %q, want no suggestion", got)
	}
}

const toolsSagaTwoControls = `project: t
release: {version: "1.0"}
config:
  controllers:
    sca: {enabled: true}
    secrets: {enabled: true}
components:
  - name: c
    repositories: [{url: "https://example.com/x.git"}]
`

// The point of the flag: install what this project runs, not the catalog. On a security tool
// every binary put on PATH is one more thing to trust and patch, so the smaller set is the
// defensible one.
func TestInstallNamesFromSaga(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	got, _, err := installNames(&out, nil, toolsInstallOptions{saga: writeSaga(t, toolsSagaTwoControls)})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []string{"gitleaks", "trivy"}) {
		t.Errorf("names = %v, want [gitleaks trivy]", got)
	}
	if len(got) >= len(tools.Installable()) {
		t.Error("a scoped install that installs everything has done nothing")
	}
	// git is needed and cannot be provisioned. Installing the rest and reporting success would
	// leave someone one failed scan away from finding that out.
	if !strings.Contains(out.String(), "git") || !strings.Contains(out.String(), "cannot provision") {
		t.Errorf("the gap should be reported, got %q", out.String())
	}
}

// Two ways of saying what to install, pointing at different sets. Guessing which one was meant
// is how you install the wrong thing quietly.
func TestInstallNamesRejectsSagaWithExplicitTools(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	_, _, err := installNames(&out, []string{"trivy"}, toolsInstallOptions{saga: writeSaga(t, toolsSagaTwoControls)})
	if err == nil {
		t.Fatal("want an error")
	}
	if !strings.Contains(err.Error(), "trivy") {
		t.Errorf("the error should name what was asked for, got: %v", err)
	}
}

// Every control here runs on a scanner built into Draugr, so there is nothing to provision.
const toolsSagaNeedsNothing = `project: t
release: {version: "1.0"}
components:
  - name: c
    hosts: [{name: site, url: "https://example.com", type: browser}]
    controls:
      headers: {}
`

// An empty selection and no selection are different answers, and the difference is the whole
// catalog. Reading one as the other would answer --saga by downloading what it was passed to
// avoid, directly under a line saying there was nothing to install.
func TestInstallNamesSagaNeedingNothingIsNotEverything(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	got, all, err := installNames(&out, nil, toolsInstallOptions{saga: writeSaga(t, toolsSagaNeedsNothing)})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("names = %v, want none", got)
	}
	if all {
		t.Error("a descriptor that needs no tool has not asked for the catalog")
	}
	if !strings.Contains(out.String(), "Nothing to install") {
		t.Errorf("output should say so, got %q", out.String())
	}
}

// And the half of it downstream: an empty selection installs nothing rather than falling through
// to every tool the host can have.
func TestRunToolsInstallEmptySelectionInstallsNothing(t *testing.T) {
	stubDetect(t, map[string]string{})
	var out bytes.Buffer
	var got []string
	install := func(name string) (tools.Installed, error) {
		got = append(got, name)
		return tools.Installed{Name: name, Version: "1.0.0", Path: "/x/" + name}, nil
	}
	if err := runToolsInstall(&out, nil, nil, false, toolsInstallOptions{yes: true}, install); err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("nothing was selected, so nothing should install; got %v", got)
	}
	if strings.Contains(out.String(), "PLAN") {
		t.Errorf("a plan with no rows contradicts the line above it, got %q", out.String())
	}
}

// --all asks for what no arguments already installs, so the one thing it must not do is change
// the set. A flag that quietly narrowed or widened it would be worse than not having one.
func TestInstallNamesAllSelectsEverything(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	got, _, err := installNames(&out, nil, toolsInstallOptions{all: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("names = %v, want none, an empty list means the whole catalog downstream", got)
	}
	// The note argues for narrowing the selection. Somebody who passed --all has answered that.
	if out.String() != "" {
		t.Errorf("--all is a decision; got unsolicited advice: %q", out.String())
	}
}

// Three ways of saying what to install, pointing at different sets. Picking a winner quietly is
// how a pipeline provisions something other than what it reads as asking for.
func TestInstallNamesAllRejectsAnyOtherSelection(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	saga := writeSaga(t, toolsSagaTwoControls)
	_, _, err := installNames(&out, nil, toolsInstallOptions{all: true, saga: saga})
	if err == nil || !strings.Contains(err.Error(), saga) {
		t.Errorf("--all with --saga should fail and name the descriptor, got: %v", err)
	}

	_, _, err = installNames(&out, []string{"trivy"}, toolsInstallOptions{all: true})
	if err == nil || !strings.Contains(err.Error(), "trivy") {
		t.Errorf("--all with a tool list should fail and name the tool, got: %v", err)
	}
}

func TestInstallNamesReportsABadSaga(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	if _, _, err := installNames(&out, nil, toolsInstallOptions{saga: "/nonexistent/saga.yaml"}); err == nil {
		t.Error("an unreadable descriptor must fail rather than installing everything")
	}
}

// The set taken from a descriptor has to be what --saga would install, or the default promises a
// coverage it does not deliver.
func TestTheSetTakenFromADescriptor(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	if narrowerSetInWorkingDir() != nil {
		t.Error("no descriptor here, so nothing to read")
	}

	if err := os.WriteFile(filepath.Join(dir, "draugr.saga.yaml"), []byte(toolsSagaTwoControls), 0o600); err != nil {
		t.Fatal(err)
	}
	n := narrowerSetInWorkingDir()
	if n == nil {
		t.Fatal("a descriptor is right there and it read nothing")
	}
	// Two of the catalog, not three: git is needed but cannot be provisioned, and counting it
	// would advertise a saving the install does not make.
	if len(n.tools) != 2 {
		t.Errorf("tools = %v, want the two that can actually be provisioned", n.tools)
	}
	if n.catalog != len(tools.Installable()) {
		t.Errorf("catalog = %d, want %d", n.catalog, len(tools.Installable()))
	}

	// An unreadable descriptor is scan's problem to report. Here it means the directory says
	// nothing, and the caller turns that into a message naming the ways forward.
	if err := os.WriteFile(filepath.Join(dir, "draugr.saga.yaml"), []byte("{{not yaml"), 0o600); err != nil {
		t.Fatal(err)
	}
	if narrowerSetInWorkingDir() != nil {
		t.Error("a broken descriptor should be left to scan and doctor")
	}
}

// A scan finds any `*.saga.yaml`, so this has to as well. A project whose descriptor carries the
// product's name rather than Draugr's is the one least likely to pass --saga by hand.
func TestTheDescriptorCanBeCalledAnything(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.WriteFile(filepath.Join(dir, "acme.saga.yaml"), []byte(toolsSagaTwoControls), 0o600); err != nil {
		t.Fatal(err)
	}
	n := narrowerSetInWorkingDir()
	if n == nil || n.descriptor != "acme.saga.yaml" {
		t.Errorf("read %+v, want acme.saga.yaml", n)
	}

	// With two beside each other there is no way to tell which one this host is being prepared
	// for, and picking one would install against a guess. The caller says so and names the ways
	// forward rather than choosing.
	if err := os.WriteFile(filepath.Join(dir, "other.saga.yaml"), []byte(toolsSagaTwoControls), 0o600); err != nil {
		t.Fatal(err)
	}
	if narrowerSetInWorkingDir() != nil {
		t.Error("two descriptors leave nothing to choose between")
	}
}

func TestPluralThem(t *testing.T) {
	t.Parallel()
	if got := pluralThem(1); got != "it" {
		t.Errorf("pluralThem(1) = %q", got)
	}
	if got := pluralThem(2); got != "them" {
		t.Errorf("pluralThem(2) = %q", got)
	}
}

// stubDetect makes presence deterministic without arranging binaries on PATH.
func stubDetect(t *testing.T, found map[string]string) {
	t.Helper()
	prior := detectTool
	t.Cleanup(func() { detectTool = prior })
	detectTool = func(_ context.Context, tool tools.Tool) tools.Status {
		v, ok := found[tool.Binary]
		return tools.Status{Tool: tool, Found: ok, Version: v, Path: "/somewhere/" + tool.Binary}
	}
}

func TestInstallPlanMarksWhatIsAlreadyThere(t *testing.T) {
	// The plan is the moment someone decides whether to let a security tool write to their machine,
	// and it was describing work it would not do, six rows for one download.
	// The pinned version, read from the manifest rather than written here, so a version bump does
	// not leave this asserting a string the product stopped producing.
	pinned, _ := tools.Spec("trivy")
	stubDetect(t, map[string]string{"trivy": pinned.Version})
	var out bytes.Buffer
	names := []string{"trivy", "gitleaks"}
	writeInstallPlan(&out, names, false, present(context.Background(), names, toolsInstallOptions{}), toolsInstallOptions{})

	got := out.String()
	if !strings.Contains(got, "already at "+pinned.Version) {
		t.Errorf("a satisfied tool should say so:\n%s", got)
	}
	if !strings.Contains(got, "1 tool to install, 1 already current") {
		t.Errorf("the summary should count the real work:\n%s", got)
	}
}

func TestPresentIgnoresAWrongVersion(t *testing.T) {
	stubDetect(t, map[string]string{"trivy": "0.1.0"})
	if have := present(context.Background(), []string{"trivy"}, toolsInstallOptions{}); len(have) != 0 {
		t.Errorf("an old version is still work to do: %v", have)
	}
}

func TestPresentIgnoresEverythingUnderForce(t *testing.T) {
	stubDetect(t, map[string]string{"trivy": "0.69.3"})
	if have := present(context.Background(), []string{"trivy"}, toolsInstallOptions{force: true}); len(have) != 0 {
		t.Errorf("--force reinstalls regardless: %v", have)
	}
}

func TestInstallAsksNothingWhenEverythingIsCurrent(t *testing.T) {
	// A confirmation that gates no action teaches people to answer without reading, on the one
	// command where reading matters.
	current := map[string]string{}
	for _, name := range tools.Installable() {
		if spec, ok := tools.Spec(name); ok {
			current[spec.Binary] = spec.Version
			continue
		}
		// Every managed path, not the Python one alone. Asking only that one stubbed the others at "",
		// and the version check that would have noticed did not cover them either, so a tool at any
		// version at all counted as current.
		current[name] = tools.ManagedVersion(name)
	}
	stubDetect(t, current)

	var out bytes.Buffer
	installed := 0
	err := runToolsInstall(&out, strings.NewReader(""), nil, true, toolsInstallOptions{},
		func(string) (tools.Installed, error) { installed++; return tools.Installed{}, nil })
	if err != nil {
		t.Fatalf("runToolsInstall: %v", err)
	}
	if installed != 0 {
		t.Errorf("nothing should have been installed, ran %d", installed)
	}
	got := out.String()
	if !strings.Contains(got, "Everything is already current") {
		t.Errorf("it should say so plainly:\n%s", got)
	}
	if strings.Contains(got, "Proceed?") {
		t.Error("a prompt that gates nothing must not be shown")
	}
	if strings.Contains(got, "pipx") {
		t.Error("semgrep is installed by Draugr now; pipx should appear nowhere")
	}
}

func TestInstallPlansSemgrepAsAnInstall(t *testing.T) {
	// It used to print an instruction to go and run pipx. The plan now describes an install
	// Draugr performs, with the verification it will do and where the tool lands.
	current := map[string]string{}
	for _, name := range tools.Installable() {
		if spec, ok := tools.Spec(name); ok {
			current[spec.Binary] = spec.Version
		}
	}
	stubDetect(t, current) // everything but semgrep is current

	var out bytes.Buffer
	err := runToolsInstall(&out, strings.NewReader(""), nil, true, toolsInstallOptions{yes: true},
		func(name string) (tools.Installed, error) {
			return tools.Installed{Name: name, Version: tools.PythonVersion(name), Path: "/x/" + name}, nil
		})
	if err != nil {
		t.Fatalf("runToolsInstall: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "semgrep") || !strings.Contains(got, "sha256 (+deps)") {
		t.Errorf("the plan should describe installing semgrep and how it is verified:\n%s", got)
	}
	if strings.Contains(got, "pipx") {
		t.Errorf("pipx should appear nowhere:\n%s", got)
	}
}

func TestWantedVersionsFromConfig(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "draugr.config.yaml"),
		[]byte("tools:\n  trivy:\n    version: \"0.68.0\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)

	got, err := wantedVersions(nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if got["trivy"] != "0.68.0" {
		t.Errorf("the pin in draugr.config.yaml was ignored: %v", got)
	}
}

func TestWantedVersionsFlagBeatsTheConfig(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "draugr.config.yaml"),
		[]byte("tools:\n  trivy:\n    version: \"0.68.0\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)

	got, err := wantedVersions([]string{"trivy"}, "0.69.3")
	if err != nil {
		t.Fatal(err)
	}
	if got["trivy"] != "0.69.3" {
		t.Errorf("--version should win for this run: %v", got)
	}
}

func TestWantedVersionsRefusesAVersionForSeveralTools(t *testing.T) {
	// One value cannot mean the right thing for two tools, and installing 0.69.3 of gitleaks
	// because it was typed for trivy is worse than saying so.
	for _, args := range [][]string{nil, {"trivy", "gitleaks"}} {
		if _, err := wantedVersions(args, "0.69.3"); err == nil {
			t.Errorf("args %v: expected a refusal", args)
		}
	}
}

func TestPresentIgnoresABinaryThatIsNotThePinnedVersion(t *testing.T) {
	// The config asks for 0.68.0; 0.69.3 on disk is still work to do, or the pin does nothing.
	stubDetect(t, map[string]string{"trivy": "0.69.3"})
	opts := toolsInstallOptions{wanted: map[string]string{"trivy": "0.68.0"}}
	if have := present(context.Background(), []string{"trivy"}, opts); len(have) != 0 {
		t.Errorf("a pinned version that is not installed was reported as satisfied: %v", have)
	}
	opts.wanted["trivy"] = "v0.69.3"
	if have := present(context.Background(), []string{"trivy"}, opts); len(have) != 1 {
		t.Errorf("a leading v is how tags are written and should not force a reinstall: %v", have)
	}
}

func TestInstallPlanSaysHowWellItCanVerify(t *testing.T) {
	// The plan is where someone decides whether to let Draugr write a security tool to their
	// machine, so the strength of the check belongs there rather than in the result afterwards.
	stubDetect(t, nil)
	var out bytes.Buffer
	names := []string{"trivy"}
	opts := toolsInstallOptions{wanted: map[string]string{"trivy": "0.68.0"}}
	writeInstallPlan(&out, names, false, present(context.Background(), names, opts), opts)

	got := out.String()
	if !strings.Contains(got, "0.68.0") {
		t.Errorf("the plan shows the version Draugr ships, not the one it will install:\n%s", got)
	}
	if !strings.Contains(got, "upstream") {
		t.Errorf("another version is verified against the upstream, and should say so:\n%s", got)
	}
}

func TestPlanVerifyReportsTheWeakestHonestClaim(t *testing.T) {
	key := tools.PlatformKey()
	cases := []struct {
		name string
		spec tools.InstallSpec
		want string
	}{
		{"recorded sha", tools.InstallSpec{Assets: map[string]tools.Asset{key: {SHA256: "abc"}}}, "sha256"},
		{"recorded sha and a signature",
			tools.InstallSpec{Assets: map[string]tools.Asset{key: {SHA256: "abc"}}, Cosign: &tools.CosignSpec{}},
			"sha256 + cosign"},
		{"upstream signature",
			tools.InstallSpec{Assets: map[string]tools.Asset{key: {}}, Cosign: &tools.CosignSpec{}},
			"upstream cosign"},
		{"upstream checksums only",
			tools.InstallSpec{Assets: map[string]tools.Asset{key: {}}, ChecksumsURLTemplate: "u"},
			"upstream sha256"},
		{"nothing published", tools.InstallSpec{Assets: map[string]tools.Asset{key: {}}}, "unverified"},
	}
	for _, tc := range cases {
		if got := planVerify(tc.spec); got != tc.want {
			t.Errorf("%s: planVerify = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// The plan above already names every current tool, with its version and where it lives. Repeating
// the list afterwards reads as a second check that found something different, and on a full
// install it buries the one line describing what happened under seven describing what did not.
func TestInstallReportsWhatChangedAndCountsTheRest(t *testing.T) {
	stubDetect(t, map[string]string{"trivy": "0.69.3", "gitleaks": "8.30.1"})
	var out bytes.Buffer
	install := func(name string) (tools.Installed, error) {
		if name == "syft" {
			return tools.Installed{Name: name, Version: "1.49.0", Path: "/bin/syft"}, nil
		}
		return tools.Installed{Name: name, Version: "x", Path: "/bin/" + name, AlreadyPresent: true}, nil
	}
	err := runToolsInstall(&out, strings.NewReader(""), []string{"trivy", "gitleaks", "syft"}, false,
		toolsInstallOptions{yes: true}, install)
	if err != nil {
		t.Fatal(err)
	}

	got := out.String()
	after := got[strings.Index(got, "Proceed")+1:] // the plan legitimately names them; the log must not
	if strings.Contains(after, "already installed") {
		t.Errorf("the current tools were listed a second time:\n%s", got)
	}
	if !strings.Contains(got, "2 tools unchanged.") {
		t.Errorf("the unchanged tools should still be accounted for:\n%s", got)
	}
	if !strings.Contains(got, "✓ syft 1.49.0") {
		t.Errorf("the one thing that happened is missing:\n%s", got)
	}
}

// A tool that turns out not to be current after all is installed here, not skipped, so the case
// worth seeing stays loud even though the quiet one went silent.
func TestInstallStillNamesAToolItReplaced(t *testing.T) {
	stubDetect(t, map[string]string{"trivy": "0.69.3"})
	var out bytes.Buffer
	install := func(name string) (tools.Installed, error) {
		// Present at the pinned version by the plan's reckoning, but the checksum did not match.
		return tools.Installed{Name: name, Version: "0.69.3", Path: "/bin/" + name}, nil
	}
	if err := runToolsInstall(&out, strings.NewReader(""), []string{"trivy", "syft"}, false,
		toolsInstallOptions{yes: true}, install); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "✓ trivy 0.69.3") {
		t.Errorf("a replaced binary has to be named:\n%s", out.String())
	}
	if strings.Contains(out.String(), "unchanged") {
		t.Errorf("nothing was unchanged:\n%s", out.String())
	}
}

// The plan's count and the log's count describe the same tools, so they have to match.
//
// They used to drift over semgrep, which was planned like everything else and installed by
// something else, so a full install reported one fewer unchanged tool than the plan had just
// called current. Two numbers about the same thing disagreeing is worse than either alone, and the
// invariant is worth keeping now that the cause is gone.
func TestInstallCountsAgreeAcrossEveryTool(t *testing.T) {
	// Everything the real command would plan, current except syft, the shape the report described.
	current := map[string]string{}
	catalog := tools.Catalog()
	for _, name := range tools.Installable() {
		if name == "syft" {
			continue
		}
		current[catalog[name].Binary] = installVersion(t, name)
	}

	stubDetect(t, current)
	var out bytes.Buffer
	install := func(name string) (tools.Installed, error) {
		return tools.Installed{
			Name: name, Version: "x", Path: "/bin/" + name, AlreadyPresent: name != "syft",
		}, nil
	}
	// No names at all is the full install, which is where semgrep enters the plan.
	if err := runToolsInstall(&out, strings.NewReader(""), nil, true,
		toolsInstallOptions{yes: true}, install); err != nil {
		t.Fatal(err)
	}

	got := out.String()
	planned := regexp.MustCompile(`(\d+) already current`).FindStringSubmatch(got)
	logged := regexp.MustCompile(`(\d+) tools? unchanged`).FindStringSubmatch(got)
	if planned == nil || logged == nil {
		t.Fatalf("both counts should be printed:\n%s", got)
	}
	if planned[1] != logged[1] {
		t.Errorf("the plan says %s current, the log says %s unchanged:\n%s", planned[1], logged[1], got)
	}
}

// installVersion is the version `tools install` would fetch for a tool, which is what has to be
// present for it to count as current.
func installVersion(t *testing.T, name string) string {
	t.Helper()
	if spec, ok := tools.Spec(name); ok {
		return spec.Version
	}
	// One place to ask, rather than a branch per install path. This helper listed them individually
	// and so did not know about the one added after it was written.
	if v := tools.ManagedVersion(name); v != "" {
		return v
	}
	t.Fatalf("%s is installable but has no pinned version by any method", name)
	return ""
}

// Installing semgrep is work, so it is planned, confirmed and reported as work.
//
// It used to be none of those: the plan named it without counting it, the prompt did not gate it,
// and the run printed an instruction to go and run something else. Each of those was correct while
// Draugr could not install it, and each is now a claim about work that does happen.
func TestInstallingSemgrepIsPlannedAndConfirmedLikeAnythingElse(t *testing.T) {
	// semgrep absent, one other tool current. The count line is only rendered when something is
	// already satisfied, and the count is what this is about.
	trivy, _ := tools.Spec("trivy")
	stubDetect(t, map[string]string{"trivy": trivy.Version})
	var out bytes.Buffer
	called := 0
	install := func(name string) (tools.Installed, error) {
		if name != "semgrep" {
			return tools.Installed{Name: name, AlreadyPresent: true}, nil
		}
		called++
		return tools.Installed{Name: name, Version: tools.PythonVersion(name), Path: "/x/" + name}, nil
	}
	priorTTY := isTTY
	t.Cleanup(func() { isTTY = priorTTY })
	isTTY = func(io.Reader) bool { return true }

	// "y" on a terminal: the prompt has something to gate now.
	if err := runToolsInstall(&out, strings.NewReader("y\n"), []string{"semgrep", "trivy"}, false,
		toolsInstallOptions{}, install); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if !strings.Contains(got, "Proceed?") {
		t.Errorf("real work should be confirmed:\n%s", got)
	}
	// trivy is current, so only semgrep is actually installed.
	if called != 1 {
		t.Errorf("installed %d time(s), want 1", called)
	}
	if !strings.Contains(got, "1 tool to install") {
		t.Errorf("semgrep should be counted as work:\n%s", got)
	}
}

// The gate still has to exist for what Draugr really does download. The point is that it gates
// downloads, not that it is gone.
func TestARealDownloadStillAsks(t *testing.T) {
	stubDetect(t, nil)
	var out bytes.Buffer
	priorTTY := isTTY
	t.Cleanup(func() { isTTY = priorTTY })
	isTTY = func(io.Reader) bool { return true }

	called := 0
	install := func(string) (tools.Installed, error) {
		called++
		return tools.Installed{Name: "syft", Version: "1", Path: "/bin/syft"}, nil
	}
	// "n". Declining proves the prompt was real rather than printed and ignored.
	if err := runToolsInstall(&out, strings.NewReader("n\n"), []string{"syft"}, false,
		toolsInstallOptions{}, install); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Proceed?") {
		t.Errorf("a real download should be approved first:\n%s", out.String())
	}
	if called != 0 {
		t.Errorf("declined, but installed %d tool(s)", called)
	}
}

// `draugr tools install` with no arguments means "everything this host can have". A tool whose
// runtime is not on the machine is not something the command was asked for and failed to do, and
// refusing the batch over it fails nine installs to report a tenth, usually a scanner the
// descriptor never names.
func TestRunToolsInstallAllSkipsAToolWhoseRuntimeIsAbsent(t *testing.T) {
	stubDetect(t, map[string]string{})
	var out bytes.Buffer
	var installed []string
	install := func(name string) (tools.Installed, error) {
		if name == "govulncheck" {
			return tools.Installed{}, fmt.Errorf("no `go` is on PATH: %w", tools.ErrRuntimeMissing)
		}
		installed = append(installed, name)
		return tools.Installed{Name: name, Version: "1.0.0", Path: "/x/" + name}, nil
	}
	if err := runToolsInstall(&out, nil, nil, true, toolsInstallOptions{yes: true}, install); err != nil {
		t.Fatalf("one absent runtime failed the whole batch: %v\n%s", err, out.String())
	}
	if slices.Contains(installed, "govulncheck") {
		t.Error("govulncheck reported as installed when its runtime is absent")
	}
	if len(installed) == 0 {
		t.Fatal("nothing else was installed")
	}
	// Named and with the command to run, so a reader does not have to work out which of ten rows
	// it was.
	for _, want := range []string{"govulncheck", "draugr tools install govulncheck"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("the skipped line never said %q:\n%s", want, out.String())
		}
	}
}

// Asking for a tool by name and being told it worked is the guarantee worth keeping, and the one
// every pipeline relies on. A missing runtime is still a failure there.
func TestRunToolsInstallNamedStillFailsOnAnAbsentRuntime(t *testing.T) {
	stubDetect(t, map[string]string{})
	var out bytes.Buffer
	install := func(string) (tools.Installed, error) {
		return tools.Installed{}, fmt.Errorf("no `go` is on PATH: %w", tools.ErrRuntimeMissing)
	}
	err := runToolsInstall(&out, nil, []string{"govulncheck"}, false, toolsInstallOptions{yes: true}, install)
	if err == nil {
		t.Fatal("a named install with no runtime reported success")
	}
	if !strings.Contains(out.String(), "✗ govulncheck") {
		t.Errorf("the named failure should be flagged as one:\n%s", out.String())
	}
}

// Everything that is not a missing runtime still fails the batch. A download that 404s, a checksum
// that does not match and a disk that is full are all the command failing at what it was asked.
func TestRunToolsInstallAllStillFailsOnAnOrdinaryError(t *testing.T) {
	stubDetect(t, map[string]string{})
	var out bytes.Buffer
	install := func(name string) (tools.Installed, error) {
		if name == "trivy" {
			return tools.Installed{}, errors.New("checksum mismatch")
		}
		return tools.Installed{Name: name, Version: "1.0.0", Path: "/x/" + name}, nil
	}
	if err := runToolsInstall(&out, nil, nil, true, toolsInstallOptions{yes: true}, install); err == nil {
		t.Fatal("a checksum mismatch in the batch reported success")
	}
}

// The JSON is what a pipeline gates on, and it reported success while every upstream was
// unreachable. "Could not reach npm" read as "current", which is the one confusion this format
// exists to prevent and the table mode already avoided.
func TestToolsOutdatedJSONFailsWhenAnUpstreamCouldNotBeAsked(t *testing.T) {
	// A transport that refuses, rather than proxy variables that ask the process to refuse.
	// http.ProxyFromEnvironment reads the environment once and caches it, so setting those
	// variables from inside a test works only while nothing has read them first, and whether
	// anything has is a property of the dependency graph. It is also faster than dialing.
	var out bytes.Buffer
	err := runToolsOutdated(context.Background(), &out, true, unreachableClient())
	if err == nil {
		t.Fatal("every upstream unreachable and the exit code said success")
	}
	// The rows are written even so, because a pipeline wants both the reasons and the failure.
	var rows []struct {
		Tool   string `json:"tool"`
		Behind bool   `json:"behind"`
		Error  string `json:"error"`
	}
	if err := json.Unmarshal(out.Bytes(), &rows); err != nil {
		t.Fatalf("the document was not written: %v\n%s", err, out.String())
	}
	if len(rows) == 0 {
		t.Fatal("no rows")
	}
	for _, r := range rows {
		if r.Error == "" {
			t.Errorf("%s reports no error though nothing could be reached", r.Tool)
		}
		// The trap this documents: unreachable and current are both `behind: false`, so a
		// consumer reading that field alone cannot tell them apart.
		if r.Behind {
			t.Errorf("%s is marked behind on an answer nobody got", r.Tool)
		}
	}
}

// unreachableClient answers every request with a failure, whatever the URL.
func unreachableClient() *http.Client {
	return &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("no route to host")
	})}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// inADescriptorDir runs a test inside a temporary directory holding one descriptor, because the
// question this adds is asked from the reading of the working directory.
func inADescriptorDir(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	body := `project: p
release:
  version: "1.0"
config:
  controls:
    secrets:
      enabled: true
components:
  - name: api
    repositories:
      - url: .
`
	if err := os.WriteFile(filepath.Join(dir, "draugr.saga.yaml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	prior, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(prior) })
}

// TestTheDescriptorBesideYouIsTheAnswer.
//
// Twelve binaries on a machine is a dozen more things to trust, patch and explain, and a small
// service runs three of them. The file that says which three is the one somebody already wrote.
func TestTheDescriptorBesideYouIsTheAnswer(t *testing.T) {
	inADescriptorDir(t)

	var out bytes.Buffer
	got, all, err := installNames(&out, nil, toolsInstallOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if all {
		t.Error("a descriptor was beside it and it asked for the whole catalog")
	}
	if !slices.Contains(got, "gitleaks") {
		t.Errorf("the descriptor's own scanner is missing: %v", got)
	}
	if slices.Contains(got, "nuclei") || slices.Contains(got, "kube-bench") {
		t.Errorf("tools nothing here runs were included: %v", got)
	}
	// Named, because a command that reads a file nobody pointed it at has to say which one.
	if !strings.Contains(out.String(), "draugr.saga.yaml") {
		t.Errorf("it did not say which descriptor it read:\n%s", out.String())
	}
}

// TestTheWholeCatalogIsAskedFor. It is a dozen downloads and a dozen things to keep patched, which
// is a decision rather than somewhere you arrive by typing less.
func TestTheWholeCatalogIsAskedFor(t *testing.T) {
	inADescriptorDir(t)

	var out bytes.Buffer
	_, all, err := installNames(&out, nil, toolsInstallOptions{all: true})
	if err != nil {
		t.Fatal(err)
	}
	if !all {
		t.Error("--all did not ask for the whole catalog")
	}
}

// TestNoDescriptorSaysWhatToDoRatherThanGuessing. The two wrong answers are a dozen silent
// downloads and an empty success, and both look like the command worked.
func TestNoDescriptorSaysWhatToDoRatherThanGuessing(t *testing.T) {
	prior, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(prior) })

	var out bytes.Buffer
	_, _, err = installNames(&out, nil, toolsInstallOptions{})
	if err == nil {
		t.Fatal("a directory saying nothing about scanners was answered with a guess")
	}
	for _, want := range []string{"draugr init", "--all", "draugr tools install trivy"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not offer %q:\n%v", want, err)
		}
	}
}

// TestAnExplicitRequestIsUnchanged. Naming tools, or naming a descriptor, already said what was
// wanted, and reading the directory over the top of that would be the tool not listening.
func TestAnExplicitRequestIsUnchanged(t *testing.T) {
	inADescriptorDir(t)

	var out bytes.Buffer
	got, all, err := installNames(&out, []string{"trivy"}, toolsInstallOptions{})
	if err != nil || all || len(got) != 1 || got[0] != "trivy" {
		t.Errorf("naming a tool gave %v (all=%v, err=%v)", got, all, err)
	}
	if strings.Contains(out.String(), "draugr.saga.yaml") {
		t.Errorf("it read the directory over an explicit request:\n%s", out.String())
	}
}
