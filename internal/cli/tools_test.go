package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
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
	if err := runToolsInstall(&out, nil, []string{"trivy", "gitleaks"}, toolsInstallOptions{yes: true}, install); err != nil {
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
		{tools.Installed{ProvenanceNote: "cosign not installed — skipped signature check"}, "sha256 verified; cosign not installed — skipped signature check"},
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
	if err := runToolsInstall(&out, nil, []string{"trivy", "cosign"}, toolsInstallOptions{dryRun: true}, install); err != nil {
		t.Fatal(err)
	}
	if called {
		t.Error("--dry-run must not install anything")
	}
	s := out.String()
	for _, want := range []string{"Install plan", "trivy", "cosign", "scanner", "utility", "dry run"} {
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
	if err := runToolsInstall(&out, strings.NewReader("n\n"), []string{"trivy"}, toolsInstallOptions{}, install); err != nil {
		t.Fatal(err)
	}
	if called {
		t.Error("a declined prompt must not install anything")
	}
	if !strings.Contains(out.String(), "Aborted") {
		t.Errorf("expected abort, got:\n%s", out.String())
	}
}

func TestRunToolsInstallSemgrepHint(t *testing.T) {
	// Stubbed absent. Without this the test asks the machine it runs on, and passes or fails
	// depending on whether the developer happens to have semgrep — which is how it read as a
	// regression the first time the installer learned to check.
	stubDetect(t, map[string]string{})
	var out bytes.Buffer
	called := false
	install := func(string) (tools.Installed, error) { called = true; return tools.Installed{}, nil }
	if err := runToolsInstall(&out, nil, []string{"semgrep"}, toolsInstallOptions{yes: true}, install); err != nil {
		t.Fatalf("runToolsInstall: %v", err)
	}
	if called {
		t.Error("semgrep should not go through the binary installer")
	}
	if !strings.Contains(out.String(), tools.SemgrepPipxCommand()) {
		t.Errorf("expected the pipx hint, got:\n%s", out.String())
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
	err := runToolsInstall(&out, nil, []string{"trivy"}, toolsInstallOptions{yes: true}, install)
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
	// Empty names → install everything installable, then print the semgrep hint.
	if err := runToolsInstall(&out, nil, nil, toolsInstallOptions{yes: true}, install); err != nil {
		t.Fatalf("runToolsInstall: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("expected installable tools to be installed")
	}
	for _, name := range got {
		if name == "semgrep" {
			t.Error("semgrep must not be passed to the binary installer")
		}
	}
	if !strings.Contains(out.String(), tools.SemgrepPipxCommand()) {
		t.Error("installing everything should still surface the semgrep hint")
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
		"trivy", "gitleaks", "semgrep", "git", "pipx",
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

// A misspelled tool used to be rendered as a row of dashes in the install plan, followed by a
// confirmation prompt. It's a typo — say so and stop.
func TestToolsInstallRejectsUnknownTool(t *testing.T) {
	var out bytes.Buffer
	called := false
	install := func(string) (tools.Installed, error) {
		called = true
		return tools.Installed{}, nil
	}
	err := runToolsInstall(&out, nil, []string{"notarealtool"}, toolsInstallOptions{yes: true}, install)
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
	err := runToolsInstall(&bytes.Buffer{}, nil, []string{"trivvy"}, toolsInstallOptions{yes: true},
		func(string) (tools.Installed, error) { return tools.Installed{}, nil })
	if err == nil || !strings.Contains(err.Error(), `did you mean "trivy"`) {
		t.Errorf("expected a suggestion for a near-miss, got %v", err)
	}
}

// One bad name fails the whole command: half-installing after a typo is the surprising outcome.
func TestToolsInstallRejectsMixedValidAndInvalid(t *testing.T) {
	installed := 0
	err := runToolsInstall(&bytes.Buffer{}, nil, []string{"trivy", "nope"}, toolsInstallOptions{yes: true},
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

const toolsSagaTwoControls = `release: {name: t, version: "1.0"}
config:
  controllers:
    sca: {enabled: true}
    secrets: {enabled: true}
components:
  - name: c
    repositories: [{url: "https://example.com/x.git"}]
`

// The point of the flag: install what this project runs, not the catalogue. On a security tool
// every binary put on PATH is one more thing to trust and patch, so the smaller set is the
// defensible one.
func TestInstallNamesFromSaga(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	got, err := installNames(&out, nil, toolsInstallOptions{saga: writeSaga(t, toolsSagaTwoControls)})
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

// Without the flag nothing changes — a pipeline that provisions the catalogue keeps doing so.
func TestInstallNamesWithoutSagaIsUnchanged(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	got, err := installNames(&out, nil, toolsInstallOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("names = %v, want none — an empty list means the whole catalogue downstream", got)
	}

	named, err := installNames(&out, []string{"trivy"}, toolsInstallOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(named, []string{"trivy"}) {
		t.Errorf("explicit names should pass through, got %v", named)
	}
}

// Two ways of saying what to install, pointing at different sets. Guessing which one was meant
// is how you install the wrong thing quietly.
func TestInstallNamesRejectsSagaWithExplicitTools(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	_, err := installNames(&out, []string{"trivy"}, toolsInstallOptions{saga: writeSaga(t, toolsSagaTwoControls)})
	if err == nil {
		t.Fatal("want an error")
	}
	if !strings.Contains(err.Error(), "trivy") {
		t.Errorf("the error should name what was asked for, got: %v", err)
	}
}

func TestInstallNamesReportsABadSaga(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	if _, err := installNames(&out, nil, toolsInstallOptions{saga: "/nonexistent/saga.yaml"}); err == nil {
		t.Error("an unreadable descriptor must fail rather than installing everything")
	}
}

// The note is the compromise that lets the default stay as it was: behaviour unchanged, the
// better option surfaced where it is relevant. Its number has to match what --saga would
// actually install, or it promises a saving the flag does not deliver.
func TestNoteDescriptorInWorkingDir(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	var out bytes.Buffer
	noteDescriptorInWorkingDir(&out)
	if out.String() != "" {
		t.Errorf("no descriptor here, so nothing to note; got %q", out.String())
	}

	if err := os.WriteFile(filepath.Join(dir, "draugr.saga.yaml"), []byte(toolsSagaTwoControls), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	noteDescriptorInWorkingDir(&out)
	// Two of the catalogue, not three: git is needed but cannot be provisioned, and counting it
	// would advertise a saving --saga does not make.
	want := fmt.Sprintf("would install 2 of these %d tools", len(tools.Installable()))
	if !strings.Contains(out.String(), want) {
		t.Errorf("note = %q, want it to contain %q", out.String(), want)
	}

	// An unreadable descriptor is scan's problem to report, not a reason to fail provisioning.
	if err := os.WriteFile(filepath.Join(dir, "draugr.saga.yaml"), []byte("{{not yaml"), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	noteDescriptorInWorkingDir(&out)
	if out.String() != "" {
		t.Errorf("a broken descriptor should be left to scan and doctor, got %q", out.String())
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
	// The plan is the moment someone decides whether to let a security tool write to their
	// machine, and it was describing work it would not do — six rows for one download.
	stubDetect(t, map[string]string{"trivy": "0.69.3"})
	var out bytes.Buffer
	names := []string{"trivy", "gitleaks"}
	writeInstallPlan(&out, names, false, present(context.Background(), names, toolsInstallOptions{}), toolsInstallOptions{})

	got := out.String()
	if !strings.Contains(got, "already at 0.69.3") {
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
	current := map[string]string{"semgrep": tools.SemgrepVersion()}
	for _, name := range tools.Installable() {
		if spec, ok := tools.Spec(name); ok {
			current[spec.Binary] = spec.Version
		}
	}
	stubDetect(t, current)

	var out bytes.Buffer
	installed := 0
	err := runToolsInstall(&out, strings.NewReader(""), nil, toolsInstallOptions{},
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
	if strings.Contains(got, "pipx install") {
		t.Error("semgrep is present; telling the user to install it reads as a failure")
	}
}

func TestInstallStillPrintsTheSemgrepHintWhenAbsent(t *testing.T) {
	stubDetect(t, map[string]string{})
	var out bytes.Buffer
	_ = runToolsInstall(&out, strings.NewReader(""), []string{"semgrep"}, toolsInstallOptions{},
		func(string) (tools.Installed, error) { return tools.Installed{}, nil })
	if !strings.Contains(out.String(), "pipx install") {
		t.Errorf("an absent semgrep still needs its instruction:\n%s", out.String())
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
