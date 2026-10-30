package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/builtins"
	"github.com/draugr-dev/draugr/internal/tools"
	"github.com/draugr-dev/draugr/pkg/config"
)

// writeConfigFile writes a config file, creating its directory.
func writeConfigFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// The pin doctor reads is the one `tools install` reads, from the same files in the same order:
// the project file over the home file, and --config alone in place of both. Each pin names the
// file it came from, the one `config show` names for it.
func TestToolPinsFollowThePrecedenceAndNameTheirFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv(config.EnvVar, "")
	project := t.TempDir()
	t.Chdir(project)
	homeFile := filepath.Join(home, ".draugr", "config.yaml")
	projectFile := filepath.Join(project, config.FileName)

	writeConfigFile(t, homeFile, "tools:\n  trivy: { version: \"0.60.0\" }\n  gitleaks: { version: \"8.0.0\" }\n")
	pins, err := configuredToolPins()
	if err != nil {
		t.Fatal(err)
	}
	if got := pins["trivy"]; got != (toolPin{Version: "0.60.0", Path: homeFile}) {
		t.Errorf("home file alone: trivy = %+v", got)
	}

	writeConfigFile(t, projectFile, "tools:\n  trivy: { version: \"0.65.0\" }\n")
	pins, err = configuredToolPins()
	if err != nil {
		t.Fatal(err)
	}
	if got := pins["trivy"]; got != (toolPin{Version: "0.65.0", Path: projectFile}) {
		t.Errorf("the project file should win: trivy = %+v", got)
	}
	if got := pins["gitleaks"]; got != (toolPin{Version: "8.0.0", Path: homeFile}) {
		t.Errorf("a pin only the home file sets should stay, named by it: gitleaks = %+v", got)
	}
	wanted, err := wantedVersions(nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if wanted["trivy"] != "0.65.0" || wanted["gitleaks"] != "8.0.0" {
		t.Errorf("tools install reads other pins than doctor: %v", wanted)
	}

	explicit := filepath.Join(t.TempDir(), "ci.yaml")
	writeConfigFile(t, explicit, "tools:\n  trivy: { version: \"0.70.0\" }\n")
	withRootConfig(t, explicit)
	pins, err = configuredToolPins()
	if err != nil {
		t.Fatal(err)
	}
	if got := pins["trivy"]; got != (toolPin{Version: "0.70.0", Path: explicit}) {
		t.Errorf("--config should be read alone: trivy = %+v", got)
	}
	if _, ok := pins["gitleaks"]; ok {
		t.Error("--config should replace the discovered files, and the home pin survived")
	}
}

// Two files holding the same value attribute it to the more specific one, as `config show` does.
func TestToolPinsNameTheMostSpecificFileHoldingTheValue(t *testing.T) {
	res := config.Resolve([]config.Source{
		{Path: "/home/a.yaml", File: config.File{Tools: map[string]config.ToolSettings{"trivy": {Version: "0.60.0"}}}},
		{Path: "/proj/b.yaml", File: config.File{Tools: map[string]config.ToolSettings{"trivy": {Version: "0.60.0"}}}},
		{Path: "/proj/c.yaml", File: config.File{Tools: map[string]config.ToolSettings{"syft": {}}}},
	})
	pins := toolPins(res)
	if got := pins["trivy"].Path; got != "/proj/b.yaml" {
		t.Errorf("trivy pinned in %s, want the most specific file", got)
	}
	if _, ok := pins["syft"]; ok {
		t.Error("an entry with no version is not a pin")
	}
}

// A broken config refuses the command, as it refuses every command that reads the file.
func TestConfiguredToolPinsRefusesABrokenFile(t *testing.T) {
	broken := filepath.Join(t.TempDir(), "broken.yaml")
	writeConfigFile(t, broken, "toolz: {}\n")
	withRootConfig(t, broken)
	if _, err := configuredToolPins(); err == nil {
		t.Fatal("a file with a key Draugr does not have was read as a pin source")
	}
}

// With a pin, the tool is held to the pin rather than to the version Draugr tests, the row names the
// pin and its file, and the advice says what `tools install --force` would put in its place.
func TestTheTableHoldsAPinnedToolToItsPin(t *testing.T) {
	t.Chdir(t.TempDir())
	tested := tools.PinnedVersion("trivy")
	pins := map[string]toolPin{"trivy": {Version: "0.60.0", Path: "/etc/draugr/ci.yaml"}}

	// Running the version Draugr tests is off a pin of another version.
	var buf bytes.Buffer
	writeDoctorTable(&buf, []tools.Status{toolAt("trivy", tested)}, pins)
	out := buf.String()
	if !strings.Contains(out, "pinned to 0.60.0 in /etc/draugr/ci.yaml") {
		t.Errorf("the row does not name the pin and its file:\n%s", out)
	}
	if strings.Contains(out, "tested against") {
		t.Errorf("a pinned tool was compared with the version Draugr tests:\n%s", out)
	}
	if !strings.Contains(out, "1 installed tool is not at its pinned version. "+
		"`draugr tools install --force` installs the pinned build.") {
		t.Errorf("the count or the advice ignores the pin:\n%s", out)
	}

	// Running the pin is current, though it is not the version Draugr tests. The row still names
	// the file that pins it, because it is why the row is held to it, and no version, because the
	// tool is at it.
	buf.Reset()
	writeDoctorTable(&buf, []tools.Status{toolAt("trivy", "v0.60.0")}, pins)
	out = buf.String()
	if strings.Contains(out, "not the version") || strings.Contains(out, "pinned version") {
		t.Errorf("a tool running its pin was warned:\n%s", out)
	}
	if !strings.Contains(out, "pinned in /etc/draugr/ci.yaml") || strings.Contains(out, "pinned to") {
		t.Errorf("a tool running its pin should name the file and not a version:\n%s", out)
	}
}

// One tool off its pin and one off the tested build are counted apart, and the advice covers both.
func TestTheTableCountsPinnedAndTestedApart(t *testing.T) {
	t.Chdir(t.TempDir())
	pins := map[string]toolPin{"trivy": {Version: "0.60.0", Path: "/etc/draugr/ci.yaml"}}
	var buf bytes.Buffer
	writeDoctorTable(&buf, []tools.Status{toolAt("trivy", "0.1.0"), toolAt("gitleaks", "0.1.0"), toolAt("syft", "0.1.0")}, pins)
	want := "2 installed tools are not the version Draugr tests and 1 is not at its pinned version. " +
		"`draugr tools install --force` installs the pinned build where there is a pin and the tested build otherwise."
	if !strings.Contains(buf.String(), want) {
		t.Errorf("want %q in:\n%s", want, buf.String())
	}
	if got := offTargetPhrase(0, 2); got != "2 installed tools are not at their pinned versions" {
		t.Errorf("plural = %q", got)
	}
}

// A pin is resolved the way `tools install` resolves it, so a leading v or surrounding space in
// the file is not a difference.
func TestVersionTargetResolvesAPinAsInstallDoes(t *testing.T) {
	for _, pin := range []string{"0.60.0", "v0.60.0", " 0.60.0 "} {
		target := versionTargetFor("trivy", map[string]toolPin{"trivy": {Version: pin}})
		if target.version != "0.60.0" || target.pin == nil {
			t.Errorf("pin %q resolved to %+v", pin, target)
		}
	}
	// A tool Draugr cannot install keeps the pin as written, so the comparison still happens.
	target := versionTargetFor("not-a-tool", map[string]toolPin{"not-a-tool": {Version: "v1.0"}})
	if target.version != "1.0" {
		t.Errorf("an uninstallable pin resolved to %q", target.version)
	}
}

// The JSON carries the pin and its file when a tool is off it, and testedVersion only for a tool
// with no pin, so presence stays the whole answer.
func TestDoctorJSONCarriesThePin(t *testing.T) {
	detect := func(_ context.Context, tl tools.Tool) tools.Status {
		return tools.Status{Tool: tl, Found: true, Version: "0.1.0", Path: "/usr/bin/" + tl.Binary}
	}
	pins := map[string]toolPin{"trivy": {Version: "0.60.0", Path: "/etc/draugr/ci.yaml"}}
	var out bytes.Buffer
	if err := runDoctor(context.Background(), &out, builtins.Registry(), "", doctorRun{json: true, pins: pins}, detect, nil); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Tools []toolReport `json:"tools"`
	}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, tr := range got.Tools {
		switch tr.Binary {
		case "trivy":
			seen++
			if tr.PinnedVersion != "0.60.0" || tr.PinnedIn != "/etc/draugr/ci.yaml" || tr.TestedVersion != "" {
				t.Errorf("trivy = %+v, want the pin and its file and no testedVersion", tr)
			}
		case "gitleaks":
			seen++
			if tr.TestedVersion == "" || tr.PinnedVersion != "" {
				t.Errorf("gitleaks = %+v, want testedVersion alone", tr)
			}
		}
	}
	if seen != 2 {
		t.Fatalf("expected trivy and gitleaks in the report:\n%s", out.String())
	}
}

// --strict fails on a tool off its pin, and passes a tool running its pin that is not the version
// Draugr tests.
func TestDoctorStrictHoldsAPinnedToolToItsPin(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv(config.EnvVar, "")
	t.Chdir(t.TempDir())
	saga := writeSaga(t, doctorSagaSASTDefault)
	// Every tool at the version Draugr tests, except semgrep, which is at its pin.
	detect := func(_ context.Context, tl tools.Tool) tools.Status {
		v := tools.PinnedVersion(tl.Binary)
		if tl.Binary == "semgrep" {
			v = "0.60.0"
		}
		if v == "" {
			v = "1.0.0"
		}
		return tools.Status{Tool: tl, Found: true, Version: v, Path: "/usr/bin/" + tl.Binary}
	}
	pins := map[string]toolPin{"semgrep": {Version: "0.60.0", Path: "/etc/draugr/ci.yaml"}}
	var out bytes.Buffer
	if err := runDoctor(context.Background(), &out, builtins.Registry(), saga, doctorRun{strict: true, pins: pins}, detect, nil); err != nil {
		t.Fatalf("a tool running its pin failed --strict: %v\n%s", err, out.String())
	}

	out.Reset()
	pins["semgrep"] = toolPin{Version: "0.65.0", Path: "/etc/draugr/ci.yaml"}
	err := runDoctor(context.Background(), &out, builtins.Registry(), saga, doctorRun{strict: true, pins: pins}, detect, nil)
	if err == nil || !strings.Contains(err.Error(), "1 installed tool is not at its pinned version; run `draugr tools install --force`") {
		t.Fatalf("err = %v, want --strict to fail on semgrep's pin\n%s", err, out.String())
	}
}
