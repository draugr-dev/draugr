package report

import (
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/plugin"
)

const (
	trivyMissing   = "run trivy-fs: exec: \"trivy\": executable file not found in $PATH. Run `draugr tools install trivy`"
	trivyIaC       = "run trivy-config: exec: \"trivy\": executable file not found in $PATH. Run `draugr tools install trivy`"
	semgrepMissing = "run semgrep: exec: \"semgrep\": executable file not found in $PATH. Run `draugr tools install semgrep`"
)

// Two tools missing across three controls: each row names its tool, and one command installs both.
func TestConsoleNamesAMissingToolAndInstallsItOnce(t *testing.T) {
	out := renderConsole(t, Data{
		Run: engine.Result{
			Controls: map[string]plugin.ControlResult{},
			ScanErrors: map[string][]string{
				"iac": {trivyIaC}, "sast": {semgrepMissing}, "sca": {trivyMissing},
			},
			MissingTools: []engine.MissingTool{
				{Control: "iac", Tool: "trivy", Provisionable: true, Message: trivyIaC},
				{Control: "sast", Tool: "semgrep", Provisionable: true, Message: semgrepMissing},
				{Control: "sca", Tool: "trivy", Provisionable: true, Message: trivyMissing},
			},
		},
		Verdict: norn.Result{Verdict: norn.Fail},
	})
	want := "CONTROLS\n" +
		"  iac   ERROR  trivy not installed\n" +
		"  sast  ERROR  semgrep not installed\n" +
		"  sca   ERROR  trivy not installed\n" +
		"  draugr tools install semgrep trivy  installs what iac, sast and sca need\n"
	if !strings.Contains(out, want) {
		t.Errorf("controls block:\n%s\nwant:\n%s", out, want)
	}
	if strings.Contains(out, "executable file not found") {
		t.Errorf("the exec error is still printed:\n%s", out)
	}
	if n := strings.Count(out, "draugr tools install"); n != 1 {
		t.Errorf("install command printed %d times:\n%s", n, out)
	}
}

// One control: the verb agrees with it.
func TestConsoleInstallLineForOneControl(t *testing.T) {
	out := renderConsole(t, Data{
		Run: engine.Result{
			Controls:     map[string]plugin.ControlResult{},
			ScanErrors:   map[string][]string{"sast": {semgrepMissing}},
			MissingTools: []engine.MissingTool{{Control: "sast", Tool: "semgrep", Provisionable: true, Message: semgrepMissing}},
		},
		Verdict: norn.Result{Verdict: norn.Fail},
	})
	if !strings.Contains(out, "  draugr tools install semgrep  installs what sast needs\n") {
		t.Errorf("install line:\n%s", out)
	}
}

// A control that also failed for another reason keeps "did not run" and both explanations: the
// missing tool briefly, the other failure in full.
func TestConsoleKeepsOtherFailuresBesideAMissingTool(t *testing.T) {
	other := "run grype: database download failed"
	out := renderConsole(t, Data{
		Run: engine.Result{
			Controls:     map[string]plugin.ControlResult{},
			ScanErrors:   map[string][]string{"sca": {trivyMissing, other}},
			MissingTools: []engine.MissingTool{{Control: "sca", Tool: "trivy", Provisionable: true, Message: trivyMissing}},
		},
		Verdict: norn.Result{Verdict: norn.Fail},
	})
	for _, want := range []string{"sca  ERROR  did not run\n", "trivy not installed\n", other, "draugr tools install trivy  installs what sca needs"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
}

// A control that ran and reported, with one of its scanners missing, says which under its row.
func TestConsoleNamesAMissingToolUnderAControlThatReported(t *testing.T) {
	out := renderConsole(t, Data{
		Run: engine.Result{
			Controls:     map[string]plugin.ControlResult{"sca": {}},
			ScanErrors:   map[string][]string{"sca": {trivyMissing}},
			MissingTools: []engine.MissingTool{{Control: "sca", Tool: "trivy", Provisionable: true, Message: trivyMissing}},
		},
		Verdict: norn.Result{Verdict: norn.Fail, Controls: []norn.ControlOutcome{{Control: "sca", Verdict: norn.Pass}}},
	})
	if !strings.Contains(out, "sca  ERROR") || !strings.Contains(out, "trivy not installed") {
		t.Errorf("controls block:\n%s", out)
	}
	if strings.Contains(out, "executable file not found") {
		t.Errorf("the exec error is still printed:\n%s", out)
	}
}

// A tool `draugr tools install` cannot fetch keeps its own message, which says where to get it,
// and gets no install line.
func TestConsoleLeavesAToolDraugrCannotInstallToItsMessage(t *testing.T) {
	msg := "run prowler: exec: \"prowler\": executable file not found in $PATH. `draugr tools install` does not fetch prowler"
	out := renderConsole(t, Data{
		Run: engine.Result{
			Controls:     map[string]plugin.ControlResult{},
			ScanErrors:   map[string][]string{"cloud": {msg}},
			MissingTools: []engine.MissingTool{{Control: "cloud", Tool: "prowler", Message: msg}},
		},
		Verdict: norn.Result{Verdict: norn.Fail},
	})
	if !strings.Contains(out, "cloud  ERROR  did not run") || !strings.Contains(out, "not fetch prowler") {
		t.Errorf("controls block:\n%s", out)
	}
	if strings.Contains(out, "installs what") {
		t.Errorf("offered an install for a tool Draugr cannot fetch:\n%s", out)
	}
}
