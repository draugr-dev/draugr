package sealed

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckErrors(t *testing.T) {
	report := []byte(`{"controls":[
	  {"name":"sca","verdict":"error","scanErrors":["run trivy-fs: exec: \"trivy\": executable file not found"]},
	  {"name":"sast","verdict":"fail"},
	  {"name":"iac","verdict":"pass","scanErrors":["run trivy-config: exit status 1"]}]}`)

	problems, err := CheckErrors([]ErrorExpectation{{Control: "sca", Contains: "executable file not found"}}, report)
	if err != nil {
		t.Fatal(err)
	}
	// iac passed yet carries an error, which is a control that did not finish.
	if len(problems) != 1 || !strings.Contains(problems[0], "control iac could not run") {
		t.Errorf("problems = %v", problems)
	}

	problems, err = CheckErrors([]ErrorExpectation{
		{Control: "sca", Contains: "exit status 2"},
		{Control: "sast", Contains: "anything"},
		{Control: "iac", Contains: "exit status 1"},
	}, report)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(problems, "\n")
	for _, want := range []string{
		`control sca failed with "run trivy-fs`,
		`control sast ran; the scenario expects it to fail with "anything"`,
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("problems lack %q:\n%s", want, joined)
		}
	}
	if _, err := CheckErrors(nil, []byte("{")); err == nil {
		t.Error("an unreadable report was accepted")
	}
}

func TestHideAndFail(t *testing.T) {
	a, b, clean := t.TempDir(), t.TempDir(), t.TempDir()
	for _, f := range []string{filepath.Join(a, "trivy"), filepath.Join(a, "gitleaks"), filepath.Join(b, "trivy")} {
		if err := os.WriteFile(f, []byte("#!/bin/sh\n"), 0o700); err != nil { // #nosec G306 -- an executable fixture
			t.Fatal(err)
		}
	}
	c := Container{Work: t.TempDir(), Path: strings.Join([]string{a, b, clean}, string(os.PathListSeparator))}
	if err := c.Hide("trivy"); err != nil {
		t.Fatal(err)
	}
	dirs := filepath.SplitList(c.Path)
	if len(dirs) != 3 || dirs[0] == a || dirs[1] == b || dirs[2] != clean {
		t.Fatalf("PATH = %v", dirs)
	}
	for _, d := range dirs[:2] {
		if _, err := os.Lstat(filepath.Join(d, "trivy")); err == nil {
			t.Errorf("%s still holds trivy", d)
		}
	}
	// Everything else in a shadowed directory is still there.
	if target, err := os.Readlink(filepath.Join(dirs[0], "gitleaks")); err != nil || target != filepath.Join(a, "gitleaks") {
		t.Errorf("gitleaks = %q (%v)", target, err)
	}

	if err := c.Fail("gitleaks"); err != nil {
		t.Fatal(err)
	}
	first := filepath.SplitList(c.Path)[0]
	script, err := os.ReadFile(filepath.Join(first, "gitleaks")) // #nosec G304 -- under t.TempDir()
	if err != nil || !strings.Contains(string(script), FailingToolMessage) || !strings.Contains(string(script), "exit 2") {
		t.Errorf("failing gitleaks = %q (%v)", script, err)
	}
}

func TestAllowMissing(t *testing.T) {
	n := Normalizer{Clear: [][]string{{"scanners", "*", "version"}}, AllowMissing: true}
	if _, err := n.Apply([]byte(`{"scanners":[{"name":"trivy-fs"}]}`)); err != nil {
		t.Errorf("a missing field was refused under AllowMissing: %v", err)
	}
}

func TestLeavesFieldsUnwritten(t *testing.T) {
	for _, c := range []struct {
		name string
		e    Expected
		want bool
	}{
		{"a control fails", Expected{Errors: []ErrorExpectation{{Control: "sca"}}, Findings: []FindingExpectation{{}}}, true},
		{"nothing is found", Expected{}, true},
		{"a finding", Expected{Findings: []FindingExpectation{{Location: "pom.xml"}, {Location: "pom.xml:8"}}}, false},
		{"only whole-file findings", Expected{Findings: []FindingExpectation{{Location: "pom.xml"}}}, true},
		{"a secret", Expected{Secrets: []SecretExpectation{{}}}, false},
		{"only secrets in history", Expected{Secrets: []SecretExpectation{{Removed: true}, {Removed: true}}}, true},
		{"a secret in history and one in the tree", Expected{Secrets: []SecretExpectation{{Removed: true}, {}}}, false},
		{"a secret in history and a finding", Expected{Secrets: []SecretExpectation{{Removed: true}}, Findings: []FindingExpectation{{}}}, false},
	} {
		if got := c.e.LeavesFieldsUnwritten(); got != c.want {
			t.Errorf("%s: LeavesFieldsUnwritten = %v, want %v", c.name, got, c.want)
		}
	}
}
