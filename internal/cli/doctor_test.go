package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/builtins"
	"github.com/draugr-dev/draugr/internal/tools"
	"github.com/draugr-dev/draugr/pkg/saga"
)

const doctorSagaRepoAndImage = `release:
  name: app
  version: "1.0"
config:
  controllers:
    sca:
      enabled: true
    images:
      enabled: true
components:
  - name: web
    repositories:
      - url: .
    images:
      - image: alpine:3.19
`

const doctorSagaImagesOnly = `release:
  name: app
  version: "1.0"
config:
  controllers:
    images:
      enabled: true
components:
  - name: web
    images:
      - image: alpine:3.19
`

const doctorSagaNoControls = `release:
  name: app
  version: "1.0"
components:
  - name: web
    images:
      - image: alpine:3.19
`

// fakeDetect reports the given binaries as found (others missing), without touching PATH.
func fakeDetect(found ...string) func(context.Context, tools.Tool) tools.Status {
	set := map[string]bool{}
	for _, b := range found {
		set[b] = true
	}
	return func(_ context.Context, t tools.Tool) tools.Status {
		if set[t.Binary] {
			return tools.Status{Tool: t, Found: true, Path: "/usr/bin/" + t.Binary, Version: "1.2.3"}
		}
		return tools.Status{Tool: t, Found: false}
	}
}

func TestRunDoctorAllPresent(t *testing.T) {
	var out bytes.Buffer
	err := runDoctor(context.Background(), &out, builtins.Registry(),
		writeSaga(t, doctorSagaRepoAndImage), false, fakeDetect("trivy", "git"))
	if err != nil {
		t.Fatalf("runDoctor: %v", err)
	}
	s := out.String()
	for _, want := range []string{"Descriptor  ✓ valid", "trivy", "git", "✓ found", "All required tools present"} {
		if !strings.Contains(s, want) {
			t.Errorf("output missing %q\n%s", want, s)
		}
	}
}

func TestRunDoctorMissingFails(t *testing.T) {
	var out bytes.Buffer
	// git present, trivy missing → non-zero.
	err := runDoctor(context.Background(), &out, builtins.Registry(),
		writeSaga(t, doctorSagaRepoAndImage), false, fakeDetect("git"))
	if err == nil {
		t.Fatal("expected error when a required tool is missing")
	}
	s := out.String()
	if !strings.Contains(s, "✗ missing") || !strings.Contains(s, "trivy.dev") {
		t.Errorf("output should flag the missing tool with a hint\n%s", s)
	}
	if !strings.Contains(s, "tools install") {
		t.Errorf("output should nudge provisioning\n%s", s)
	}
}

func TestRunDoctorInvalidDescriptor(t *testing.T) {
	var out bytes.Buffer
	err := runDoctor(context.Background(), &out, builtins.Registry(),
		writeSaga(t, invalidSaga), false, fakeDetect("trivy", "git"))
	if err == nil {
		t.Fatal("expected error for invalid descriptor")
	}
	if !strings.Contains(err.Error(), "invalid descriptor") {
		t.Errorf("err = %v", err)
	}
	if !strings.Contains(out.String(), "✗ invalid") {
		t.Errorf("output should report the invalid descriptor\n%s", out.String())
	}
}

func TestRunDoctorNoSagaChecksAll(t *testing.T) {
	var out bytes.Buffer
	err := runDoctor(context.Background(), &out, builtins.Registry(),
		"", false, fakeDetect("trivy", "gitleaks", "semgrep", "git"))
	if err != nil {
		t.Fatalf("runDoctor: %v", err)
	}
	s := out.String()
	if strings.Contains(s, "Descriptor") {
		t.Errorf("no saga given → should not print a descriptor line\n%s", s)
	}
	for _, bin := range []string{"trivy", "gitleaks", "semgrep", "git"} {
		if !strings.Contains(s, bin) {
			t.Errorf("full check should include %q\n%s", bin, s)
		}
	}
}

func TestRunDoctorJSON(t *testing.T) {
	var out bytes.Buffer
	err := runDoctor(context.Background(), &out, builtins.Registry(),
		writeSaga(t, doctorSagaRepoAndImage), true, fakeDetect("git"))
	if err == nil {
		t.Fatal("expected error (trivy missing)")
	}
	var report struct {
		Descriptor struct {
			Path  string `json:"path"`
			Valid bool   `json:"valid"`
		} `json:"descriptor"`
		Tools   []map[string]any `json:"tools"`
		Missing int              `json:"missing"`
	}
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out.String())
	}
	if !report.Descriptor.Valid {
		t.Error("descriptor should be reported valid")
	}
	if report.Missing != 1 {
		t.Errorf("missing = %d, want 1", report.Missing)
	}
	if len(report.Tools) != 2 { // trivy + git
		t.Errorf("tools = %d, want 2", len(report.Tools))
	}
}

func TestRequiredToolsDerivation(t *testing.T) {
	reg := builtins.Registry()

	// Repo + image controls → trivy and git.
	model, err := saga.LoadFile(writeSaga(t, doctorSagaRepoAndImage))
	if err != nil {
		t.Fatal(err)
	}
	if got := binaries(requiredTools(reg, model)); !slices.Equal(got, []string{"git", "trivy"}) {
		t.Errorf("repo+image required = %v, want [git trivy]", got)
	}

	// Images only → trivy, no git.
	model, err = saga.LoadFile(writeSaga(t, doctorSagaImagesOnly))
	if err != nil {
		t.Fatal(err)
	}
	if got := binaries(requiredTools(reg, model)); !slices.Equal(got, []string{"trivy"}) {
		t.Errorf("images-only required = %v, want [trivy]", got)
	}
}

func TestDoctorCommandViaCobra(t *testing.T) {
	// A saga with no enabled controls needs no tools, so the command succeeds regardless of
	// what's installed in the test environment.
	cmd := newDoctorCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{writeSaga(t, doctorSagaNoControls)})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !strings.Contains(out.String(), "All required tools present") {
		t.Errorf("output = %q", out.String())
	}
}

func binaries(ts []tools.Tool) []string {
	out := make([]string, len(ts))
	for i, t := range ts {
		out[i] = t.Binary
	}
	return out
}
