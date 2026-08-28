package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validSaga = `release:
  name: app
  version: "1.0"
components:
  - name: web
    images:
      - image: alpine:3.19
`

const invalidSaga = `release:
  name: app
components:
  - name: web
    exposure:
      value: bogus
`

func TestRunValidateValid(t *testing.T) {
	var out bytes.Buffer
	if err := runValidate([]string{writeSaga(t, validSaga)}, &out); err != nil {
		t.Fatalf("runValidate: %v", err)
	}
	if !strings.Contains(out.String(), "is valid") {
		t.Errorf("output = %q, want it to mention validity", out.String())
	}
}

func TestRunValidateInvalid(t *testing.T) {
	var out bytes.Buffer
	err := runValidate([]string{writeSaga(t, invalidSaga)}, &out)
	if err == nil {
		t.Fatal("expected error for invalid saga")
	}
	if !strings.Contains(err.Error(), "invalid exposure") {
		t.Errorf("err = %v, want it to mention the schema problem", err)
	}
}

func TestRunValidateMissingFile(t *testing.T) {
	if err := runValidate([]string{filepath.Join(t.TempDir(), "nope.yaml")}, &bytes.Buffer{}); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestValidateCommandViaCobra(t *testing.T) {
	cmd := newValidateCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{writeSaga(t, validSaga)})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !strings.Contains(out.String(), "is valid") {
		t.Errorf("output = %q", out.String())
	}
}

// A repo can hold many Sagas — one per service, per environment — so validating them one command
// at a time doesn't scale, and CI wants a single exit code over all of them.
func writeSagaAt(t *testing.T, dir, name, body string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestValidateDiscoversSagasWhenGivenNoArguments(t *testing.T) {
	dir := t.TempDir()
	writeSagaAt(t, dir, "draugr.saga.yaml", validSaga)
	writeSagaAt(t, filepath.Join(dir, "svc"), "api.saga.yaml", validSaga)
	// Neither of these is a Saga; discovery must not pick them up.
	writeSagaAt(t, dir, "values.yaml", "not: a saga")
	writeSagaAt(t, filepath.Join(dir, "node_modules"), "dep.saga.yaml", invalidSaga)

	found, err := discoverSagas(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 2 {
		t.Fatalf("discovered %v, want the two *.saga.yaml files", found)
	}
	for _, f := range found {
		if strings.Contains(f, "node_modules") {
			t.Errorf("discovery should skip node_modules, got %s", f)
		}
	}
}

func TestValidateReportsEveryFileAndFailsIfAnyIsInvalid(t *testing.T) {
	dir := t.TempDir()
	good := writeSagaAt(t, dir, "good.saga.yaml", validSaga)
	bad := writeSagaAt(t, dir, "bad.saga.yaml", invalidSaga)

	var out bytes.Buffer
	err := runValidate([]string{good, bad}, &out)
	if err == nil {
		t.Fatal("one invalid file should fail the command")
	}
	s := out.String()
	// The valid one is still reported: a failure must not hide the rest.
	if !strings.Contains(s, "good.saga.yaml is valid") {
		t.Errorf("valid file should still be reported:\n%s", s)
	}
	if !strings.Contains(s, "✗") || !strings.Contains(s, "bad.saga.yaml") {
		t.Errorf("invalid file should be named:\n%s", s)
	}
}

func TestValidateExpandsGlobs(t *testing.T) {
	dir := t.TempDir()
	writeSagaAt(t, dir, "a.saga.yaml", validSaga)
	writeSagaAt(t, dir, "b.saga.yaml", validSaga)

	var out bytes.Buffer
	if err := runValidate([]string{filepath.Join(dir, "*.saga.yaml")}, &out); err != nil {
		t.Fatalf("glob validate: %v", err)
	}
	if !strings.Contains(out.String(), "2 Saga file(s) valid") {
		t.Errorf("both files should be validated:\n%s", out.String())
	}
}

func TestValidateGlobWithNoMatchesIsAnError(t *testing.T) {
	// Silently succeeding on a typo'd pattern would make a CI lint step useless.
	if err := runValidate([]string{filepath.Join(t.TempDir(), "*.saga.yaml")}, &bytes.Buffer{}); err == nil {
		t.Error("a pattern matching nothing should be an error")
	}
}

func TestValidateDeduplicatesPaths(t *testing.T) {
	dir := t.TempDir()
	p := writeSagaAt(t, dir, "a.saga.yaml", validSaga)
	var out bytes.Buffer
	if err := runValidate([]string{p, p, filepath.Join(dir, "*.saga.yaml")}, &out); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(out.String(), "is valid"); n != 1 {
		t.Errorf("the same file should be validated once, got %d reports:\n%s", n, out.String())
	}
}
