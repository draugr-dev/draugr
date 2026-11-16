package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/builtins"
)

const validSaga = `project: app
release:
  version: "1.0"
components:
  - name: web
    images:
      - image: alpine:3.19
`

const invalidSaga = `project: app
components:
  - name: web
    exposure: bogus
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

// A value YAML reads as a number or a boolean, in a field that takes text, is a warning under the
// line saying the file is valid, naming the field, the line and the quoted value to write, and the
// command succeeds as it did before. The same holds for a fragment checked on its own.
func TestValidateWarnsAboutUnquotedText(t *testing.T) {
	descriptor := writeSaga(t, `project: app
release:
  version: 1.0
components:
  - name: web
    labels:
      pci: true
    images:
      - image: alpine:3.19
config:
  publishers:
    - kind: file
      dir: true
      reports:
        - format: sarif
`)
	var out bytes.Buffer
	if err := runValidate([]string{descriptor}, &out); err != nil {
		t.Fatalf("runValidate: %v", err)
	}
	for _, want := range []string{
		"is valid\n",
		`  ! release.version: 1.0 on line 3 is read as a number, and this field takes text. Write it in quotes, "1.0"; a later release refuses it unquoted.` + "\n",
		`  ! config.publishers[0].dir: true on line 13 is read as a boolean, and this field takes text. Write it in quotes, "true"; a later release refuses it unquoted.` + "\n",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output does not contain %q:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "labels") {
		t.Errorf("a label's value drew a warning:\n%s", out.String())
	}

	fragment := writeSagaAt(t, t.TempDir(), "team.saga-fragment.yaml", "components:\n  - name: 2026\n")
	out.Reset()
	if err := runValidate([]string{fragment}, &out); err != nil {
		t.Fatalf("runValidate on a fragment: %v", err)
	}
	if want := `components[0].name: 2026 on line 2 is read as a number`; !strings.Contains(out.String(), want) {
		t.Errorf("fragment output does not contain %q:\n%s", want, out.String())
	}

	// A scan prints the same, before it runs, on the writer it is given.
	m, err := loadSaga(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	out.Reset()
	writeDescriptorWarnings(&out, builtins.Registry(), m)
	if got := strings.Count(out.String(), "a later release refuses it unquoted.\n"); got != 2 {
		t.Errorf("a scan wrote %d quoting warnings, want 2:\n%s", got, out.String())
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

// A repo can hold many Sagas, one per service, per environment, so validating them one command
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
	if err.Error() != "1 of 2 Saga files invalid" {
		t.Errorf("err = %q, want the count of each", err)
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
	if !strings.Contains(out.String(), "2 Saga files valid") {
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

// Discovery and the check both treat fragments as their own kind of file, and the help says so.
func TestValidateHelpCoversFragments(t *testing.T) {
	long := newValidateCommand().Long
	for _, want := range []string{"*.saga-fragment.yaml", "fragment schema", "fragments merged in"} {
		if !strings.Contains(long, want) {
			t.Errorf("validate --help is missing %q:\n%s", want, long)
		}
	}
}
