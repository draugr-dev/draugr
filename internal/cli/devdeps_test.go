package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/builtins"
	"github.com/draugr-dev/draugr/pkg/saga"
)

const sagaWithIncludeDevDeps = `project: app
release:
  version: "1.0"
components:
  - name: web
    repositories:
      - url: ./web
config:
  controls:
    sca:
      enabled: true
      trivyFs:
        includeDevDeps: true
`

const includeDevDepsWarning = "config.controls.sca.trivyFs.includeDevDeps is deprecated and stops being read " +
	"in the next release. Replace it with config.controls.sca.devDependencies: report."

// validate accepts the deprecated key and names what it is read as, under the line saying the file
// is valid.
func TestValidateWarnsOfIncludeDevDeps(t *testing.T) {
	path := writeSaga(t, sagaWithIncludeDevDeps)
	var out bytes.Buffer
	if err := runValidate([]string{path}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "is valid\n  ! "+includeDevDepsWarning+"\n") {
		t.Errorf("validate printed:\n%s\nwant the deprecation under the valid line", out.String())
	}
}

// validate accepts the new key and refuses a value it does not take.
func TestValidateHoldsDevDependenciesToItsValues(t *testing.T) {
	good := strings.Replace(sagaWithIncludeDevDeps, "      trivyFs:\n        includeDevDeps: true\n", "      devDependencies: report\n", 1)
	var out bytes.Buffer
	if err := runValidate([]string{writeSaga(t, good)}, &out); err != nil {
		t.Fatalf("devDependencies: report refused: %v", err)
	}
	if strings.Contains(out.String(), "!") {
		t.Errorf("a descriptor with nothing deprecated drew a warning:\n%s", out.String())
	}
	bad := strings.Replace(good, "devDependencies: report", "devDependencies: include", 1)
	if err := runValidate([]string{writeSaga(t, bad)}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "devDependencies") {
		t.Errorf("devDependencies: include: err %v, want a refusal naming the key", err)
	}
}

// Before a scan the same line goes to the writer it is given, which is stderr, one line each.
func TestScanWritesControlWarnings(t *testing.T) {
	model := &saga.Model{Config: saga.Config{Controls: map[string]saga.ControllerSettings{
		"sca": {"trivyFs": saga.ControllerSettings{"includeDevDeps": true}},
	}}}
	var out bytes.Buffer
	writeControlWarnings(&out, builtins.Registry(), model)
	if out.String() != includeDevDepsWarning+"\n" {
		t.Errorf("wrote %q, want the deprecation", out.String())
	}
	if got := controlWarnings(builtins.Registry(), nil); got != nil {
		t.Errorf("no descriptor: %q", got)
	}
}
