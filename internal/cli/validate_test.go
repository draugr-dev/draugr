package cli

import (
	"bytes"
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
    exposure: bogus
`

func TestRunValidateValid(t *testing.T) {
	var out bytes.Buffer
	if err := runValidate(writeSaga(t, validSaga), &out); err != nil {
		t.Fatalf("runValidate: %v", err)
	}
	if !strings.Contains(out.String(), "is valid") {
		t.Errorf("output = %q, want it to mention validity", out.String())
	}
}

func TestRunValidateInvalid(t *testing.T) {
	var out bytes.Buffer
	err := runValidate(writeSaga(t, invalidSaga), &out)
	if err == nil {
		t.Fatal("expected error for invalid saga")
	}
	if !strings.Contains(err.Error(), "invalid exposure") {
		t.Errorf("err = %v, want it to mention the schema problem", err)
	}
}

func TestRunValidateMissingFile(t *testing.T) {
	if err := runValidate(filepath.Join(t.TempDir(), "nope.yaml"), &bytes.Buffer{}); err == nil {
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
