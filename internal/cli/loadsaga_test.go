package cli

import (
	"strings"
	"testing"
)

func TestLoadSagaValid(t *testing.T) {
	m, err := loadSaga(writeSaga(t, validSaga))
	if err != nil {
		t.Fatalf("loadSaga: %v", err)
	}
	if len(m.Components) != 1 {
		t.Errorf("components = %d, want 1", len(m.Components))
	}
}

func TestLoadSagaInvalidHasContextAndHint(t *testing.T) {
	path := writeSaga(t, invalidSaga)
	_, err := loadSaga(path)
	if err == nil {
		t.Fatal("expected error for invalid saga")
	}
	msg := err.Error()
	for _, want := range []string{
		"is not a valid Saga",         // states it's a descriptor problem
		"invalid exposure",            // includes the underlying validation detail
		"release.version is required", // aggregates all problems, not just the first
		"draugr validate " + path,     // points at the fix
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("error missing %q\ngot: %s", want, msg)
		}
	}
	// The aggregated detail is indented under the summary line.
	if !strings.Contains(msg, "\n  ") {
		t.Errorf("expected indented detail, got: %s", msg)
	}
}
