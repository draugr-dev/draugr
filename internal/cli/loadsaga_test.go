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

// The zero-config control list appears in the scan help and the run notice. Both must render it
// from syntheticSaga's actual set — hard-coded copies drifted from reality twice before.
func TestZeroConfigControlsMatchSyntheticSaga(t *testing.T) {
	model := syntheticSaga(t.TempDir())
	for name := range model.Config.Controllers {
		if !strings.Contains(ZeroConfigControls("and"), name) {
			t.Errorf("control %q is enabled zero-config but missing from the rendered list %q",
				name, ZeroConfigControls("and"))
		}
	}
	if got := len(model.Config.Controllers); got != len(zeroConfigControls) {
		t.Errorf("synthesized saga enables %d controls, the list names %d", got, len(zeroConfigControls))
	}
	// The help text uses the "and" form; the run notice uses the plain list.
	if got := ZeroConfigControls("and"); got != "sca, secrets, sast, and iac" {
		t.Errorf("conjunction form = %q", got)
	}
	if got := ZeroConfigControls(""); got != "sca, secrets, sast, iac" {
		t.Errorf("plain form = %q", got)
	}
}

func TestScanHelpRendersTheDerivedControls(t *testing.T) {
	long := newScanCommand().Long
	if !strings.Contains(long, ZeroConfigControls("and")) {
		t.Errorf("scan help should render the derived control list, got:\n%s", long)
	}
}
