package sarif

import "testing"

func TestSeverityOrdering(t *testing.T) {
	if LevelError.Severity() <= LevelWarning.Severity() {
		t.Error("error should outrank warning")
	}
	if LevelWarning.Severity() <= LevelNote.Severity() {
		t.Error("warning should outrank note")
	}
	if LevelNote.Severity() <= LevelNone.Severity() {
		t.Error("note should outrank none")
	}
	if Level("bogus").Severity() != 0 {
		t.Error("unknown level should have severity 0")
	}
}

func TestAtLeast(t *testing.T) {
	if !LevelError.AtLeast(LevelWarning) {
		t.Error("error should be at least warning")
	}
	if LevelNote.AtLeast(LevelError) {
		t.Error("note should not be at least error")
	}
	if !LevelWarning.AtLeast(LevelWarning) {
		t.Error("warning should be at least warning (equal)")
	}
}
