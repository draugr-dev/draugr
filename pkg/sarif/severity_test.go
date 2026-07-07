package sarif

import "testing"

func TestSeverityOrdering(t *testing.T) {
	if !(LevelError.Severity() > LevelWarning.Severity() &&
		LevelWarning.Severity() > LevelNote.Severity() &&
		LevelNote.Severity() > LevelNone.Severity()) {
		t.Fatal("severity ordering is wrong")
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
