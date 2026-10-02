package saga

import "testing"

// The gate a block asks for, whichever spelling wrote it. A reader of one field alone reports no
// gate for a descriptor that wrote the other.
func TestAGateResolvesFromEitherSpelling(t *testing.T) {
	for _, tc := range []struct {
		name      string
		gate      *GateConfig
		wantKind  GateKind
		wantValue string
	}{
		{"no block", nil, GateNone, ""},
		{"an empty block", &GateConfig{}, GateNone, ""},
		{"a band", &GateConfig{FailOn: "P2"}, GatePriority, "P2"},
		{"a severity", &GateConfig{FailOn: "high"}, GateSeverity, "high"},
		{"the older spelling", &GateConfig{FailOnPriority: "P3"}, GatePriority, "P3"},
		{"the current spelling wins", &GateConfig{FailOn: "P1", FailOnPriority: "P4"}, GatePriority, "P1"},
		{"a value that is neither", &GateConfig{FailOn: "loud"}, GateNone, ""},
		{"an older value that is neither", &GateConfig{FailOnPriority: "loud"}, GateNone, ""},
	} {
		kind, value := tc.gate.Resolved()
		if kind != tc.wantKind || value != tc.wantValue {
			t.Errorf("%s: Resolved() = %v %q, want %v %q", tc.name, kind, value, tc.wantKind, tc.wantValue)
		}
	}
}
