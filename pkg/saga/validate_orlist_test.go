package saga

import (
	"strings"
	"testing"
)

// A closed vocabulary offered back to somebody who missed it reads as a sentence, never as a Go
// slice. `%v` prints `[public authenticated internal restricted]`: brackets nobody typed and no
// separators, shown at the moment somebody is stuck.
func TestAVocabularyIsOfferedAsASentence(t *testing.T) {
	for _, tc := range []struct {
		name string
		got  string
		want string
	}{
		{"exposures", orList(Exposures), "public, authenticated, internal or restricted"},
		{"priorities", orList(Priorities), "P1, P2, P3 or P4"},
		{"two values", orList(BuiltByValues), "self or upstream"},
		{"one value", orList([]Exposure{"public"}), "public"},
		{"none", orList([]Exposure{}), ""},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %q, want %q", tc.name, tc.got, tc.want)
		}
	}
}

// The shape this replaced, held to by the errors themselves rather than by remembering. A bracket
// in a message about a value is the Go slice leaking through.
func TestNoValidationErrorPrintsAGoSlice(t *testing.T) {
	m := &Model{
		Project: "x",
		Release: Release{Version: "1"},
		Config: Config{
			Gate: &GateConfig{FailOnPriority: "P9"},
			SBOM: &SBOMConfig{Format: "nonsense", Scope: "nonsense"},
		},
		Components: []Component{{
			Name: "a", Exposure: "nonsense", Criticality: "nonsense", BuiltBy: "aliens",
		}},
	}
	err := m.Validate()
	if err == nil {
		t.Fatal("a descriptor wrong in six ways validated")
	}
	for _, line := range strings.Split(err.Error(), "\n") {
		if strings.Contains(line, "[") && strings.Contains(line, "]") &&
			!strings.Contains(line, "[0]") && !strings.Contains(line, "[1]") {
			t.Errorf("a value list is printed as a Go slice: %s", line)
		}
	}
}
