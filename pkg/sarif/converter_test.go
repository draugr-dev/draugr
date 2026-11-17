package sarif

import (
	"slices"
	"testing"
)

// A converter's stamp and the CWE ids it stated survive results.sarif, so `draugr diff` and every
// platform format read back whose word a finding's properties rest on.
func TestAConverterStampSurvivesResultsSARIF(t *testing.T) {
	stamp := &Converter{Name: "npm-audit", Version: "1.0.0", Contract: 1, SHA256: "ab", Set: []string{"package", "cwe"},
		Raise: &Raise{Priority: "P1", Reason: "on the internal exploited list"}}
	rep := Report{Tool: "npm audit", Results: []Result{{RuleID: "GHSA-xvch-5gv4-984h", Level: LevelError, Message: "m",
		CWE: []string{"CWE-1321"}, Converter: stamp}}}
	data, err := rep.MarshalSARIF()
	if err != nil {
		t.Fatal(err)
	}
	back, err := FromSARIF(data)
	if err != nil {
		t.Fatal(err)
	}
	got := back.Results[0]
	if got.Converter == nil || got.Converter.Name != "npm-audit" || got.Converter.SHA256 != "ab" ||
		!slices.Equal(got.Converter.Set, stamp.Set) || *got.Converter.Raise != *stamp.Raise || !slices.Equal(got.CWE, []string{"CWE-1321"}) {
		t.Errorf("read back %+v, cwe %v", got.Converter, got.CWE)
	}
	// Another tool's file read for import never carries a stamp, whatever its property bag names.
	foreign, _, err := FromForeignSARIF(data, nil)
	if err != nil {
		t.Fatal(err)
	}
	if foreign.Results[0].Converter != nil || foreign.Results[0].CWE != nil {
		t.Errorf("a foreign file set a stamp: %+v", foreign.Results[0])
	}
}

// A band a converter's raise moved is told apart from a control's floor by its reason.
func TestARaiseIsToldApartFromAFloor(t *testing.T) {
	c := &Converter{Name: "acme-deps", Raise: &Raise{Priority: "P1", Reason: "listed"}}
	if got := c.RaiseNote(); got != "raised to P1 by converter acme-deps, listed" {
		t.Errorf("note %q", got)
	}
	if (&Converter{Name: "x"}).RaiseNote() != "" || (*Converter)(nil).RaiseNote() != "" {
		t.Error("a converter that asked no raise has a note")
	}
	raised := Result{Converter: c, PriorityFloor: c.RaiseNote()}
	floored := Result{Converter: c, PriorityFloor: "secrets are ranked P1 wherever they are found"}
	if !raised.RaisedByConverter() || floored.RaisedByConverter() || (Result{}).RaisedByConverter() {
		t.Error("RaisedByConverter mistakes a control's floor for a raise, or the reverse")
	}
}
