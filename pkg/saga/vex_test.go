package saga

import "testing"

// vexModel is a minimal valid Saga carrying one exclusion, so a validation error can only have
// come from the VEX block under test.
func vexModel(v *VEXDecision) Model {
	return Model{
		Release: Release{Name: "app", Version: "1.0.0"},
		Config: Config{Exclude: []ExcludeRule{{
			Rules: []string{"CVE-2024-0001"}, Reason: "accepted", VEX: v,
		}}},
		Components: []Component{{
			Name: "api", Criticality: Unstated(Criticality("supporting")), Exposure: Unstated(Exposure("internal")),
			Repositories: []Repository{{URL: "."}},
		}},
	}
}

func vexErr(t *testing.T, v *VEXDecision) string {
	t.Helper()
	m := vexModel(v)
	err := m.Validate()
	if err == nil {
		return ""
	}
	return err.Error()
}

func TestVEXDecisionAcceptsTheThreeDeclarableStatuses(t *testing.T) {
	for _, st := range VEXStatuses {
		if got := vexErr(t, &VEXDecision{Status: st}); got != "" {
			t.Errorf("status %q rejected: %s", st, got)
		}
	}
}

// The vocabulary is the whole point of the field: a consumer acts on it without reading it, so a
// value outside the list can be neither passed through nor quietly dropped.
func TestVEXDecisionRejectsAnUnknownStatus(t *testing.T) {
	got := vexErr(t, &VEXDecision{Status: "probably_fine"})
	if got == "" {
		t.Fatal("an unknown status was accepted")
	}
	for _, want := range []string{"probably_fine", VEXNotAffected, VEXAffected, VEXFixed} {
		if !contains(got, want) {
			t.Errorf("error should name %q: %s", want, got)
		}
	}
}

// Suppressing something and calling it under investigation are contradictory, and the error says
// so rather than only listing the alternatives.
func TestVEXDecisionRejectsUnderInvestigationWithAnExplanation(t *testing.T) {
	got := vexErr(t, &VEXDecision{Status: VEXUnderInvestigation})
	if got == "" {
		t.Fatal("under_investigation was accepted on an exclusion")
	}
	if !contains(got, "finished investigating") {
		t.Errorf("error should explain why, got: %s", got)
	}
}

func TestVEXDecisionRequiresAStatus(t *testing.T) {
	if got := vexErr(t, &VEXDecision{Justification: "component_not_present"}); !contains(got, "vex.status is required") {
		t.Errorf("got %q", got)
	}
}

func TestVEXJustificationMustBeInTheVocabulary(t *testing.T) {
	got := vexErr(t, &VEXDecision{Status: VEXNotAffected, Justification: "we checked"})
	if !contains(got, "not one of VEX's justifications") {
		t.Errorf("got %q", got)
	}
	for _, j := range VEXJustifications {
		if err := vexErr(t, &VEXDecision{Status: VEXNotAffected, Justification: j}); err != "" {
			t.Errorf("justification %q rejected: %s", j, err)
		}
	}
}

// A justification answers "why is the product unaffected", so pairing it with a status that
// concedes the product is affected is a descriptor that contradicts itself.
func TestVEXJustificationOnlyAppliesToNotAffected(t *testing.T) {
	got := vexErr(t, &VEXDecision{Status: VEXAffected, Justification: "component_not_present"})
	if !contains(got, "applies only to status not_affected") {
		t.Errorf("got %q", got)
	}
}

func TestVEXValidators(t *testing.T) {
	if !ValidVEXStatus(VEXFixed) || ValidVEXStatus(VEXUnderInvestigation) {
		t.Error("ValidVEXStatus")
	}
	if !ValidVEXJustification("component_not_present") || ValidVEXJustification("nope") {
		t.Error("ValidVEXJustification")
	}
}
