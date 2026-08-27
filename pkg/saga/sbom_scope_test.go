package saga

import (
	"strings"
	"testing"
)

// scopeModel is a minimal valid Saga so a validation error can only have come from the SBOM
// block under test.
func scopeModel(scope SBOMScope) Model {
	return Model{
		Release: Release{Name: "app", Version: "1.0.0"},
		Config:  Config{SBOM: &SBOMConfig{Enabled: true, Scope: scope}},
		Components: []Component{{
			Name: "api", Criticality: Unstated(Criticality("supporting")), Exposure: Unstated(Exposure("internal")),
			Repositories: []Repository{{URL: "."}},
		}},
	}
}

func TestSBOMScopeValidation(t *testing.T) {
	base := scopeModel
	for _, s := range append(SBOMScopes, "") {
		m := base(s)
		if err := m.Validate(); err != nil {
			t.Errorf("scope %q rejected: %v", s, err)
		}
	}
	m := base("everything")
	err := m.Validate()
	if err == nil {
		t.Fatal("an unknown scope was accepted")
	}
	if !strings.Contains(err.Error(), "everything") || !strings.Contains(err.Error(), "project") {
		t.Errorf("error should name the value and the alternatives: %v", err)
	}
}

func TestSBOMScopeHelpers(t *testing.T) {
	for _, tc := range []struct {
		scope              SBOMScope
		project, perTarget bool
	}{
		{SBOMScopeComponent, false, true},
		{SBOMScopeProject, true, false},
		{SBOMScopeBoth, true, true},
	} {
		if tc.scope.Project() != tc.project || tc.scope.PerTarget() != tc.perTarget {
			t.Errorf("%s: project=%v perTarget=%v", tc.scope, tc.scope.Project(), tc.scope.PerTarget())
		}
	}
	if !SBOMScopeProject.Valid() || SBOMScope("nope").Valid() || SBOMScope("").Valid() {
		t.Error("Valid")
	}
}
