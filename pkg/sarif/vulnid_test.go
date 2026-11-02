package sarif

import "testing"

func TestVulnerabilityIDIgnoresWhatAScannerAppends(t *testing.T) {
	// Grype reports the identifier plus the package it found it in, because one advisory can
	// affect several packages in one scan. Anything asking which vulnerability a finding is about
	// has to see through that, or it answers for one scanner and silently not the other.
	for _, tc := range []struct{ ruleID, want string }{
		{"CVE-2019-1010083", "CVE-2019-1010083"},
		{"CVE-2019-1010083-flask", "CVE-2019-1010083"},
		{"GHSA-562c-5r94-xh97-flask", "GHSA-562c-5r94-xh97"},
		{"GO-2022-1059", "GO-2022-1059"},
		{"RUSTSEC-2020-0159", "RUSTSEC-2020-0159"},
		{"OSV-2021-1234", "OSV-2021-1234"},
		// Trivy's identifiers for advisories that have no CVE, as it reports them.
		{"NSWG-ECO-408", "NSWG-ECO-408"},
		{"TEMP-0628843-DBAD28", "TEMP-0628843-DBAD28"},
		{"TEMP-0000000-153207", "TEMP-0000000-153207"},
		{"DLA-4867-1", "DLA-4867-1"},
	} {
		if got := (Result{RuleID: tc.ruleID}).VulnerabilityID(); got != tc.want {
			t.Errorf("%q → %q, want %q", tc.ruleID, got, tc.want)
		}
	}
}

func TestVulnerabilityIDIsEmptyForFindingsThatAreNotVulnerabilities(t *testing.T) {
	// A leaked credential and a misconfigured security group are real findings with no advisory
	// to be un-affected by. Describing them in a VEX document would be calling them something
	// they are not.
	for _, ruleID := range []string{
		"private-key",
		"generic-api-key",
		"go.lang.security.audit.dangerous-exec-command.dangerous-exec-command",
		"AVD-KSV-0012",
		// Trivy's misconfiguration checks share the shape of an advisory and are not one.
		"KSV-0012",
		"DS-0002",
		"AZU-0001",
		"",
	} {
		if got := (Result{RuleID: ruleID}).VulnerabilityID(); got != "" {
			t.Errorf("%q → %q, want empty", ruleID, got)
		}
	}
}

// The other identifiers a scanner reported for a finding name each vulnerability once, leaving out
// the rule id's own and anything that is not a vulnerability identifier.
func TestAliasVulnerabilityIDs(t *testing.T) {
	r := Result{RuleID: "CVE-2026-1", Aliases: []string{
		"CVE-2026-1", "GHSA-cg2g-xh64-v4q7", "retirejs:x:1", "GHSA-cg2g-xh64-v4q7", "",
	}}
	if got := r.AliasVulnerabilityIDs(); len(got) != 1 || got[0] != "GHSA-cg2g-xh64-v4q7" {
		t.Errorf("ids = %q, want the GitHub advisory id once", got)
	}
	if got := (Result{RuleID: "CVE-2026-1"}).AliasVulnerabilityIDs(); got != nil {
		t.Errorf("ids = %q, want none", got)
	}
}

func TestVulnerabilityIDDoesNotMatchMidString(t *testing.T) {
	// Anchored at the front: a rule id that merely mentions an advisory is not a finding about
	// it, and a wrong identifier in a document a stranger's tooling matches against is worse
	// than a missing one.
	if got := (Result{RuleID: "see-CVE-2019-1010083"}).VulnerabilityID(); got != "" {
		t.Errorf("got %q, want empty for an id that only mentions one", got)
	}
}
