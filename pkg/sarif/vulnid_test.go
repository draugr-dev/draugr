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
		"",
	} {
		if got := (Result{RuleID: ruleID}).VulnerabilityID(); got != "" {
			t.Errorf("%q → %q, want empty", ruleID, got)
		}
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
