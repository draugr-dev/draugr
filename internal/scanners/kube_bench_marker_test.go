package scanners

import "testing"

// TestWithoutAssessmentMarker drops CIS vocabulary that reads as a claim about the fix.
//
// "(Automated)" says the benchmark's recommendation can be assessed programmatically. It says
// nothing about the finding or its remediation, and a reader seeing it beside something they have
// been told to act on reads it as one — while it costs a dozen characters of a line that is
// already truncated, in every row.
func TestWithoutAssessmentMarker(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{
			"Ensure that the kube-proxy metrics service is bound to localhost (Automated)",
			"Ensure that the kube-proxy metrics service is bound to localhost",
		},
		{
			"Ensure that the admission control plugin AlwaysAdmit is not set (Manual)",
			"Ensure that the admission control plugin AlwaysAdmit is not set",
		},
		// Only a trailing marker, and only the two the benchmark uses. A parenthesis anywhere
		// else is part of what the check says.
		{"Minimize wildcard use in Roles (and ClusterRoles)", "Minimize wildcard use in Roles (and ClusterRoles)"},
		{"Ensure (Automated) appears mid-sentence here", "Ensure (Automated) appears mid-sentence here"},
		{"", ""},
	} {
		if got := withoutAssessmentMarker(c.in); got != c.want {
			t.Errorf("withoutAssessmentMarker(%q)\n got  %q\n want %q", c.in, got, c.want)
		}
	}
}
