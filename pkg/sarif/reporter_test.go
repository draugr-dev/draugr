package sarif

import "testing"

// A finding read from another tool's file is that tool's, marked as imported, so it never reads as
// the native run of the same tool; every other finding is its tool's.
func TestReporter(t *testing.T) {
	for _, c := range []struct {
		res  Result
		want string
	}{
		{Result{Tool: "Semgrep OSS", Scanner: "semgrep"}, "Semgrep OSS"},
		{Result{Tool: "trivy"}, "trivy"},
		{Result{Tool: "Semgrep OSS", Scanner: ImportScanner}, "imported Semgrep OSS"},
		{Result{Scanner: ImportScanner}, "imported"},
		{Result{Tool: "trivy", Scanner: ImportScanner, ImportFormat: "trivy-json"}, "imported trivy (trivy-json)"},
	} {
		if got := c.res.Reporter(); got != c.want {
			t.Errorf("Reporter(%+v) = %q, want %q", c.res, got, c.want)
		}
	}
}

// Where a tool recorded a suppression reads from its kind, and a dismissal in a service names the
// service.
func TestWhereASuppressionWasRecorded(t *testing.T) {
	for s, want := range map[Suppression]string{
		{Kind: "inSource"}: "suppressed in a comment in the code",
		{Kind: "external"}: "suppressed in the tool's own settings",
		{Kind: "external", Service: "Dependabot", Author: "octocat"}: "dismissed in Dependabot",
	} {
		if got := s.Where(); got != want {
			t.Errorf("Where(%+v) = %q, want %q", s, got, want)
		}
	}
}

// A decision made in a service is placed in that service, in GitHub's word for GitHub's alerts and as
// set aside elsewhere, and a file's suppression where its kind says.
func TestWhereNamesTheServiceAndItsWord(t *testing.T) {
	for _, c := range []struct{ service, kind, want string }{
		{"GitHub code scanning", "external", "dismissed in GitHub code scanning"},
		{"Dependabot", "external", "dismissed in Dependabot"},
		{"SonarQube", "external", "set aside in SonarQube"},
		{"", "inSource", "suppressed " + SuppressedIn("inSource")},
	} {
		if got := (Suppression{Service: c.service, Kind: c.kind}).Where(); got != c.want {
			t.Errorf("%q: Where = %q, want %q", c.service, got, c.want)
		}
	}
}
