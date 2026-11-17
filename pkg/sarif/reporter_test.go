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
