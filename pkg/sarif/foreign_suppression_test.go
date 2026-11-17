package sarif

import (
	"strings"
	"testing"
)

// foreignSuppressed reads one result carrying the given suppressions array.
func foreignSuppressed(t *testing.T, suppressions string) Result {
	t.Helper()
	rep, _ := readForeign(t, `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"vendor"}},
		"results":[{"ruleId":"r","message":{"text":"m"},"suppressions":`+suppressions+`}]}]}`)
	return rep.Results[0]
}

// TestASuppressionSetsAsideOnlyWhereItStands. SARIF's status is the team's decision about the request
// to suppress (3.35.3): rejected is a decision not to, and underReview is none yet. Setting either
// aside would excuse a finding nobody excused.
func TestASuppressionSetsAsideOnlyWhereItStands(t *testing.T) {
	cases := []struct {
		name, suppressions string
		aside              bool
		detail             string
	}{
		{"accepted", `[{"kind":"external","status":"accepted","justification":"fine"}]`, true, ""},
		{"no status", `[{"kind":"inSource","justification":"fine"}]`, true, ""},
		{"accepted in another case", `[{"kind":"external","status":"Accepted"}]`, true, ""},
		{"rejected", `[{"kind":"external","status":"rejected","justification":"not fine"}]`, false,
			"the file's suppression is rejected"},
		{"under review", `[{"kind":"external","status":"underReview"}]`, false,
			"the file's suppression is underReview"},
		{"accepted then rejected", `[{"kind":"inSource","status":"accepted"},{"kind":"external","status":"rejected"}]`,
			false, "the file's suppression is rejected"},
		{"rejected then accepted", `[{"kind":"external","status":"rejected"},{"kind":"inSource","status":"accepted"}]`,
			false, "the file's suppression is rejected"},
		{"empty array", `[]`, false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := foreignSuppressed(t, c.suppressions)
			if (r.Suppression != nil) != c.aside {
				t.Errorf("suppression = %+v, want set aside %v", r.Suppression, c.aside)
			}
			if c.detail == "" && strings.Contains(r.Detail, "suppression") {
				t.Errorf("detail = %q, want no suppression named", r.Detail)
			}
			if c.detail != "" && !strings.Contains(r.Detail, c.detail) {
				t.Errorf("detail = %q, want it to say %q", r.Detail, c.detail)
			}
		})
	}
}

// TestADeclinedSuppressionKeepsTheScannersDetail: the declined request is added to what the scanner
// wrote about the occurrence, not written over it.
func TestADeclinedSuppressionKeepsTheScannersDetail(t *testing.T) {
	rep, _ := readForeign(t, `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"vendor"}},
		"results":[{"ruleId":"r","message":{"text":"Severity: HIGH\nMessage: used in handler.go"},
			"suppressions":[{"kind":"external","status":"rejected"}]}]}]}`)
	r := rep.Results[0]
	if r.Suppression != nil || r.Detail != "used in handler.go · the file's suppression is rejected" ||
		strings.HasPrefix(r.Detail, " · ") {
		t.Errorf("suppression %+v, detail %q", r.Suppression, r.Detail)
	}
}

// TestDraugrsOwnReaderHoldsTheSameRule: a scanner Draugr runs, read through FromSARIF, is held to
// the same statuses, so where a finding came from does not change whether it is excused.
func TestDraugrsOwnReaderHoldsTheSameRule(t *testing.T) {
	for status, aside := range map[string]bool{"": true, "accepted": true, "rejected": false, "underReview": false} {
		if got := readSuppression([]sarifSuppression{{Kind: "inSource", Status: status}}) != nil; got != aside {
			t.Errorf("status %q: set aside %v, want %v", status, got, aside)
		}
	}
	if readSuppression([]sarifSuppression{{Kind: "inSource"}, {Kind: "external", Status: "rejected"}}) != nil {
		t.Error("a rejected entry after a standing one set the finding aside")
	}
}
