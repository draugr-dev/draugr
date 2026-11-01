package sarif

import (
	"strings"
	"testing"
)

// A descriptor rule says so in the report, whether or not it named a person.
//
// The origin decides who a reader goes and asks, and the three answers are different people. Read
// off a name alone, a rule that named nobody came back as the one origin nobody reviewed, which
// points a reader at the file's author for a decision the descriptor's owner made.
func TestADescriptorRuleSaysSoWhateverItNamed(t *testing.T) {
	for _, c := range []struct {
		name string
		sup  Suppression
	}{
		{"naming where it is written", Suppression{
			Kind: "external", Justification: "a compensating control covers this",
			Origin: OriginSaga, Source: "draugr.saga.yaml", Line: 9,
		}},
		{"naming nobody", Suppression{
			Kind: "external", Justification: "a compensating control covers this",
			Origin: OriginSaga,
		}},
		{"naming nobody, with an expiry", Suppression{
			Kind: "external", Justification: "a compensating control covers this",
			Origin: OriginSaga, Expires: "2027-06-30",
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := roundTrip(t, c.sup)
			if got.Origin != OriginSaga {
				t.Errorf("origin %q, want %q", got.Origin, OriginSaga)
			}
		})
	}
}

// A suppression the scanner already carried is the one Draugr did not write.
func TestASuppressionDraugrDidNotMakeIsTheTools(t *testing.T) {
	got := roundTrip(t, Suppression{Kind: "inSource", Justification: "nosem: reviewed"})
	if got.Origin != OriginTool {
		t.Errorf("origin %q, want %q", got.Origin, OriginTool)
	}
}

// A report from before origins were recorded still means what it said, under either key an earlier
// release wrote a descriptor rule's name under, so a baseline from one compares as the decision it
// recorded.
func TestAnOldReportWithANameIsStillADescriptorRule(t *testing.T) {
	for _, key := range []string{"acceptedBy", "unverifiedAcceptedBy"} {
		t.Run(key, func(t *testing.T) {
			older := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Draugr"}},"results":[{"ruleId":"CVE-2026-1",
"level":"error","message":{"text":"x"},"suppressions":[{"kind":"external","justification":"j",
"properties":{"` + key + `":"ada@acme.example","expires":"2027-01-01"}}]}]}]}`
			back, err := FromSARIF([]byte(older))
			if err != nil {
				t.Fatal(err)
			}
			sup := back.Results[0].Suppression
			if sup == nil || sup.Origin != OriginSaga || sup.Justification != "j" || sup.Expires != "2027-01-01" {
				t.Errorf("an older report read back as %+v", sup)
			}
			if !back.Results[0].Suppressed() || back.Results[0].SilencedInSource() {
				t.Error("an older report's decision did not read back as a recorded decision")
			}
		})
	}
}

// A report this release writes has no key for a typed name on any suppression.
func TestNoNameIsWrittenForADecision(t *testing.T) {
	data, err := Report{Tool: "trivy", Results: []Result{{
		RuleID: "CVE-2026-1", Level: LevelError, Message: "x",
		Suppression: &Suppression{Kind: "external", Justification: "j", Origin: OriginSaga,
			Source: "draugr.saga.yaml", Line: 9},
	}}}.MarshalSARIF()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "cceptedBy") {
		t.Errorf("a suppression carries a name key:\n%s", data)
	}
}

// The file and line an exclusion is written at survive the report, so a consumer of the SARIF can
// find the exclusion, and its git history in report.json, from the finding it set aside.
func TestASuppressionKeepsWhereItsExclusionIsWritten(t *testing.T) {
	got := roundTrip(t, Suppression{
		Kind: "external", Justification: "fixtures", Origin: OriginSaga,
		Source: "excl/fixtures.saga-fragment.yaml", Line: 14,
	})
	if got.Source != "excl/fixtures.saga-fragment.yaml" || got.Line != 14 {
		t.Errorf("source %q line %d, want excl/fixtures.saga-fragment.yaml and 14", got.Source, got.Line)
	}
	// A line alone is still worth carrying, and is the one field that would otherwise be dropped.
	if got := roundTrip(t, Suppression{Kind: "external", Justification: "x", Line: 3}); got.Line != 3 {
		t.Errorf("line %d, want 3", got.Line)
	}
}

// roundTrip writes a result carrying the suppression and reads it back, which is what every
// consumer of a report does and the only place the origin is decided.
func roundTrip(t *testing.T, sup Suppression) *Suppression {
	t.Helper()
	data, err := Report{Tool: "trivy", Results: []Result{{
		RuleID: "CVE-2026-1", Level: LevelError, Message: "x", Suppression: &sup,
	}}}.MarshalSARIF()
	if err != nil {
		t.Fatal(err)
	}
	back, err := FromSARIF(data)
	if err != nil {
		t.Fatal(err)
	}
	if back.Results[0].Suppression == nil {
		t.Fatal("the suppression did not survive the round trip")
	}
	return back.Results[0].Suppression
}
