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
		{"naming who accepted it", Suppression{
			Kind: "external", Justification: "a compensating control covers this",
			Origin: OriginSaga, AcceptedBy: "ada@acme.example",
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

// A report from before origins were recorded still means what it said.
func TestAnOldReportWithANameIsStillADescriptorRule(t *testing.T) {
	data, err := Report{Tool: "trivy", Results: []Result{{
		RuleID: "CVE-2026-1", Level: LevelError, Message: "x",
		// No Origin, which is every report a Draugr before this one wrote.
		Suppression: &Suppression{Kind: "external", AcceptedBy: "ada@acme.example"},
	}}}.MarshalSARIF()
	if err != nil {
		t.Fatal(err)
	}
	back, err := FromSARIF(data)
	if err != nil {
		t.Fatal(err)
	}
	if got := back.Results[0].Suppression.Origin; got != OriginSaga {
		t.Errorf("origin %q, want %q", got, OriginSaga)
	}
}

// The descriptor's acceptedBy is written only under the key that marks it unverified, and a report
// an earlier release wrote under the old key still reads back, so a baseline from one compares.
func TestTheDescriptorsNameIsWrittenAsUnverified(t *testing.T) {
	data, err := Report{Tool: "trivy", Results: []Result{{
		RuleID: "CVE-2026-1", Level: LevelError, Message: "x",
		Suppression: &Suppression{Kind: "external", Justification: "j", Origin: OriginSaga, AcceptedBy: "ada@acme.example"},
	}}}.MarshalSARIF()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"unverifiedAcceptedBy": "ada@acme.example"`) || strings.Contains(string(data), `"acceptedBy"`) {
		t.Errorf("the name should be written only as unverifiedAcceptedBy:\n%s", data)
	}

	older := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Draugr"}},"results":[{"ruleId":"CVE-2026-1",
"level":"error","message":{"text":"x"},"suppressions":[{"kind":"external","justification":"j",
"properties":{"acceptedBy":"ada@acme.example"}}]}]}]}`
	back, err := FromSARIF([]byte(older))
	if err != nil {
		t.Fatal(err)
	}
	sup := back.Results[0].Suppression
	if sup == nil || sup.AcceptedBy != "ada@acme.example" || sup.Origin != OriginSaga {
		t.Errorf("an older report read back as %+v", sup)
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
