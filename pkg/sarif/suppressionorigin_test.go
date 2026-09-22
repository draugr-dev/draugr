package sarif

import "testing"

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
