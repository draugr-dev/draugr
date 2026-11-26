package sarif

import (
	"slices"
	"testing"

	"github.com/draugr-dev/draugr/internal/fieldprobe"
)

// notInResultsSARIF are the fields of a Result that results.sarif deliberately does not carry, each
// with the reason. A field missing from the file and from this list fails
// TestEveryResultFieldSurvivesResultsSARIF: write it and read it back, or add it here with why.
var notInResultsSARIF = map[string]string{
	"Aliases":                             "correlation reads them within the run, and the file carries the correlation they decided",
	"Correlation.AlsoFoundBy[0].Location": "each copy is a result of its own in the file, with its own location",
	"ImportFormat":                        "held for the run: Reporter names the format beside the tool",
	"ImportedRepository":                  "held for the run: correlation joins an imported finding to the native copy by it",
	"ImportedTool":                        "held for the run: the engine finds the native finding an uploaded alert came from by it",
	"Location.EndLine":                    "read from a scanner's region to recognize one setting reported at two lines, and not part of a finding's identity",
	"Uses":                                "held for the run: a row standing for several mutable-tag findings is chosen by it",
}

// fillEveryField returns a Result with every exported field set, nested ones included, to a value
// that a writer validating its input still accepts.
func fillEveryField() Result {
	var r Result
	fieldprobe.Fill(&r, map[string]any{"Level": LevelError})
	return r
}

// A field added to Result is written to results.sarif and read back by hand, so a field the writer
// or the reader never learned is dropped from every report `draugr diff`, the MCP tools and a gate on
// new findings read back, with no test naming it failing. This one sets every field.
func TestEveryResultFieldSurvivesResultsSARIF(t *testing.T) {
	want := fillEveryField()
	data, err := Report{Results: []Result{want}}.MarshalSARIF()
	if err != nil {
		t.Fatal(err)
	}
	back, err := FromSARIF(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(back.Results) != 1 {
		t.Fatalf("read back %d results, want 1", len(back.Results))
	}
	lost := fieldprobe.Lost(want, back.Results[0])
	for _, field := range lost {
		if _, listed := notInResultsSARIF[field]; !listed {
			t.Errorf("%s did not survive results.sarif: write it and read it back, or list it in notInResultsSARIF with the reason", field)
		}
	}
	for field := range notInResultsSARIF {
		if !slices.Contains(lost, field) {
			t.Errorf("%s now survives results.sarif: take it off notInResultsSARIF", field)
		}
	}
}

// The suppression fields a VEX document, the accepted findings and a dismissed alert's row read,
// each read back on its own: the test above sets them all at once, and a reader that read one only
// beside another would pass it.
func TestEachSuppressionFieldSurvivesResultsSARIFAlone(t *testing.T) {
	for name, sup := range map[string]Suppression{
		"statement":         {Kind: "external", Justification: "j", StatementID: "stmt-1"},
		"digest":            {Kind: "external", Justification: "j", Digest: "sha256:abc"},
		"vex status":        {Kind: "external", Justification: "j", VEXStatus: "not_affected"},
		"vex justification": {Kind: "external", Justification: "j", VEXJustification: "component_not_present"},
		"service":           {Kind: "external", Justification: "j", Service: "GitHub code scanning"},
	} {
		t.Run(name, func(t *testing.T) {
			want := Result{RuleID: "R", Level: LevelWarning, Message: "m", Suppression: &sup}
			data, err := Report{Results: []Result{want}}.MarshalSARIF()
			if err != nil {
				t.Fatal(err)
			}
			back, err := FromSARIF(data)
			if err != nil {
				t.Fatal(err)
			}
			got := back.Results[0].Suppression
			if got == nil {
				t.Fatal("the suppression did not survive")
			}
			// Origin is read from the kind where none was written, which the test does not set.
			got.Origin = sup.Origin
			if *got != sup {
				t.Errorf("read back %+v, want %+v", *got, sup)
			}
		})
	}
}

// Another tool's file may well use a plain `service` key in a suppression's property bag. Only
// Draugr's own namespaced key keeps a suppression apart from the other copies of its flaw.
func TestAPlainServiceKeyInAnotherToolsSuppressionIsNotRead(t *testing.T) {
	const doc = `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Other"}},"results":[
		{"ruleId":"R","level":"warning","message":{"text":"m"},
		 "suppressions":[{"kind":"external","properties":{"service":"somewhere"}}]}]}]}`
	rep, err := FromSARIF([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if got := rep.Results[0].Suppression.Service; got != "" {
		t.Errorf("Service = %q, want it unread", got)
	}
}
