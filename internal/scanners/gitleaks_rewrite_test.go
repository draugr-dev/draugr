package scanners

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func rewritten(t *testing.T, doc, dir string, added ...string) (string, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "report.sarif")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	var raw []json.RawMessage
	for _, a := range added {
		raw = append(raw, json.RawMessage(a))
	}
	err := rewriteGitleaksReport(path, dir, raw)
	out, _ := os.ReadFile(path) // #nosec G304 -- under the test's temporary directory
	return string(out), err
}

// Shapes the whole-document merge has no case for: a document, its runs or a run given as null,
// and runs with nothing to add to.
func TestTheRewrittenReportKeepsWhatHasNothingAdded(t *testing.T) {
	for doc, want := range map[string]string{
		`null`:                         `null`,
		`{"runs":null}`:                `{"runs":null}`,
		`{"runs":[null]}`:              `{"runs":[null]}`,
		`{"runs":[{"results":null}]}`:  `{"runs":[{"results":null}]}`,
		`{"runs":[]}`:                  `{"runs":[]}`,
		`{"runs":[{"tool":{}}],"x":1}`: `{"runs":[{"tool":{}}],"x":1}`,
	} {
		got, err := rewritten(t, doc, "/checkout")
		if err != nil || got != want {
			t.Errorf("%s: got %s, %v; want %s", doc, got, err, want)
		}
	}
}

func TestTheRewrittenReportAddsWhereThereIsNoRunOrResults(t *testing.T) {
	added := `{"ruleId":"r"}`
	for doc, want := range map[string]string{
		`{"runs":null}`:      `{"runs":[{"tool":{"driver":{"name":"gitleaks"}},"results":[{"ruleId":"r"}]}]}`,
		`{"runs":[]}`:        `{"runs":[{"tool":{"driver":{"name":"gitleaks"}},"results":[{"ruleId":"r"}]}]}`,
		`{"runs":[{}]}`:      `{"runs":[{"results":[{"ruleId":"r"}]}]}`,
		`{"runs":[{"a":1}]}`: `{"runs":[{"a":1,"results":[{"ruleId":"r"}]}]}`,
	} {
		got, err := rewritten(t, doc, "", added)
		if err != nil || got != want {
			t.Errorf("%s: got %s, %v; want %s", doc, got, err, want)
		}
	}
}

func TestTheRewrittenReportRefusesWhatItCannotAddTo(t *testing.T) {
	for _, doc := range []string{
		`null`,
		`[]`,
		`{"runs":{}}`,
		`{"runs":[null]}`,
		`{"runs":[1]}`,
		`{"runs":[{"results":{}}]}`,
		`{"runs":[{"results":[{"ruleId":`,
	} {
		before := doc
		got, err := rewritten(t, doc, "/checkout", `{"ruleId":"r"}`)
		if err == nil {
			t.Errorf("%s: rewritten to %s without error", doc, got)
		}
		if got != before {
			t.Errorf("%s: a refused rewrite changed the report to %s", doc, got)
		}
	}
}
