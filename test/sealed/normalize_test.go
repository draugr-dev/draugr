package sealed

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNormalizerApply(t *testing.T) {
	n := Normalizer{
		Clear:   [][]string{{"runs", "*", "version"}, {"stats", "*"}},
		Sort:    [][]string{{"runs"}},
		Replace: map[string]string{"/tmp/w": "<work>"},
	}
	got, err := n.Apply([]byte(`{"runs":[{"id":"b","version":"2","path":"/tmp/w/x"},{"id":"a","version":"1"}],"stats":{"ms":3,"n":4}}`))
	if err != nil {
		t.Fatal(err)
	}
	want := `{
  "runs": [
    {
      "id": "a",
      "version": "<cleared>"
    },
    {
      "id": "b",
      "path": "<work>/x",
      "version": "<cleared>"
    }
  ],
  "stats": {
    "ms": "<cleared>",
    "n": "<cleared>"
  }
}
`
	if string(got) != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}

	// A path that reaches nothing is the field having moved, which is an error.
	_, err = Normalizer{Clear: [][]string{{"runs", "*", "gone"}}}.Apply([]byte(`{"runs":[{"id":"a"}]}`))
	if err == nil || !strings.Contains(err.Error(), "runs.*.gone") {
		t.Errorf("err = %v, want the path named", err)
	}
	for _, path := range [][]string{{}, {"runs", "0"}, {"id", "x"}} {
		if _, err := (Normalizer{Clear: [][]string{path}}).Apply([]byte(`{"runs":[{"id":"a"}],"id":"s"}`)); err == nil {
			t.Errorf("path %v matched something", path)
		}
	}
	if _, err := n.Apply([]byte("{")); err == nil {
		t.Error("unreadable JSON was accepted")
	}
}

func TestTheNormalizersMatchADraugrReport(t *testing.T) {
	sarif := `{"runs":[{"tool":{"driver":{"name":"Draugr","version":"dev","rules":[{"id":"b"},{"id":"a"}]}},
	  "properties":{"draugr/provenance":[{"tool":"t","version":"1","fields":{"revision":"abc"}}]},
	  "results":[{"ruleId":"b","partialFingerprints":{"primaryLocationLineHash/v1":"h"}},{"ruleId":"a","partialFingerprints":{"primaryLocationLineHash/v1":"h"}}]}]}`
	got, err := SARIFNormalizer(nil).Apply([]byte(sarif))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), `"abc"`) || strings.Index(string(got), `"ruleId": "a"`) > strings.Index(string(got), `"ruleId": "b"`) {
		t.Errorf("not normalized:\n%s", got)
	}
	report := `{"draugr":{"version":"dev","commit":"abc1234"},"scanners":[{"name":"b","version":"1"},{"name":"a","version":"2"}],
	  "repositories":[{"revision":"abc"}],"descriptor":{"digest":"d","effective":"e"},
	  "stats":{"durationMs":1,"byControlMs":{"sca":1},"concurrency":8}}`
	if _, err := ReportNormalizer(nil).Apply([]byte(report)); err != nil {
		t.Error(err)
	}
}

func TestValidateSARIF(t *testing.T) {
	valid := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Draugr"}},"results":[]}]}`
	if err := ValidateSARIF([]byte(valid)); err != nil {
		t.Errorf("valid SARIF refused: %v", err)
	}
	if err := ValidateSARIF([]byte(strings.Replace(valid, "2.1.0", "9.9", 1))); err == nil {
		t.Error("a wrong version was accepted")
	}
	if err := ValidateSARIF([]byte("{")); err == nil {
		t.Error("unreadable JSON was accepted")
	}
}

// Every golden the integration test compares against is a document the normalizer produced, so
// normalizing it again changes nothing. A golden edited by hand into a shape the normalizer would
// not write fails here, in the gate, rather than in the integration job.
func TestTheGoldensAreNormalized(t *testing.T) {
	scenarios, err := globNonEmpty("../integration/testdata/ecosystems/*/expected.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, exp := range scenarios {
		s, err := LoadScenario(filepath.Dir(exp))
		if err != nil {
			t.Fatal(err)
		}
		for name, n := range map[string]Normalizer{
			"results.sarif": SARIFNormalizer(nil),
			"report.json":   ReportNormalizer(nil),
		} {
			// As the integration test normalizes it: a scenario about a failure has fields nothing
			// wrote.
			n.AllowMissing = len(s.Expected.Errors) > 0
			path := filepath.Join(s.Dir, "golden", name)
			raw, err := os.ReadFile(path) // #nosec G304 -- a checked-in golden
			if err != nil {
				t.Errorf("%s: %v", s.Name, err)
				continue
			}
			if name == "results.sarif" {
				if err := ValidateSARIF(raw); err != nil {
					t.Errorf("%s: %v", path, err)
				}
			}
			again, err := n.Apply(raw)
			if err != nil {
				t.Errorf("%s: %v", path, err)
				continue
			}
			if string(again) != string(raw) {
				t.Errorf("%s changes when normalized again:\n%s", path, Diff(string(raw), string(again)))
			}
		}
	}
}

func TestRunReplacements(t *testing.T) {
	start := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	r := RunReplacements("/tmp/Test1/001", start)
	if r["/tmp/Test1/001"] != "<work>" || r["2026-03-04"] != "<today>" || len(r) > 3 {
		t.Errorf("replacements = %v", r)
	}
}

func TestDiff(t *testing.T) {
	// An inserted line is one addition, not every line after it moved.
	d := Diff("a\nb\nc\nd", "a\nx\nb\nc\nD")
	if d != "  + 2: x\n  - 4: d\n  + 5: D\n" {
		t.Errorf("diff = %q", d)
	}
	if d := Diff("same", "same"); d != "" {
		t.Errorf("diff of equal documents = %q", d)
	}
	many := strings.Repeat("x\n", 60)
	if d := Diff(many, strings.ReplaceAll(many, "x", "y")); !strings.Contains(d, "not shown") {
		t.Errorf("a long diff was not capped:\n%s", d)
	}
}

func globNonEmpty(pattern string) ([]string, error) {
	paths, err := filepath.Glob(pattern)
	if err == nil && len(paths) == 0 {
		err = os.ErrNotExist
	}
	return paths, err
}
