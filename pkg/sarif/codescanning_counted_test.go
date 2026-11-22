package sarif

import (
	"encoding/json"
	"errors"
	"testing"
)

// TestACodeScanningCopyHoldsOneResultPerCountedFinding leaves out a second scanner's copy of a flaw
// the first one's finding is counted under, so code scanning opens one alert for it, and keeps the
// counted result, its alsoFoundBy, its fingerprint and the run's rules as written.
func TestACodeScanningCopyHoldsOneResultPerCountedFinding(t *testing.T) {
	withCopy := []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Draugr","rules":[{"id":"R"},{"id":"S"}]}},"results":[
{"ruleId":"R","ruleIndex":0,"partialFingerprints":{"draugr/v1":"abc"},"properties":{"correlation":{"alsoFoundBy":[{"tool":"grype","ruleId":"S"}]}}},
{"ruleId":"S","ruleIndex":1,"properties":{"correlation":{"countedUnder":"trivy"}}},
{"ruleId":"T","properties":{"correlation":{"countedUnder":""}}}]}]}`)
	got, unplaced, err := ForCodeScanning(withCopy, nil)
	if err != nil {
		t.Fatal(err)
	}
	if unplaced != 0 {
		t.Errorf("unplaced = %d, want 0", unplaced)
	}
	var doc struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Rules []json.RawMessage `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID              string            `json:"ruleId"`
				RuleIndex           int               `json:"ruleIndex"`
				PartialFingerprints map[string]string `json:"partialFingerprints"`
				Properties          struct {
					Correlation struct {
						AlsoFoundBy []struct {
							Tool string `json:"tool"`
						} `json:"alsoFoundBy"`
					} `json:"correlation"`
				} `json:"properties"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(got, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Version != "2.1.0" || len(doc.Runs) != 1 || len(doc.Runs[0].Tool.Driver.Rules) != 2 {
		t.Errorf("the document around the results changed: %s", got)
	}
	r := doc.Runs[0].Results
	if len(r) != 2 || r[0].RuleID != "R" || r[0].RuleIndex != 0 || r[0].PartialFingerprints["draugr/v1"] != "abc" || r[1].RuleID != "T" {
		t.Fatalf("results = %+v, want R as written and T, without the copy S", r)
	}
	if a := r[0].Properties.Correlation.AlsoFoundBy; len(a) != 1 || a[0].Tool != "grype" {
		t.Errorf("the counted result's alsoFoundBy = %+v, want grype named", a)
	}
}

// TestACodeScanningCopyRefusesACorrelationItCannotRead refuses a document whose runs, results or
// correlation are not what Draugr writes, rather than uploading what may be a copy.
func TestACodeScanningCopyRefusesACorrelationItCannotRead(t *testing.T) {
	for name, bad := range map[string]string{
		"no runs":                 `{"version":"2.1.0"}`,
		"runs not a list":         `{"runs":"x"}`,
		"results not a list":      `{"runs":[{"results":{}}]}`,
		"correlation a string":    `{"runs":[{"results":[{"properties":{"correlation":"trivy"}}]}]}`,
		"countedUnder not a name": `{"runs":[{"results":[{"properties":{"correlation":{"countedUnder":3}}}]}]}`,
	} {
		if _, _, err := ForCodeScanning([]byte(bad), nil); !errors.Is(err, ErrNotSARIF) {
			t.Errorf("%s: err = %v, want ErrNotSARIF", name, err)
		}
	}
}
