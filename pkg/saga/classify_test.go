package saga

import (
	"strings"
	"testing"
)

func TestWriteClassificationsInsertsAndPreserves(t *testing.T) {
	src := `# my app
release:
  name: app
  version: "1.0"
components:
  - name: web   # the frontend
    images:
      - image: registry/${{ IMG }}:1
`
	out, err := WriteClassifications([]byte(src), map[string]Classification{
		"web": {Exposure: ExposurePublic, Criticality: CriticalityCritical},
	})
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	// Values written with semantic labels, right after name.
	if !strings.Contains(s, "exposure: public") || !strings.Contains(s, "criticality: critical") {
		t.Fatalf("classification not written:\n%s", s)
	}
	// Comment and ${{ }} token preserved (not substituted).
	if !strings.Contains(s, "# my app") || !strings.Contains(s, "${{ IMG }}") {
		t.Errorf("comments/tokens not preserved:\n%s", s)
	}
	// Re-parses cleanly with the new classification.
	m, err := Load([]byte(strings.ReplaceAll(s, "${{ IMG }}", "x"))) // substitute so Load doesn't error
	if err != nil {
		t.Fatalf("output should re-parse: %v", err)
	}
	if m.Components[0].Exposure != ExposurePublic || m.Components[0].Criticality != CriticalityCritical {
		t.Errorf("round-trip classification = %+v", m.Components[0])
	}
}

func TestWriteClassificationsUpdatesInPlace(t *testing.T) {
	src := `release:
  version: "1"
components:
  - name: api
    exposure: internal
    criticality: supporting
`
	out, err := WriteClassifications([]byte(src), map[string]Classification{
		"api": {Exposure: ExposurePublic, Criticality: CriticalityCritical},
	})
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Contains(s, "internal") || strings.Contains(s, "supporting") {
		t.Errorf("old values should be replaced, not duplicated:\n%s", s)
	}
	if strings.Count(s, "exposure:") != 1 || strings.Count(s, "criticality:") != 1 {
		t.Errorf("keys duplicated:\n%s", s)
	}
	if !strings.Contains(s, "exposure: public") || !strings.Contains(s, "criticality: critical") {
		t.Errorf("values not updated:\n%s", s)
	}
}

func TestWriteClassificationsLeavesOthersAlone(t *testing.T) {
	src := `release:
  version: "1"
components:
  - name: a
  - name: b
`
	out, err := WriteClassifications([]byte(src), map[string]Classification{
		"a": {Exposure: ExposureRestricted, Criticality: CriticalitySupporting},
	})
	if err != nil {
		t.Fatal(err)
	}
	m, err := Load(out)
	if err != nil {
		t.Fatal(err)
	}
	if m.Components[0].Exposure != ExposureRestricted {
		t.Errorf("component a should be classified: %+v", m.Components[0])
	}
	if m.Components[1].Exposure != "" || m.Components[1].Criticality != "" {
		t.Errorf("component b should be untouched: %+v", m.Components[1])
	}
}
