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
	out, _, err := WriteClassifications([]byte(src), map[string]Classification{
		"web": {Exposure: ExposurePublic, Criticality: CriticalityCritical},
	})
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	// Values written with semantic labels, right after name.
	if !strings.Contains(s, "exposure:\n      value: public") || !strings.Contains(s, "criticality:\n      value: critical") {
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
	if m.Components[0].Exposure.Value != ExposurePublic || m.Components[0].Criticality.Value != CriticalityCritical {
		t.Errorf("round-trip classification = %+v", m.Components[0])
	}
}

func TestWriteClassificationsUpdatesInPlace(t *testing.T) {
	src := `release:
  version: "1"
components:
  - name: api
    exposure:
      value: internal
    criticality:
      value: supporting
`
	out, _, err := WriteClassifications([]byte(src), map[string]Classification{
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
	if !strings.Contains(s, "exposure:\n      value: public") || !strings.Contains(s, "criticality:\n      value: critical") {
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
	out, _, err := WriteClassifications([]byte(src), map[string]Classification{
		"a": {Exposure: ExposureRestricted, Criticality: CriticalitySupporting},
	})
	if err != nil {
		t.Fatal(err)
	}
	m, err := Load(out)
	if err != nil {
		t.Fatal(err)
	}
	if m.Components[0].Exposure.Value != ExposureRestricted {
		t.Errorf("component a should be classified: %+v", m.Components[0])
	}
	if m.Components[1].Exposure.Value != "" || m.Components[1].Criticality.Value != "" {
		t.Errorf("component b should be untouched: %+v", m.Components[1])
	}
}

// A reason argues for a value. Change the value and the argument is not merely stale — it is a
// false statement sitting beside the thing it contradicts, and it is published with the findings
// that value shapes.
func TestWriteClassificationsNamesAReasonThatArguedForAnotherValue(t *testing.T) {
	const src = `components:
  - name: argued
    exposure:
      value: restricted
      reason: Namespace-scoped, and a NetworkPolicy keeps it there.
    criticality:
      value: supporting
      reason: Limited blast radius.
  - name: agrees
    exposure:
      value: public
      reason: Anyone can reach it.
`
	out, stale, err := WriteClassifications([]byte(src), map[string]Classification{
		// exposure moves and criticality does not; only the first has been contradicted.
		"argued": {Exposure: ExposurePublic, Criticality: CriticalitySupporting},
		// The value is unchanged, so its reason still argues for what is written.
		"agrees": {Exposure: ExposurePublic, Criticality: CriticalityCritical},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(stale) != 1 {
		t.Fatalf("stale = %v, want only the exposure somebody moved away from", stale)
	}
	for _, want := range []string{"argued", "exposure", "public", "restricted"} {
		if !strings.Contains(stale[0], want) {
			t.Errorf("%q should mention %q", stale[0], want)
		}
	}

	// Kept, not deleted: it is somebody's prose, and a tool that drops it teaches people not to
	// write any.
	if !strings.Contains(string(out), "NetworkPolicy keeps it there") {
		t.Errorf("deleted the reason instead of reporting it:\n%s", out)
	}
	// And a component gaining a rule it never had is not reported as contradicted.
	if strings.Contains(strings.Join(stale, " "), "agrees") {
		t.Errorf("reported a value nobody changed: %v", stale)
	}
}
