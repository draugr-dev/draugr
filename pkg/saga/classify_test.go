package saga

import (
	"os"
	"strings"
	"testing"
)

func TestWriteClassificationsInsertsAndPreserves(t *testing.T) {
	src := `# my app
project: app
release:
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

// The file is a person's: classifying adds two lines and leaves every other byte where it was, the
// aligned comments and the commented-out blocks `draugr init` writes included.
func TestWriteClassificationsKeepsTheLayout(t *testing.T) {
	src, err := os.ReadFile("testdata/classify-init.saga.yaml")
	if err != nil {
		t.Fatal(err)
	}
	out, err := WriteClassifications(src, map[string]Classification{
		"draugr-demo": {Exposure: ExposureAuthenticated, Criticality: CriticalityImportant},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Replace(string(src), "  - name: draugr-demo\n",
		"  - name: draugr-demo\n    exposure: authenticated\n    criticality: important\n", 1)
	if string(out) != want {
		t.Errorf("classify changed more than the two keys:\n%s", out)
	}
}

// A value already there is replaced where it stands, its quotes and trailing comment kept apart
// from the value itself, and a line ending the file had is the one an added line gets.
func TestWriteClassificationsEditsInPlace(t *testing.T) {
	for _, tc := range []struct{ name, src, want string }{
		{
			"comment after the value",
			"components:\n  - name: api\n    exposure: internal      # who reaches it\n    criticality: \"supporting\"\n",
			"components:\n  - name: api\n    exposure: public      # who reaches it\n    criticality: critical\n",
		},
		{
			"single-quoted value",
			"components:\n  - name: api\n    exposure: 'it''s internal'\n",
			"components:\n  - name: api\n    exposure: public\n    criticality: critical\n",
		},
		{
			"empty value",
			"components:\n  - name: api\n    exposure:   # decide\n",
			"components:\n  - name: api\n    exposure: public   # decide\n    criticality: critical\n",
		},
		{
			"criticality only",
			"components:\n  - name: api\n    criticality: supporting\n",
			"components:\n  - name: api\n    exposure: public\n    criticality: critical\n",
		},
		{
			"CRLF and no newline at the end",
			"components:\r\n  - repositories: [{url: .}]\r\n    name: api",
			"components:\r\n  - repositories: [{url: .}]\r\n    name: api\r\n    exposure: public\r\n    criticality: critical\r\n",
		},
	} {
		out, err := WriteClassifications([]byte(tc.src), map[string]Classification{
			"api": {Exposure: ExposurePublic, Criticality: CriticalityCritical},
		})
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if string(out) != tc.want {
			t.Errorf("%s:\ngot  %q\nwant %q", tc.name, out, tc.want)
		}
	}
}

// A component written in flow style has no line of its own to add a key to, so the document is
// encoded again, and the values still land.
func TestWriteClassificationsFlowStyle(t *testing.T) {
	src := "components: [{name: api}]\n"
	out, err := WriteClassifications([]byte(src), map[string]Classification{
		"api": {Exposure: ExposurePublic, Criticality: CriticalityCritical},
	})
	if err != nil {
		t.Fatal(err)
	}
	m, err := Load(out)
	if err != nil {
		t.Fatal(err)
	}
	if m.Components[0].Exposure != ExposurePublic || m.Components[0].Criticality != CriticalityCritical {
		t.Errorf("flow-style component = %+v\n%s", m.Components[0], out)
	}
}

// Input that is not a Saga with components comes back as it was, and YAML that does not parse is
// an error rather than an empty file.
func TestWriteClassificationsOddInput(t *testing.T) {
	for _, src := range []string{"", "project: x\n", "components: none\n", "components:\n  - just-a-string\n  - image: x\n"} {
		out, err := WriteClassifications([]byte(src), map[string]Classification{"api": {}})
		if err != nil || string(out) != src {
			t.Errorf("%q: got %q, %v", src, out, err)
		}
	}
	if _, err := WriteClassifications([]byte("components: [\n"), nil); err == nil {
		t.Error("unparseable YAML should be an error")
	}
}
