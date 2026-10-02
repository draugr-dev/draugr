package saga

import (
	"strings"
	"testing"
)

const oneSpellingBase = `project: p
release:
  version: "1"
components:
  - name: api
    exposure: public
    criticality: important
`

func loadErr(t *testing.T, extra string) string {
	t.Helper()
	_, err := Load([]byte(oneSpellingBase + extra))
	if err == nil {
		return ""
	}
	return err.Error()
}

// A host type Draugr does not know used to be scanned with the browser rules, whatever it said.
// Refused now, and the wrong case is told its spelling.
func TestAHostTypeIsOneDraugrKnows(t *testing.T) {
	for extra, want := range map[string]string{
		"    hosts:\n      - url: https://a.test\n        type: api\n":  "",
		"    hosts:\n      - url: https://a.test\n        type: apii\n": `hosts[0].type "apii" is not one of browser, api`,
		"    hosts:\n      - url: https://a.test\n        type: API\n":  `hosts[0].type "API" must be lowercase: api`,
	} {
		if got := loadErr(t, extra); (want == "" && got != "") || !strings.Contains(got, want) {
			t.Errorf("%q: error %q, want %q", extra, got, want)
		}
	}
}

// A label YAML reads as a number or a boolean keeps its text, in a descriptor and in a fragment
// alike: labels are compared as text and never reach the verdict.
func TestALabelKeepsItsText(t *testing.T) {
	m, err := Load([]byte(oneSpellingBase + "    labels:\n      tier: 01\n      pci: true\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := m.Components[0].Labels; got["tier"] != "01" || got["pci"] != "true" {
		t.Errorf("labels = %v, want tier 01 and pci true as written", got)
	}
	f, err := LoadFragment([]byte("components:\n  - name: w\n    labels:\n      tier: 1.10\n"), "f.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if got := f.Components[0].Labels["tier"]; got != "1.10" {
		t.Errorf("fragment label = %q, want 1.10", got)
	}
}
