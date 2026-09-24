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

func TestAnInfrastructureKindHasOneSpelling(t *testing.T) {
	got := loadErr(t, "    infrastructure:\n      - kind: Kubernetes\n        ref: prod\n")
	if !strings.Contains(got, `"Kubernetes" must be lowercase: kubernetes`) {
		t.Errorf("error %q", got)
	}
}

// A label YAML reads as a number or a boolean is refused with the quoted form to write, in a
// descriptor and in a fragment alike.
func TestALabelIsAString(t *testing.T) {
	got := loadErr(t, "    labels:\n      tier: 1\n      team: payments\n")
	if !strings.Contains(got, `labels.tier is 1, not a string: write tier: "1"`) {
		t.Errorf("error %q", got)
	}
	if got := loadErr(t, "    labels:\n      tier: \"1\"\n"); got != "" {
		t.Errorf("a quoted label was refused: %s", got)
	}
	_, err := LoadFragment([]byte("components:\n  - name: w\n    labels:\n      pci: true\n"), "f.yaml")
	if err == nil || !strings.Contains(err.Error(), `pci: "true"`) {
		t.Errorf("fragment: %v", err)
	}
}
