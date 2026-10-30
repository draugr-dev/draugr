package scanners

import (
	"context"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/mendapi"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// unknownLicenseJSON is Trivy's report on two packages whose licenses it could not identify, one
// that found some text and one that found none, beside one it could.
const unknownLicenseJSON = `{"Results":[{"Target":"go.mod","Class":"license","Licenses":[
 {"Severity":"UNKNOWN","Category":"unknown","PkgName":"github.com/mystery/lib","FilePath":"go.mod","Name":"Custom License v2 (see LICENSE)"},
 {"Severity":"UNKNOWN","Category":"unknown","PkgName":"github.com/blank/lib","FilePath":"go.mod","Name":""},
 {"Severity":"HIGH","Category":"restricted","PkgName":"github.com/copyleft/lib","FilePath":"go.mod","Name":"GPL-3.0-only"}
]}]}`

// A license Trivy could not identify is keyed `unknown`, not on the text it found, which is not an
// identifier. The message keeps that text, quoted, so a reader still sees what the package said.
func TestAnUnidentifiedLicenseIsKeyedUnknownAndKeepsItsText(t *testing.T) {
	rep, err := parseTrivyLicenses([]byte(unknownLicenseJSON), t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	byRule := map[string]sarif.Result{}
	for _, r := range rep.Results {
		byRule[r.RuleID] = r
	}
	mystery, ok := byRule["license/unknown/github.com/mystery/lib"]
	if !ok {
		t.Fatalf("no unknown finding for the package with text: %v", byRule)
	}
	if !strings.Contains(mystery.Message, `"Custom License v2 (see LICENSE)"`) {
		t.Errorf("the message lost the text Trivy found: %q", mystery.Message)
	}
	if strings.Contains(mystery.RuleID, "Custom") {
		t.Errorf("the rule is keyed on the text: %s", mystery.RuleID)
	}
	blank, ok := byRule["license/unknown/github.com/blank/lib"]
	if !ok || strings.Contains(blank.Message, `""`) {
		t.Errorf("the package with no text: %+v", blank)
	}
	if rule := rep.Rules["license/unknown/github.com/mystery/lib"]; rule.Name != unknownLicense ||
		strings.Contains(rule.ShortDescription, "Custom") {
		t.Errorf("the rule names the text rather than unknown: %+v", rule)
	}
	if _, ok := byRule["license/GPL-3.0-only/github.com/copyleft/lib"]; !ok {
		t.Error("an identified license should keep its SPDX id")
	}
}

// `unknown` in a deny or warn list selects every license the scanner could not identify, and only
// those: the identified license beside them is untouched.
func TestADenyListSelectsUnknownLicenses(t *testing.T) {
	for _, c := range []struct {
		key  string
		want sarif.Level
	}{{denyKey, sarif.LevelError}, {warnKey, sarif.LevelWarning}} {
		rep, err := parseTrivyLicenses([]byte(unknownLicenseJSON), t.TempDir(),
			plugin.Config{c.key: []string{"unknown"}})
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rep.Results {
			unknown := strings.HasPrefix(r.RuleID, "license/unknown/")
			if unknown && r.Level != c.want {
				t.Errorf("%s with %s [unknown]: level %q, want %q", r.RuleID, c.key, r.Level, c.want)
			}
			if !unknown && r.Level != sarif.LevelWarning {
				t.Errorf("%s with %s [unknown]: level %q, want the category's warning", r.RuleID, c.key, r.Level)
			}
		}
	}
}

// Mend reports only what a policy names. A license it names neither by SPDX id nor by its own name
// is `unknown`, so the same deny list selects it on the control's other scanner, and it is not
// reported among the names Mend used in place of SPDX.
func TestMendCallsAnUnnamedLicenseUnknown(t *testing.T) {
	libs := []mendapi.InventoryLibrary{lib("mystery", "", ""), lib("Jinja2", "BSD 3", "")}
	rep := mendLicenseReport(context.Background(), libs, plugin.Config{denyKey: []any{"unknown"}})
	if len(rep.Results) != 1 || rep.Results[0].RuleID != "license/unknown/mystery" ||
		rep.Results[0].Level != sarif.LevelError {
		t.Fatalf("results = %+v", rep.Results)
	}
	if id, isSPDX := mendLicenseID(mendapi.InventoryLicense{}); id != unknownLicense || isSPDX {
		t.Errorf("an unnamed license = %q, SPDX %v", id, isSPDX)
	}
}

// Trivy files a license under its `unknown` category whenever its classifier does not know the
// name, and that name can still be a real id a policy lists. The id the policy names wins: a deny
// does not stop matching because Trivy could not classify the license.
func TestAnIDThePolicyNamesBeatsTrivysUnknownCategory(t *testing.T) {
	const doc = `{"Results":[{"Target":"go.mod","Class":"license","Licenses":[
 {"Severity":"UNKNOWN","Category":"unknown","PkgName":"github.com/rare/lib","FilePath":"go.mod","Name":"Sleepycat"}
]}]}`
	rep, err := parseTrivyLicenses([]byte(doc), t.TempDir(), plugin.Config{denyKey: []string{"Sleepycat"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 1 || rep.Results[0].Level != sarif.LevelError {
		t.Fatalf("a denied id Trivy could not classify: %+v", rep.Results)
	}
}
