package sarif

import "testing"

// A setting's suppression is told apart from every other origin, and survives the SARIF it is
// written to and read back from.
func TestSetAsideBySetting(t *testing.T) {
	for origin, want := range map[string]bool{
		OriginSetting: true, OriginSaga: false, OriginVEX: false, OriginTool: false, OriginScanner: false, "": false,
	} {
		r := Result{Suppression: &Suppression{Kind: "external", Origin: origin}}
		if got := r.SetAsideBySetting(); got != want {
			t.Errorf("origin %q: %v, want %v", origin, got, want)
		}
	}
	if (Result{}).SetAsideBySetting() {
		t.Error("a finding nothing set aside reads as set aside by a setting")
	}

	in := Report{Tool: "trivy", Results: []Result{{
		Tool: "trivy", RuleID: "CVE-2026-67213", Level: LevelError, Location: Location{URI: "npm/package-lock.json"},
		Package: &Package{Name: "nanoid", Version: "3.3.7", PURL: "pkg:npm/nanoid@3.3.7", Dev: true},
		Suppression: &Suppression{Kind: "external", Origin: OriginSetting, Justification: JustificationDevDependency,
			Source: "config.controls.sca.devDependencies"},
	}}}
	raw, err := in.MarshalSARIF()
	if err != nil {
		t.Fatal(err)
	}
	out, err := FromSARIF(raw)
	if err != nil {
		t.Fatal(err)
	}
	got := out.Results[0]
	if !got.SetAsideBySetting() || got.Suppression.Source != "config.controls.sca.devDependencies" ||
		got.Suppression.Justification != JustificationDevDependency {
		t.Errorf("suppression read back as %+v", got.Suppression)
	}
	if got.Package == nil || !got.Package.Dev {
		t.Errorf("package read back as %+v, want dev", got.Package)
	}
}
