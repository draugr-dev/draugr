package sarif

import "testing"

// TestUpgradePolicySurvivesTheFile: `fix_list` and `draugr diff` read results.sarif without the
// descriptor, and split a component's upgrades the same way only if its policy is in the file.
func TestUpgradePolicySurvivesTheFile(t *testing.T) {
	in := Report{Results: []Result{{
		RuleID: "CVE-2020-11023", Level: LevelError, Tool: "trivy", Control: "sca", Component: "web",
		Location:      Location{URI: "package-lock.json", StartLine: 12},
		Package:       &Package{Name: "jquery", Version: "1.8.3", FixedVersion: "3.5.0"},
		UpgradePolicy: "minor",
	}}}
	data, err := in.MarshalSARIF()
	if err != nil {
		t.Fatal(err)
	}
	out, err := FromSARIF(data)
	if err != nil {
		t.Fatal(err)
	}
	if got := out.Results[0].UpgradePolicy; got != "minor" {
		t.Errorf("upgradePolicy read back as %q, want minor", got)
	}
}
