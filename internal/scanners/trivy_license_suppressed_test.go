package scanners

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// A license `.trivyignore` set aside reaches the report as a suppression, in a package and in a
// file alike. Trivy reports the two in separate results, so both shapes are driven here.
func TestAnExcludedLicenseArrivesAsASuppression(t *testing.T) {
	const out = `{"Results": [
	  {"Target": "a/package-lock.json", "Class": "lang-pkgs",
	   "Licenses": [{"Severity": "HIGH", "Category": "restricted", "PkgName": "gpl-dep",
	                 "FilePath": "a/package-lock.json", "Name": "GPL-3.0"}],
	   "ExperimentalModifiedFindings": [
	     {"Type": "license", "Status": "ignored", "Source": ".trivyignore", "Statement": "",
	      "Finding": {"Severity": "MEDIUM", "Category": "reciprocal", "PkgName": "mpl-dep",
	                  "FilePath": "a/package-lock.json", "Name": "MPL-2.0"}},
	     {"Type": "license", "Status": "ignored", "Source": ".trivyignore",
	      "Finding": {"Severity": "LOW", "Category": "notice", "PkgName": "inherits",
	                  "FilePath": "a/package-lock.json", "Name": "ISC"}}
	   ]},
	  {"Target": "Loose File License(s)", "Class": "license-file",
	   "ExperimentalModifiedFindings": [
	     {"Type": "license", "Status": "ignored", "Source": "trivy.yaml", "Statement": "vendored, reviewed",
	      "Finding": {"Severity": "HIGH", "Category": "restricted", "FilePath": "b/LICENSE",
	                  "Name": "LGPL-3.0"}}
	   ]}
	]}`
	rep, err := parseTrivyLicenses([]byte(out), t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]*sarif.Suppression{}
	for _, r := range rep.Results {
		got[r.RuleID+"@"+r.Location.URI] = r.Suppression
		if _, ok := rep.Rules[r.RuleID]; !ok {
			t.Errorf("%s has no rule, so it reaches the report without a description", r.RuleID)
		}
	}
	if len(got) != 3 {
		t.Fatalf("results %v, want the reported license and the two excluded ones it would report", got)
	}
	if got["license/GPL-3.0/gpl-dep@a/package-lock.json"] != nil {
		t.Error("the license Trivy reported was marked suppressed")
	}
	for key, want := range map[string]sarif.Suppression{
		"license/MPL-2.0/mpl-dep@a/package-lock.json": {Source: ".trivyignore"},
		"license/LGPL-3.0@b/LICENSE":                  {Source: "trivy.yaml", Justification: "vendored, reviewed"},
	} {
		sup := got[key]
		switch {
		case sup == nil:
			t.Errorf("%s: no suppression, so the exclusion reads as an active finding", key)
		case sup.Origin != sarif.OriginScanner || sup.Kind != "external":
			t.Errorf("%s: origin %q kind %q, want the scanner's own configuration", key, sup.Origin, sup.Kind)
		case sup.Source != want.Source || sup.Justification != want.Justification:
			t.Errorf("%s: source %q justification %q, want %q %q",
				key, sup.Source, sup.Justification, want.Source, want.Justification)
		}
	}
}

// Anything in that section other than an exclusion of a license is left out, for the reason
// TestOnlyAnExclusionOfAVulnerabilityIsReadAsOne gives.
func TestOnlyAnExclusionOfALicenseIsReadAsOne(t *testing.T) {
	for _, entry := range []string{
		`{"Type": "license", "Status": "fixed", "Finding": {"Name": "GPL-3.0", "Category": "restricted"}}`,
		`{"Type": "vulnerability", "Status": "ignored", "Finding": {"Name": "GPL-3.0", "Category": "restricted"}}`,
		`{"Type": "license", "Status": "ignored", "Finding": {"Category": "restricted"}}`,
	} {
		out := `{"Results": [{"Target": "a/package-lock.json", "Class": "lang-pkgs",
		  "ExperimentalModifiedFindings": [` + entry + `]}]}`
		rep, err := parseTrivyLicenses([]byte(out), t.TempDir(), nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(rep.Results) != 0 {
			t.Errorf("%s produced %d result(s), want none", entry, len(rep.Results))
		}
	}
}

// Both license commands ask a Trivy that can answer, with the target still last.
func TestTheLicenseCommandsAskTrivyForWhatItExcluded(t *testing.T) {
	was := sharedTrivyVersion.val
	t.Cleanup(func() { sharedTrivyVersion.val = was })

	sharedTrivyVersion.val = "trivy@0.74.0;db@2026-07-15T00:56:58Z"
	image, err := trivyLicenseImageArgv(plugin.ImageTarget{Ref: "registry.example/api:1.0"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, argv := range [][]string{trivyLicenseArgs("/tree", nil), image} {
		if !hasArg(argv, "--show-suppressed") {
			t.Errorf("a Trivy that can list its exclusions was not asked: %v", argv)
		}
		if last := argv[len(argv)-1]; last != "/tree" && last != "registry.example/api:1.0" {
			t.Errorf("the target must stay last: %v", argv)
		}
	}

	sharedTrivyVersion.val = "trivy@0.40.0;db@2026-07-15T00:56:58Z"
	if argv := trivyLicenseArgs("/tree", nil); hasArg(argv, "--show-suppressed") {
		t.Errorf("an older Trivy was passed a flag it does not have: %v", argv)
	}
}
