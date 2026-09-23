package scanners

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// A `.trivyignore` line reaches the report as a suppression rather than as an absence.
//
// Trivy removes the finding from its own list, so without this the exclusion and a finding nobody
// ever had are the same thing in the output, which is the one state the suppression model exists
// to prevent.
func TestATrivyIgnoreLineArrivesAsASuppression(t *testing.T) {
	const out = `{
	  "Results": [{
	    "Target": "requirements.txt", "Class": "lang-pkgs", "Type": "pip",
	    "Vulnerabilities": [
	      {"VulnerabilityID": "CVE-2024-22195", "PkgName": "Jinja2", "InstalledVersion": "2.10",
	       "Severity": "MEDIUM", "Title": "xss"}
	    ],
	    "ExperimentalModifiedFindings": [
	      {"Type": "vulnerability", "Status": "ignored", "Source": ".trivyignore",
	       "Statement": "not reachable from the entry point",
	       "Finding": {"VulnerabilityID": "CVE-2020-28493", "PkgName": "Jinja2",
	                   "InstalledVersion": "2.10", "Severity": "HIGH", "Title": "redos"}}
	    ]
	  }]
	}`
	rep, err := parseTrivyVulns([]byte(out), t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 2 {
		t.Fatalf("%d result(s), want the reported one and the excluded one", len(rep.Results))
	}
	var excluded *sarif.Result
	for i := range rep.Results {
		if rep.Results[i].RuleID == "CVE-2020-28493" {
			excluded = &rep.Results[i]
		}
	}
	if excluded == nil {
		t.Fatal("the excluded finding is not in the report")
	}
	sup := excluded.Suppression
	switch {
	case sup == nil:
		t.Fatal("the excluded finding carries no suppression, so it reads as an active one")
	case sup.Origin != sarif.OriginScanner:
		t.Errorf("origin %q, want %q", sup.Origin, sarif.OriginScanner)
	case sup.Source != ".trivyignore":
		t.Errorf("source %q, want the file the rule was written in", sup.Source)
	case sup.Justification != "not reachable from the entry point":
		t.Errorf("justification %q, want the statement Trivy carried", sup.Justification)
	}
	if excluded.Package == nil || excluded.Package.Name != "Jinja2" {
		t.Errorf("the excluded finding lost its package: %+v", excluded.Package)
	}
}

// Anything in that section which is not an exclusion of a vulnerability is left out.
//
// Trivy reports a rewritten severity in the same place, and a severity somebody changed is not a
// decision to live with the finding. Read as one it would arrive in the register as an acceptance
// nobody made.
func TestOnlyAnExclusionOfAVulnerabilityIsReadAsOne(t *testing.T) {
	for _, entry := range []string{
		`{"Type": "vulnerability", "Status": "fixed", "Finding": {"VulnerabilityID": "CVE-1"}}`,
		`{"Type": "misconfiguration", "Status": "ignored", "Finding": {"VulnerabilityID": "CVE-1"}}`,
		`{"Type": "vulnerability", "Status": "ignored", "Finding": {}}`,
	} {
		out := `{"Results": [{"Target": "requirements.txt", "Class": "lang-pkgs",
		  "ExperimentalModifiedFindings": [` + entry + `]}]}`
		rep, err := parseTrivyVulns([]byte(out), t.TempDir(), nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(rep.Results) != 0 {
			t.Errorf("%s produced %d result(s), want none", entry, len(rep.Results))
		}
	}
}

// A Trivy too old to have the flag runs the command Draugr has always run.
//
// An unknown flag fails the scan, and losing the record of an exclusion is the lesser of the two.
func TestTheSuppressedFlagIsOnlyPassedToATrivyThatHasIt(t *testing.T) {
	for _, c := range []struct {
		probed string
		want   bool
	}{
		{"", false},
		{"trivy@0.52.9;db@2026-07-15T00:56:58Z", false},
		{"trivy@0.53.0;db@2026-07-15T00:56:58Z", true},
		{"trivy@0.74.0;db@2026-07-15T00:56:58Z", true},
		{"trivy@1.0.0", true},
		{"trivy@nonsense", false},
	} {
		if got := trivyAtLeast(c.probed, showSuppressedSince); got != c.want {
			t.Errorf("trivyAtLeast(%q) = %v, want %v", c.probed, got, c.want)
		}
	}
}

// And the command carries the flag once the version is known to have it.
//
// The probe is memoized before the command line is built, so the version this reads is the one
// that will run. Set here rather than probed, because the test is about the decision, not about
// whichever Trivy happens to be on the machine.
func TestTheCommandAsksTrivyForWhatItExcluded(t *testing.T) {
	was := sharedTrivyVersion.val
	t.Cleanup(func() { sharedTrivyVersion.val = was })

	sharedTrivyVersion.val = "trivy@0.74.0;db@2026-07-15T00:56:58Z"
	argv := trivyFSArgs("/tree", nil)
	if !hasArg(argv, "--show-suppressed") {
		t.Errorf("a Trivy that can list its exclusions was not asked: %v", argv)
	}
	if argv[len(argv)-1] != "/tree" {
		t.Errorf("the target must stay last: %v", argv)
	}

	sharedTrivyVersion.val = "trivy@0.40.0;db@2026-07-15T00:56:58Z"
	if argv := trivyFSArgs("/tree", nil); hasArg(argv, "--show-suppressed") {
		t.Errorf("an older Trivy was passed a flag it does not have: %v", argv)
	}
}

func hasArg(argv []string, want string) bool {
	for _, a := range argv {
		if a == want {
			return true
		}
	}
	return false
}
