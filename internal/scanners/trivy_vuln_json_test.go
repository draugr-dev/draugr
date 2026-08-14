package scanners

import (
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// A trimmed copy of real `trivy fs --format json` output: two ecosystems, one vulnerability with
// no fix, and the CVSS spread across sources that Trivy actually reports.
const trivyVulnJSON = `{
  "Results": [
    {
      "Target": "requirements.txt",
      "Type": "pip",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2018-1000656",
          "PkgName": "Flask",
          "InstalledVersion": "0.12.2",
          "FixedVersion": "0.12.3",
          "PkgIdentifier": {"PURL": "pkg:pypi/flask@0.12.2"},
          "Severity": "HIGH",
          "Title": "denial of service via crafted JSON",
          "Description": "A long paragraph about the flaw.",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2018-1000656",
          "CVSS": {"nvd": {"V3Score": 7.5}, "redhat": {"V3Score": 5.9}}
        },
        {
          "VulnerabilityID": "CVE-2020-28493",
          "PkgName": "Jinja2",
          "InstalledVersion": "2.10",
          "PkgIdentifier": {"PURL": "pkg:pypi/jinja2@2.10"},
          "Severity": "MEDIUM",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2020-28493",
          "CVSS": {"nvd": {"V3Score": 5.3}}
        }
      ]
    },
    {
      "Target": "go.sum",
      "Type": "gomod",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2024-24790",
          "PkgName": "stdlib",
          "InstalledVersion": "1.21.0",
          "FixedVersion": "1.21.11",
          "Severity": "CRITICAL",
          "CVSS": {"nvd": {"V3Score": 9.8}}
        }
      ]
    }
  ]
}`

func parseFixture(t *testing.T) sarif.Report {
	t.Helper()
	rep, err := parseTrivyVulns([]byte(trivyVulnJSON), "", plugin.Config{})
	if err != nil {
		t.Fatalf("parseTrivyVulns: %v", err)
	}
	return rep
}

// The point of reading JSON rather than SARIF: the package is a set of fields, not a sentence.
func TestTrivyVulnsCarryTheirPackage(t *testing.T) {
	rep := parseFixture(t)
	if len(rep.Results) != 3 {
		t.Fatalf("got %d findings, want 3", len(rep.Results))
	}
	byRule := map[string]sarif.Result{}
	for _, r := range rep.Results {
		byRule[r.RuleID] = r
	}

	flask := byRule["CVE-2018-1000656"]
	if flask.Package == nil {
		t.Fatal("no package on a dependency finding")
	}
	want := sarif.Package{
		Name: "Flask", Version: "0.12.2", FixedVersion: "0.12.3",
		PURL: "pkg:pypi/flask@0.12.2", Ecosystem: "pip",
	}
	if *flask.Package != want {
		t.Errorf("package = %+v, want %+v", *flask.Package, want)
	}
	// The ecosystem comes from the result block, so a second manifest in the same run is not
	// labelled with the first one's.
	if got := byRule["CVE-2024-24790"].Package.Ecosystem; got != "gomod" {
		t.Errorf("ecosystem = %q, want gomod", got)
	}
	// No fix is a real answer, and a different one from "unknown".
	if got := byRule["CVE-2020-28493"].Package.FixedVersion; got != "" {
		t.Errorf("FixedVersion = %q, want empty for a vulnerability with no fix", got)
	}
}

// The location is the manifest the package was declared in, which is more use than the scan root
// the SARIF path reported.
func TestTrivyVulnsAreLocatedAtTheirManifest(t *testing.T) {
	rep := parseFixture(t)
	seen := map[string]string{}
	for _, r := range rep.Results {
		seen[r.RuleID] = r.Location.URI
	}
	if seen["CVE-2018-1000656"] != "requirements.txt" || seen["CVE-2024-24790"] != "go.sum" {
		t.Errorf("locations = %v", seen)
	}
}

// Everything the SARIF path carried has to survive the swap, or reading JSON trades one gap for
// another.
func TestTrivyVulnsKeepWhatTheSARIFPathGave(t *testing.T) {
	rep := parseFixture(t)
	byRule := map[string]sarif.Result{}
	for _, r := range rep.Results {
		byRule[r.RuleID] = r
	}

	// The score behind `security-severity`, taken as the highest across sources — a vendor rating
	// a flaw below NVD is a claim about their build, not a correction.
	flask := byRule["CVE-2018-1000656"]
	if !flask.HasScore || flask.Score != 7.5 {
		t.Errorf("score = %v (has=%v), want 7.5 from nvd rather than redhat's 5.9",
			flask.Score, flask.HasScore)
	}
	// Severity ladder.
	if got := byRule["CVE-2024-24790"].Level; got != sarif.LevelError {
		t.Errorf("CRITICAL -> %q, want error", got)
	}
	if got := byRule["CVE-2020-28493"].Level; got != sarif.LevelWarning {
		t.Errorf("MEDIUM -> %q, want warning", got)
	}
	// Rule documentation and the advisory link a reader follows.
	rule, ok := rep.Rules["CVE-2018-1000656"]
	if !ok {
		t.Fatal("no rule recorded")
	}
	if rule.HelpURI != "https://avd.aquasec.com/nvd/cve-2018-1000656" {
		t.Errorf("helpURI = %q", rule.HelpURI)
	}
	if rule.ShortDescription == "" || rule.FullDescription == "" {
		t.Errorf("rule descriptions were dropped: %+v", rule)
	}
}

// The message is what a console shows, so it says what to do rather than restating the identifier.
func TestTrivyVulnMessageSaysWhatToDo(t *testing.T) {
	rep := parseFixture(t)
	byRule := map[string]sarif.Result{}
	for _, r := range rep.Results {
		byRule[r.RuleID] = r
	}
	if got := byRule["CVE-2018-1000656"].Message; !strings.Contains(got, "fixed in 0.12.3") {
		t.Errorf("message = %q, want the fixed version", got)
	}
	// The more alarming answer has to be the louder one.
	if got := byRule["CVE-2020-28493"].Message; !strings.Contains(got, "no fixed version available") {
		t.Errorf("message = %q, want it to say there is no fix", got)
	}
}

func TestTrivyVulnsRejectUnreadableOutput(t *testing.T) {
	if _, err := parseTrivyVulns([]byte("not json"), "", plugin.Config{}); err == nil {
		t.Error("unreadable output was treated as an empty report, which reads as a clean scan")
	}
}

// A run that found nothing produces a report with no findings, not an error.
func TestTrivyVulnsOnACleanScan(t *testing.T) {
	rep, err := parseTrivyVulns([]byte(`{"Results":[{"Target":"go.sum","Type":"gomod"}]}`), "", plugin.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 0 {
		t.Errorf("got %d findings from a clean scan", len(rep.Results))
	}
}
