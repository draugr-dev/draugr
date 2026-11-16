package scanners

import (
	"slices"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// Trivy's JSON for one echo advisory in a Go service, keyed on the CVE with the GitHub advisory id in
// VendorIDs, beside a Debian package in the same image whose VendorIDs are the distribution's errata.
// Excluded by a `.trivyignore` line, the same advisory keeps its identifiers.
const trivyVendorIDsJSON = `{
  "Metadata": {"OS": {"Family": "debian", "Name": "12.8"}},
  "Results": [
    {
      "Target": "go.mod", "Class": "lang-pkgs", "Type": "gomod",
      "Vulnerabilities": [
        {"VulnerabilityID": "CVE-2026-118264", "PkgName": "github.com/labstack/echo/v4",
         "InstalledVersion": "v4.12.0", "Severity": "CRITICAL",
         "VendorIDs": ["GHSA-cxf3-9h37-7rr8", "", "CVE-2026-118264", "CVE-2026-118265", "GHSA-cxf3-9h37-7rr8", "GO-2026-6839"]}
      ],
      "ExperimentalModifiedFindings": [
        {"Type": "vulnerability", "Status": "ignored", "Source": ".trivyignore",
         "Finding": {"VulnerabilityID": "CVE-2026-118266", "PkgName": "github.com/labstack/echo/v4",
                     "InstalledVersion": "v4.12.0", "Severity": "HIGH", "VendorIDs": ["GHSA-q7m4-hr3w-2v9c"]}}
      ]
    },
    {
      "Target": "app (debian 12.8)", "Class": "os-pkgs", "Type": "debian",
      "Vulnerabilities": [
        {"VulnerabilityID": "CVE-2026-0101", "PkgName": "openssl", "InstalledVersion": "3.0.15-1",
         "Severity": "HIGH", "VendorIDs": ["DSA-5901-1", "DLA-4100-1"]}
      ]
    }
  ]
}`

// aliasesByRule is each finding's aliases, keyed by its rule id.
func aliasesByRule(rep sarif.Report) map[string][]string {
	out := map[string][]string{}
	for _, r := range rep.Results {
		out[r.RuleID] = r.Aliases
	}
	return out
}

// A language package's finding names the other identifiers Trivy reported for it, each once, and
// never a CVE: Trivy reports a second CVE as a second finding. An excluded finding keeps them, so a
// copy another scanner keyed on its GitHub advisory id still finds the decision. A distribution's
// errata are left out, because each one fixes several flaws.
func TestTrivyFindingsCarryTheirVendorIDsAsAliases(t *testing.T) {
	for _, c := range []struct {
		name  string
		parse func() (sarif.Report, error)
	}{
		{"filesystem", func() (sarif.Report, error) { return parseTrivyVulns([]byte(trivyVendorIDsJSON), "", nil) }},
		{"image", func() (sarif.Report, error) {
			return parseTrivyImage([]byte(trivyVendorIDsJSON), plugin.ImageTarget{}, nil)
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			rep, err := c.parse()
			if err != nil {
				t.Fatal(err)
			}
			got := aliasesByRule(rep)
			if want := []string{"GHSA-cxf3-9h37-7rr8", "GO-2026-6839"}; !slices.Equal(got["CVE-2026-118264"], want) {
				t.Errorf("echo aliases = %q, want %q", got["CVE-2026-118264"], want)
			}
			if want := []string{"GHSA-q7m4-hr3w-2v9c"}; !slices.Equal(got["CVE-2026-118266"], want) {
				t.Errorf("excluded echo aliases = %q, want %q", got["CVE-2026-118266"], want)
			}
			if a, ok := got["CVE-2026-0101"]; !ok || a != nil {
				t.Errorf("openssl aliases = %q (present %v), want the finding with none", a, ok)
			}
		})
	}
}

// The identifiers reach correlation as vulnerabilities: the GitHub advisory id and the Go id.
func TestTrivyAliasesAreVulnerabilityIDs(t *testing.T) {
	rep, err := parseTrivyVulns([]byte(trivyVendorIDsJSON), "", nil)
	if err != nil {
		t.Fatal(err)
	}
	i := slices.IndexFunc(rep.Results, func(r sarif.Result) bool { return r.RuleID == "CVE-2026-118264" })
	if i < 0 {
		t.Fatal("no echo finding")
	}
	if got, want := rep.Results[i].AliasVulnerabilityIDs(), []string{"GHSA-cxf3-9h37-7rr8", "GO-2026-6839"}; !slices.Equal(got, want) {
		t.Errorf("alias vulnerability ids = %q, want %q", got, want)
	}
}
