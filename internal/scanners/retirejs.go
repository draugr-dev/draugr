package scanners

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/draugr-dev/draugr/internal/tools"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// NewRetireJS returns a Scanner that runs retire.js over a checked-out repository to find known
// vulnerable JavaScript that never appears in a lockfile. It serves the "sca" control, opt-in
// beside Trivy rather than instead of it.
//
// Lockfile-based SCA answers for what the package manager installed. Front-end code routinely
// ships JavaScript it did not: a library pulled from a CDN, a vendored file under static/, bundled
// output shipped without its manifest. retire.js fingerprints those by content, which is the only
// way to identify a file whose provenance was never recorded.
//
// The gap matters because of its shape rather than its size. A repository serving a five-year-old
// jQuery scans clean today — the control runs, reports, and passes — so nothing about the output
// suggests anywhere left to look.
func NewRetireJS() plugin.Scanner {
	return newRepoScannerWithParser(
		plugin.ScannerInfo{
			Name:         "retirejs",
			Origin:       "RetireJS",
			Binary:       "retire",
			Controls:     []string{"sca"},
			TargetKinds:  []plugin.TargetKind{plugin.TargetRepository},
			ConfigSchema: json.RawMessage(noScannerOptions),
		},
		retireJSArgs,
		parseRetireJS,
	)
}

// retireJSArgs builds `retire --path <dir> --outputformat json --exitwith 0`.
//
// --exitwith 0 because retire.js exits 13 when it finds something, and a scanner that fails on
// findings makes the exit code the verdict. Severity is the controller's job and the findings
// belong in the report; this is the same reason Trivy is run with --exit-code 0.
//
// --cachedir moves the advisory database out of /tmp and into the directory Draugr already owns.
// retire.js bundles no database — it fetches one on first use and caches it — so the default
// location means a CI runner downloads it every job, and an air-gapped machine has nowhere to be
// handed one. Under ~/.draugr/data it travels with everything else the air-gapped guide says to
// copy across.
func retireJSArgs(dir string, _ plugin.Config) []string {
	argv := []string{"retire", "--path", dir, "--outputformat", "json", "--exitwith", "0"}
	if cache := retireCacheDir(); cache != "" {
		argv = append(argv, "--cachedir", cache)
	}
	return argv
}

// retireCacheDir is where the advisory database is kept, or "" when Draugr cannot work out a home
// directory — in which case retire.js uses its own default rather than the scan failing over a
// cache location.
func retireCacheDir() string {
	root, err := tools.DataRoot()
	if err != nil {
		return ""
	}
	return filepath.Join(root, "retirejs")
}

// retireReport is the part of retire.js's JSON output Draugr reads.
type retireReport struct {
	Data []struct {
		File    string `json:"file"`
		Results []struct {
			Component string `json:"component"`
			Version   string `json:"version"`
			// Detection is how the library was recognised — "filecontent", "filename", "uri".
			Detection       string             `json:"detection"`
			Vulnerabilities []retireVulnerable `json:"vulnerabilities"`
		} `json:"results"`
	} `json:"data"`
}

type retireVulnerable struct {
	// Below is the first version that is not affected, which is the fix.
	Below       string   `json:"below"`
	Severity    string   `json:"severity"`
	CWE         []string `json:"cwe"`
	Identifiers struct {
		Summary  string   `json:"summary"`
		CVE      []string `json:"CVE"`
		GitHubID string   `json:"githubID"`
		Issue    string   `json:"issue"`
		Bug      string   `json:"bug"`
		RetID    string   `json:"retid"`
	} `json:"identifiers"`
}

// parseRetireJS converts retire.js's JSON into SARIF results.
func parseRetireJS(out []byte, _ string, _ plugin.Config) (sarif.Report, error) {
	var report retireReport
	if err := json.Unmarshal(out, &report); err != nil {
		return sarif.Report{}, fmt.Errorf("decode retire.js output: %w", err)
	}
	var results []sarif.Result
	for _, entry := range report.Data {
		for _, found := range entry.Results {
			for _, v := range found.Vulnerabilities {
				level, score, hasScore := retireSeverity(v.Severity)
				results = append(results, sarif.Result{
					Tool:     "retirejs",
					RuleID:   retireRuleID(found.Component, v),
					Level:    level,
					Score:    score,
					HasScore: hasScore,
					Message:  retireMessage(found.Component, found.Version, found.Detection, v),
					Location: sarif.Location{URI: entry.File},
					Package: &sarif.Package{
						Name:         found.Component,
						Version:      found.Version,
						FixedVersion: v.Below,
						PURL:         retirePURL(found.Component, found.Version),
						Ecosystem:    "npm",
					},
				})
			}
		}
	}
	return sarif.Report{Tool: "retirejs", Results: results}, nil
}

// retireRuleID picks the most portable identifier the advisory carries.
//
// A CVE first, because it is the one a reader can look up and the one an exclusion is most likely
// to be written against. Then the GitHub advisory. Only when an advisory has neither does the rule
// fall back to retire.js's own identifier — prefixed, so it cannot be mistaken for a CVE, and
// stable, so a suppression written against it keeps working.
func retireRuleID(component string, v retireVulnerable) string {
	if len(v.Identifiers.CVE) > 0 && v.Identifiers.CVE[0] != "" {
		return v.Identifiers.CVE[0]
	}
	if v.Identifiers.GitHubID != "" {
		return v.Identifiers.GitHubID
	}
	for _, local := range []string{v.Identifiers.RetID, v.Identifiers.Issue, v.Identifiers.Bug} {
		if local != "" {
			return "retirejs:" + component + ":" + local
		}
	}
	// Nothing identifies it but the fix boundary, which is still stable for a given advisory.
	return "retirejs:" + component + ":below-" + v.Below
}

// retireMessage says what was found, in which library, and what fixes it.
func retireMessage(component, version, detection string, v retireVulnerable) string {
	summary := strings.TrimSpace(v.Identifiers.Summary)
	if summary == "" {
		summary = "known vulnerability"
	}
	msg := fmt.Sprintf("%s %s: %s", component, version, summary)
	if v.Below != "" {
		msg += fmt.Sprintf(" (fixed in %s)", v.Below)
	}
	// How the library was recognised, because it is the answer to "why is this not in my
	// lockfile" — a file matched by content is one the package manager never installed.
	if detection != "" {
		msg += fmt.Sprintf(" [detected by %s]", detection)
	}
	if cwes := nonEmpty(v.CWE); len(cwes) > 0 {
		sort.Strings(cwes)
		msg += " (" + strings.Join(cwes, ", ") + ")"
	}
	return msg
}

// retirePURL builds the package URL for a library retire.js named.
//
// npm, because that is the ecosystem retire.js identifies against even for a file that was never
// installed from it — the vendored copy of jQuery and the npm package are the same library, and
// saying so is what lets a consumer correlate them.
func retirePURL(component, version string) string {
	if component == "" {
		return ""
	}
	purl := "pkg:npm/" + component
	if version != "" {
		purl += "@" + version
	}
	return purl
}

// retireSeverity maps retire.js's severity to a SARIF level and a CVSS-style score, set together
// so counts and prioritization agree. An unrecognised severity gets no score and falls to a note.
func retireSeverity(sev string) (sarif.Level, float64, bool) {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "critical":
		return sarif.LevelError, 9.5, true
	case "high":
		return sarif.LevelError, 8.0, true
	case "medium":
		return sarif.LevelWarning, 5.0, true
	case "low":
		return sarif.LevelNote, 2.0, true
	default:
		return sarif.LevelNote, 0, false
	}
}
