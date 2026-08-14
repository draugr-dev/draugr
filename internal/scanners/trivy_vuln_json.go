package scanners

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// Trivy's SARIF says which vulnerability and where; its JSON also says which package.
//
// The package is in the SARIF too, as prose: the message reads "Package: flask\nFixed Version:
// 0.12.3". That is a fact formatted for a human and unavailable to anything else, and parsing it
// back out would be reading a sentence a tool is free to reword. The JSON has the same facts as
// fields, plus a purl, plus the manifest the package was declared in — so it is read instead, and
// the SARIF Draugr publishes is built here rather than by Trivy.
//
// Nothing is lost in the swap. Everything the SARIF carried — rule documentation, the advisory
// link, the CVSS score behind `security-severity` — is in the JSON under another name.

// trivyVulnDoc is the slice of Trivy's JSON this reads.
type trivyVulnDoc struct {
	Results []trivyVulnResult `json:"Results"`
}

type trivyVulnResult struct {
	// Target is the manifest or layer the packages were found in — "requirements.txt", "go.mod",
	// an image's OS package database. More precise than the SARIF location, which points at the
	// scanned root.
	Target          string      `json:"Target"`
	Type            string      `json:"Type"`
	Vulnerabilities []trivyVuln `json:"Vulnerabilities"`
}

type trivyVuln struct {
	VulnerabilityID  string `json:"VulnerabilityID"`
	PkgName          string `json:"PkgName"`
	InstalledVersion string `json:"InstalledVersion"`
	FixedVersion     string `json:"FixedVersion"`
	Status           string `json:"Status"`
	PkgIdentifier    struct {
		PURL string `json:"PURL"`
	} `json:"PkgIdentifier"`
	Severity    string `json:"Severity"`
	Title       string `json:"Title"`
	Description string `json:"Description"`
	PrimaryURL  string `json:"PrimaryURL"`
	CVSS        map[string]struct {
		V3Score float64 `json:"V3Score"`
		V40     float64 `json:"V40Score"`
	} `json:"CVSS"`
}

// parseTrivyVulns turns Trivy's JSON into the report Draugr publishes.
func parseTrivyVulns(out []byte, _ string, _ plugin.Config) (sarif.Report, error) {
	var doc trivyVulnDoc
	if err := json.Unmarshal(out, &doc); err != nil {
		return sarif.Report{}, fmt.Errorf("parse trivy JSON: %w", err)
	}
	rep := sarif.Report{Tool: "trivy", Rules: map[string]sarif.Rule{}}
	for _, res := range doc.Results {
		for _, v := range res.Vulnerabilities {
			rep.Results = append(rep.Results, trivyVulnResultOf(res, v))
			if _, seen := rep.Rules[v.VulnerabilityID]; !seen {
				rep.Rules[v.VulnerabilityID] = trivyVulnRule(v)
			}
		}
	}
	return rep, nil
}

// trivyVulnResultOf builds one finding.
func trivyVulnResultOf(res trivyVulnResult, v trivyVuln) sarif.Result {
	score, hasScore := trivyVulnScore(v)
	return sarif.Result{
		Tool:     "trivy",
		RuleID:   v.VulnerabilityID,
		Level:    trivyVulnLevel(v.Severity),
		Message:  trivyVulnMessage(v),
		Location: sarif.Location{URI: res.Target},
		Score:    score,
		HasScore: hasScore,
		Package: &sarif.Package{
			Name:         v.PkgName,
			Version:      v.InstalledVersion,
			FixedVersion: v.FixedVersion,
			PURL:         v.PkgIdentifier.PURL,
			Ecosystem:    res.Type,
		},
	}
}

// trivyVulnRule is the rule documentation a reader follows.
func trivyVulnRule(v trivyVuln) sarif.Rule {
	return sarif.Rule{
		Name:             v.VulnerabilityID,
		ShortDescription: v.Title,
		FullDescription:  v.Description,
		HelpURI:          v.PrimaryURL,
	}
}

// trivyVulnMessage is the one line a console shows, and the sentence a reader acts on.
//
// It says what to do rather than restating the identifier: the fixed version is the action, and
// its absence is the more alarming answer — "no fix available" is a decision to make, where a
// version number is a change to schedule.
func trivyVulnMessage(v trivyVuln) string {
	subject := v.PkgName
	if v.InstalledVersion != "" {
		subject += " " + v.InstalledVersion
	}
	action := "no fixed version available"
	if v.FixedVersion != "" {
		action = "fixed in " + v.FixedVersion
	}
	if v.Title != "" {
		return subject + ": " + v.Title + " (" + action + ")"
	}
	return subject + ": " + action
}

// trivyVulnLevel maps Trivy's severity onto SARIF's three.
//
// Severity itself is recovered from the score below, which is finer than this — the level exists
// because SARIF has one, not because it is the interesting number.
func trivyVulnLevel(severity string) sarif.Level {
	switch strings.ToUpper(severity) {
	case "CRITICAL", "HIGH":
		return sarif.LevelError
	case "MEDIUM":
		return sarif.LevelWarning
	case "LOW", "UNKNOWN":
		return sarif.LevelNote
	default:
		return sarif.LevelNote
	}
}

// trivyVulnScore recovers the CVSS score Trivy's SARIF published as `security-severity`.
//
// Trivy reports a score per source — nvd, ghsa, redhat — and its own SARIF picks one. The highest
// is taken here for the same reason severity is never rounded down: a vendor scoring a flaw lower
// than NVD is a claim about their build, and Draugr is not in a position to accept it silently.
func trivyVulnScore(v trivyVuln) (float64, bool) {
	best, found := 0.0, false
	for _, c := range v.CVSS {
		for _, s := range []float64{c.V3Score, c.V40} {
			if s > best {
				best, found = s, true
			}
		}
	}
	return best, found
}
