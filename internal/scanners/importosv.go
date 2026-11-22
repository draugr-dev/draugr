package scanners

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/draugr-dev/draugr/internal/versionorder"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// OSV-Scanner's SARIF names each finding by one identifier, lists its others as the rule's deprecated
// ids, carries no score, and states the package and its fix in prose. Its JSON keeps each as a field:
// the package with its ecosystem and package URL, the advisories OSV-Scanner grouped as one
// vulnerability with every alias they list, the highest score among them, and each advisory's
// affected ranges, which say which version fixes it.
//
// Draugr runs no OSV-Scanner of its own, so there is no native parser to share. The reader builds
// each finding as Draugr's dependency scanners build theirs, Trivy's above all: a finding per
// vulnerability and package, keyed on an advisory id with the others as aliases, so KEV and EPSS
// reach it by its CVE and correlation joins it to another scanner's finding of that CVE.
//
// Read from the JSON OSV-Scanner 2.7.1 wrote for a package-lock.json pinning lodash 4.17.20,
// testdata/sarif-import/osv-scanner-lodash.json. What that file does not show is quoted from
// OSV-Scanner's output documentation, https://google.github.io/osv-scanner/output/.

// errNotOSVScannerJSON is the error of a file that is not OSV-Scanner's JSON report.
var errNotOSVScannerJSON = errors.New("not OSV-Scanner JSON. Write it with osv-scanner scan --format json")

// osvScanner is the tool an imported OSV-Scanner finding names, as OSV-Scanner's SARIF names itself.
const osvScanner = "osv-scanner"

// osvDoc is the part of OSV-Scanner's JSON report the reader reads.
type osvDoc struct {
	Results []osvResult `json:"results"`
}

// osvResult is one file OSV-Scanner read and the vulnerable packages it found in it.
type osvResult struct {
	Source struct {
		// Path is the file, absolute as OSV-Scanner writes it.
		Path string `json:"path"`
		// Type is what the file is. The documentation lists "One of: lockfile, sbom, git, docker".
		Type string `json:"type"`
	} `json:"source"`
	Packages []osvPackage `json:"packages"`
}

// osvPackage is one vulnerable package and the advisories that name it.
type osvPackage struct {
	Package struct {
		Name      string `json:"name"`
		Version   string `json:"version"`
		Ecosystem string `json:"ecosystem"`
		PURL      string `json:"purl"`
	} `json:"package"`
	// Groups are the package's vulnerabilities, one each. In the documentation's words: "Grouping
	// based on aliases, if two vulnerability share the same alias, or alias each other, they are
	// considered the same vulnerability, and is grouped here under the id field."
	Groups          []osvGroup         `json:"groups"`
	Vulnerabilities []osvVulnerability `json:"vulnerabilities"`
}

// osvGroup is one vulnerability: the advisories OSV-Scanner grouped, every alias they list, and the
// highest score among them, which OSV-Scanner writes as a string, "7.2".
type osvGroup struct {
	IDs         []string `json:"ids"`
	Aliases     []string `json:"aliases"`
	MaxSeverity string   `json:"max_severity"`
}

// osvVulnerability is one advisory, an OSV record.
type osvVulnerability struct {
	ID       string        `json:"id"`
	Aliases  []string      `json:"aliases"`
	Summary  string        `json:"summary"`
	Details  string        `json:"details"`
	Affected []osvAffected `json:"affected"`
	// DatabaseSpecific is whatever the advisory's database adds, which the OSV schema leaves to
	// each database, so it is read as raw JSON and only its severity is taken from it.
	DatabaseSpecific json.RawMessage `json:"database_specific"`
}

// osvAffected is one package an advisory covers, and the versions of it that are affected.
type osvAffected struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
	} `json:"package"`
	Ranges []struct {
		// Type is SEMVER or ECOSYSTEM for a range of versions, GIT for a range of commits.
		Type   string `json:"type"`
		Events []struct {
			Introduced   string `json:"introduced"`
			Fixed        string `json:"fixed"`
			LastAffected string `json:"last_affected"`
		} `json:"events"`
	} `json:"ranges"`
}

// readOSVScannerImport reads the JSON `osv-scanner scan --format json` writes.
//
// A finding is a vulnerability OSV-Scanner grouped, in one package, at the file it read the package
// from. It is keyed on the group's first advisory id, the one OSV-Scanner matched; the group's other
// ids and every alias they list, its CVE among them, are the finding's aliases.
//
// Only a lockfile's or an SBOM's results are read. Each is a file in the repository, and its path
// places the finding there. A container image's packages are about the image rather than the
// component's repositories, and a git result names a commit rather than a package version, so a
// file holding either is refused rather than read in part.
func readOSVScannerImport(data []byte, ft plugin.FileTarget) (importRead, error) {
	// Every OSV-Scanner report is an object listing its results, an empty list for a clean scan. The
	// key is matched exactly: Go's decoder matches field names without regard to case, and Trivy's
	// report lists its Results, which would otherwise read as a scan that found nothing.
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil || !bytes.HasPrefix(bytes.TrimSpace(top["results"]), []byte("[")) {
		return importRead{}, errNotOSVScannerJSON
	}
	var doc osvDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return importRead{}, errNotOSVScannerJSON
	}
	rep := sarif.Report{Tool: osvScanner, Rules: map[string]sarif.Rule{}}
	var rated []string
	for _, res := range doc.Results {
		switch res.Source.Type {
		case "lockfile", "sbom":
		case "":
			return importRead{}, errNotOSVScannerJSON
		default:
			return importRead{}, fmt.Errorf("%s source; Draugr reads only lockfiles and SBOMs. Scan the directory", res.Source.Type)
		}
		for _, p := range res.Packages {
			for _, g := range osvGroups(p) {
				if len(g.IDs) == 0 {
					return importRead{}, errNotOSVScannerJSON
				}
				found, rule, rating := osvFinding(res, p, g)
				rep.Results = append(rep.Results, found)
				rated = append(rated, rating)
				if _, seen := rep.Rules[found.RuleID]; !seen {
					rep.Rules[found.RuleID] = rule
				}
			}
		}
	}
	outside := relativeToCheckouts(rep.Results, checkoutRoots(ft.Repositories))
	// The line of the package's entry in its lockfile, where the component's one checkout is here to
	// read, as trivy-fs finds it. Zero where it is not: the finding still points at the file.
	if root := importRoot(ft.Repositories); root != "" {
		lines := newLineIndex(root)
		for i := range rep.Results {
			r := &rep.Results[i]
			if !filepath.IsAbs(r.Location.URI) {
				r.Location.StartLine = lines.find(r.Location.URI, r.Package.Name, r.Package.Version)
			}
		}
	}

	// OSV-Scanner's JSON names no version of itself and no time it ran, so the report states the
	// tool alone and the file's modification time.
	var run importRun
	run.Tool.Driver = importDriver{Name: osvScanner}
	run.Results = make([]json.RawMessage, len(rep.Results))
	return importRead{rep: rep, outside: outside, meta: importLog{Runs: []importRun{run}}, rated: rated,
		scored: "CVSS score"}, nil
}

// osvGroups are a package's vulnerabilities: its groups, and a group of its own for any advisory no
// group lists, so an advisory the file names is never left out for want of a group.
func osvGroups(p osvPackage) []osvGroup {
	groups := slices.Clone(p.Groups)
	for _, v := range p.Vulnerabilities {
		if v.ID == "" || slices.ContainsFunc(groups, func(g osvGroup) bool { return slices.Contains(g.IDs, v.ID) }) {
			continue
		}
		groups = append(groups, osvGroup{IDs: []string{v.ID}, Aliases: v.Aliases})
	}
	return groups
}

// osvFinding is the finding for the vulnerability g in the package p of the result res, the rule it
// is reported under, and, where neither a score nor the advisory rated it, the rating it is read at.
//
// Severity is the group's max_severity, the highest score OSV-Scanner computed from the advisories'
// CVSS vectors: 6.9 for GHSA-xxjr-mmjv-4gpg in the recorded file, whose CVSS v3 vector scores 6.5 and
// whose v4 vector 6.9. That is Trivy's rule too, the highest score any source gives. Without one, the
// advisory's own rating in database_specific.severity, the GitHub advisory database's LOW, MODERATE,
// HIGH or CRITICAL. An advisory that rates it neither way, as the Go vulnerability database rates
// none, is medium, as an imported govulncheck finding is and as OSV-Scanner's SARIF levels every
// finding.
func osvFinding(res osvResult, p osvPackage, g osvGroup) (sarif.Result, sarif.Rule, string) {
	id := g.IDs[0]
	var vulns []osvVulnerability
	for _, gid := range g.IDs {
		if i := slices.IndexFunc(p.Vulnerabilities, func(v osvVulnerability) bool { return v.ID == gid }); i >= 0 {
			vulns = append(vulns, p.Vulnerabilities[i])
		}
	}
	aliases := slices.Clone(g.IDs[1:])
	aliases = append(aliases, g.Aliases...)
	var summary, details string
	for _, v := range vulns {
		aliases = append(aliases, v.Aliases...)
		if summary == "" {
			summary, details = v.Summary, v.Details
		}
	}
	pkg := &sarif.Package{
		Name:         p.Package.Name,
		Version:      p.Package.Version,
		FixedVersion: osvFixedVersion(p, vulns),
		PURL:         osvPURL(p.Package.PURL),
		Ecosystem:    p.Package.Ecosystem,
	}
	found := sarif.Result{
		Tool:     osvScanner,
		RuleID:   id,
		Level:    sarif.LevelWarning,
		Location: sarif.Location{URI: res.Source.Path},
		Aliases:  osvAliases(id, aliases),
		Package:  pkg,
		Message: trivyVulnMessage(trivyVuln{PkgName: pkg.Name, InstalledVersion: pkg.Version,
			FixedVersion: pkg.FixedVersion, Title: summary}),
	}
	rated := ""
	if score, err := strconv.ParseFloat(strings.TrimSpace(g.MaxSeverity), 64); err == nil && score > 0 {
		found.Score, found.HasScore = score, true
		found.Level = osvLevel(sarif.SeverityFromScore(score))
	} else if rating := osvAdvisoryRating(vulns); rating != nil {
		found.Rating = rating
		found.Level = osvLevel(rating.Severity)
		rated = "the advisory's severity"
	} else {
		markNotScored(&found, nil, found.Message)
		rated = "OSV-Scanner states none, " + notScoredYet + ", read as high"
	}
	rule := sarif.Rule{Name: id, ShortDescription: summary, FullDescription: details,
		// The documentation's table links each vulnerability as "OSV URL: Link to the osv.dev entry
		// for the vulnerability", https://osv.dev/<id>.
		HelpURI: "https://osv.dev/" + url.PathEscape(id)}
	return found, rule, rated
}

// osvAliases are the identifiers in ids other than the finding's own, each once, in the order the
// file lists them.
func osvAliases(own string, ids []string) []string {
	var out []string
	for _, a := range ids {
		if a == "" || a == own || slices.Contains(out, a) {
			continue
		}
		out = append(out, a)
	}
	return out
}

// osvSeverities are the bands database_specific.severity names, in the GitHub advisory database's
// words.
var osvSeverities = map[string]sarif.Severity{
	"CRITICAL": sarif.SeverityCritical,
	"HIGH":     sarif.SeverityHigh,
	"MODERATE": sarif.SeverityMedium,
	"MEDIUM":   sarif.SeverityMedium,
	"LOW":      sarif.SeverityLow,
}

// osvAdvisoryRating is the highest rating the grouped advisories give in database_specific.severity,
// or nil where none gives one this reads. A database that writes something else there, or nothing,
// rates nothing.
func osvAdvisoryRating(vulns []osvVulnerability) *sarif.Rating {
	var best *sarif.Rating
	for _, v := range vulns {
		var specific struct {
			Severity json.RawMessage `json:"severity"`
		}
		var word string
		if json.Unmarshal(v.DatabaseSpecific, &specific) != nil || json.Unmarshal(specific.Severity, &word) != nil {
			continue
		}
		word = strings.ToUpper(strings.TrimSpace(word))
		severity, ok := osvSeverities[word]
		if !ok || (best != nil && best.Severity.Rank() >= severity.Rank()) {
			continue
		}
		best = newRating(severity, map[string]string{"severity": word}, "severity "+word)
	}
	return best
}

// osvLevel is the SARIF level of a band, as Trivy's findings are leveled.
func osvLevel(s sarif.Severity) sarif.Level {
	switch s {
	case sarif.SeverityCritical, sarif.SeverityHigh:
		return sarif.LevelError
	case sarif.SeverityMedium:
		return sarif.LevelWarning
	}
	return sarif.LevelNote
}

// osvPURL is the package URL OSV-Scanner wrote without its `source` qualifier.
//
// OSV-Scanner 2.7.1 writes lodash's as pkg:npm/lodash@4.17.20?source=PUBLIC_REGISTRY, which says
// where the lockfile resolved the package from, and every other scanner Draugr reads writes
// pkg:npm/lodash@4.17.20. Correlation compares package URLs whole, so with the qualifier the finding
// would never meet another scanner's copy of the same flaw in the same package. Any other qualifier,
// such as a Maven classifier, names which artifact the package is, and is kept.
func osvPURL(purl string) string {
	base, query, ok := strings.Cut(purl, "?")
	if !ok {
		return purl
	}
	qs, err := url.ParseQuery(query)
	if err != nil {
		return purl
	}
	qs.Del("source")
	if len(qs) == 0 {
		return base
	}
	return base + "?" + qs.Encode()
}

// osvFixedVersion is the version that fixes the vulnerability vulns describe in p, empty where none
// does.
//
// Each advisory lists, for each package it covers, ranges of affected versions, each opened by an
// introduced event and closed by fixed, by last_affected, or by nothing. Only the advisory's ranges
// for this package count: GHSA-29mw-wpgm-hmr9 lists lodash fixed in 4.17.21 beside lodash.trim,
// affected through 4.5.1 with no fix. Of those, the fix is the one closing the range the installed
// version is in. A range closed by last_affected, or by nothing, holds a version with no fix.
//
// Where the ranges cannot be ordered against the installed version, in an ecosystem Draugr does not
// order or a version that does not parse, or none holds it, the fix is the one fixed version the
// ranges name, else the lowest above the installed version, else every one, joined.
//
// Two advisories grouped as one vulnerability may name two fixes, one database having found a later
// release needed. The finding takes the later one, which fixes it by both.
func osvFixedVersion(p osvPackage, vulns []osvVulnerability) string {
	eco := versionorder.Ecosystem(p.Package.PURL, p.Package.Ecosystem)
	if eco == "" {
		eco = p.Package.Ecosystem
	}
	var fixes []string
	for _, v := range vulns {
		if fix := osvAdvisoryFix(p, v, eco); fix != "" && !slices.Contains(fixes, fix) {
			fixes = append(fixes, fix)
		}
	}
	return latestVersion(eco, fixes)
}

// osvAdvisoryFix is the version that fixes the advisory v in p, by the ranges osvFixedVersion reads.
func osvAdvisoryFix(p osvPackage, v osvVulnerability, eco string) string {
	installed := p.Package.Version
	// before reports whether a is an earlier version than b, and whether the two could be ordered.
	before := func(a, b string) (bool, bool) {
		order, ok := versionorder.Compare(eco, a, b)
		return order < 0, ok
	}
	var named []string
	for _, a := range v.Affected {
		if !osvSamePackage(a, p) {
			continue
		}
		for _, r := range a.Ranges {
			if r.Type != "SEMVER" && r.Type != "ECOSYSTEM" {
				continue
			}
			from, open := "", false
			for _, e := range r.Events {
				switch {
				case e.Introduced != "":
					from, open = e.Introduced, true
				case e.Fixed != "" && open:
					named = append(named, e.Fixed)
					if in, ok := osvHolds(from, installed, before); ok && in {
						if below, ok := before(installed, e.Fixed); ok && below {
							return e.Fixed
						}
					}
					open = false
				case e.LastAffected != "" && open:
					if in, ok := osvHolds(from, installed, before); ok && in {
						if after, ok := before(e.LastAffected, installed); ok && !after {
							return ""
						}
					}
					open = false
				}
			}
			// A range left open affects every version from its start on, and none of them has a fix.
			if in, ok := osvHolds(from, installed, before); open && ok && in {
				return ""
			}
		}
	}
	named = osvAliases("", named)
	if len(named) == 1 {
		return named[0]
	}
	var above []string
	for _, f := range named {
		if below, ok := before(installed, f); !ok {
			return strings.Join(named, ", ")
		} else if below {
			above = append(above, f)
		}
	}
	if len(above) == 0 {
		return strings.Join(named, ", ")
	}
	return earliestVersion(eco, above)
}

// osvHolds reports whether the installed version is at or after from, a range's introduced event,
// "0" meaning every version, and whether that could be told.
func osvHolds(from, installed string, before func(a, b string) (bool, bool)) (bool, bool) {
	if from == "0" {
		return true, true
	}
	earlier, ok := before(installed, from)
	return !earlier, ok
}

// osvSamePackage reports whether the affected entry a is about the package p: the same ecosystem,
// before any release suffix such as Debian:11, and the same name, compared as the ecosystem compares
// names where it folds case.
func osvSamePackage(a osvAffected, p osvPackage) bool {
	ecoA, _, _ := strings.Cut(a.Package.Ecosystem, ":")
	ecoP, _, _ := strings.Cut(p.Package.Ecosystem, ":")
	if !strings.EqualFold(ecoA, ecoP) {
		return false
	}
	if strings.EqualFold(ecoP, "PyPI") {
		fold := strings.NewReplacer("_", "-", ".", "-")
		return strings.EqualFold(fold.Replace(a.Package.Name), fold.Replace(p.Package.Name))
	}
	return a.Package.Name == p.Package.Name
}

// latestVersion is the latest of versions under eco's ordering, and every one, joined, where they
// cannot be ordered.
func latestVersion(eco string, versions []string) string {
	return pickVersion(eco, versions, 1)
}

// earliestVersion is the earliest of versions under eco's ordering, and every one, joined, where
// they cannot be ordered.
func earliestVersion(eco string, versions []string) string {
	return pickVersion(eco, versions, -1)
}

// pickVersion is the version of versions that compares as want (1 for the latest, -1 for the
// earliest) against every other, and every one, joined, where two cannot be ordered.
func pickVersion(eco string, versions []string, want int) string {
	if len(versions) == 0 {
		return ""
	}
	best := versions[0]
	for _, v := range versions[1:] {
		order, ok := versionorder.Compare(eco, v, best)
		if !ok {
			return strings.Join(versions, ", ")
		}
		if order == want {
			best = v
		}
	}
	return best
}
