package scanners

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/draugr-dev/draugr/internal/versionorder"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// aquaTool is the name a finding read from Aqua's scanner JSON is reported under.
const aquaTool = "Aqua"

// errNotAquaJSON is the error of a file that is not the JSON Aqua's scanner writes of an image scan.
var errNotAquaJSON = errors.New("not Aqua's scanner JSON. Write it with " +
	"scannercli scan --jsonfile <file> <image>")

// aquaIncomplete is the error of a file, resource or vulnerability missing what the format needs to
// place and name it: what names it, and the key it lacks.
func aquaIncomplete(what, key string) error {
	return fmt.Errorf("%s has no %s, which Aqua's scanner writes for every one. Import the file "+
		"scannercli wrote, unedited", what, key)
}

// aquaFile is the JSON `scannercli scan --jsonfile` writes of one image. Aqua publishes no schema for
// it outside its console's documentation; the fields are those its Harbor adapter decodes
// (github.com/aquasecurity/harbor-scanner-aqua, pkg/aqua/model.go) and real files hold. The image's
// sensitive data, malware and assurance policy results are not a vulnerable package, and are not
// read.
type aquaFile struct {
	// Image is the image as it was asked for, "library/photon@sha256:…" or "web:1.0", PullName the
	// reference it was pulled by, and Digest its digest; files seen name all three.
	Image    string `json:"image"`
	PullName string `json:"pull_name"`
	Digest   string `json:"digest"`
	// OS and Version are the image's operating system, "debian" and "10".
	OS      string `json:"os"`
	Version string `json:"version"`
	// Resources are the image's packages and files with their vulnerabilities, and Summary their
	// counts by severity. A file without either is not the scanner's.
	Resources *[]aquaResourceScan `json:"resources"`
	Summary   json.RawMessage     `json:"vulnerability_summary"`
}

// aquaResourceScan is one package or file in the image and its vulnerabilities.
type aquaResourceScan struct {
	Resource        aquaResource        `json:"resource"`
	Vulnerabilities []aquaVulnerability `json:"vulnerabilities"`
}

// aquaResource is a package or file Aqua found vulnerabilities in.
type aquaResource struct {
	// Format is the package's kind, "deb", "apk" or "rpm" for the operating system's, "npm" or "java"
	// for an application's, and absent for a binary or a library Aqua identifies by its path.
	Format string `json:"format"`
	// Name and Version are the package's; a library identified by its path has neither.
	Name    string `json:"name"`
	Version string `json:"version"`
	// Path is where the package or file is in the image, absent for the operating system's packages.
	Path string `json:"path"`
	// SrcName and SrcVersion are the source package an operating-system package was built from.
	SrcName    string `json:"src_name"`
	SrcVersion string `json:"src_version"`
}

// aquaVulnerability is one vulnerability of one resource.
type aquaVulnerability struct {
	// Name is the CVE, or the advisory's own id where it has none, such as Debian's DSA.
	Name        string `json:"name"`
	Description string `json:"description"`
	NVDURL      string `json:"nvd_url"`
	VendorURL   string `json:"vendor_url"`
	// FixVersion is the versions that fix it, one or several joined by commas, sometimes followed or
	// replaced by the vendor's words on the fix, and absent where there is none.
	FixVersion string `json:"fix_version"`
	// AquaSeverity is Aqua's rating, and AquaScore the CVSS score Aqua chose for it, absent where
	// nobody scored it.
	AquaSeverity string          `json:"aqua_severity"`
	AquaScore    json.RawMessage `json:"aqua_score"`
}

// aquaSeverities are the bands of the severities Aqua gives a vulnerability. Negligible, which Aqua
// gives where a distribution calls the flaw unimportant, is the lowest band Draugr has.
var aquaSeverities = map[string]sarif.Severity{
	"critical":   sarif.SeverityCritical,
	"high":       sarif.SeverityHigh,
	"medium":     sarif.SeverityMedium,
	"low":        sarif.SeverityLow,
	"negligible": sarif.SeverityLow,
}

// aquaOSFormats are the package formats of an operating system's package database.
var aquaOSFormats = []string{"apk", "deb", "rpm"}

// readAquaImport reads the vulnerable packages in the JSON `scannercli scan --jsonfile` writes.
//
// A finding is a vulnerability of a package at the version installed, in the image it was found in,
// under its CVE, so the known-exploited and EPSS feeds reach it. It is rated by Aqua's CVSS score
// where that is at least as severe as Aqua's severity, as Draugr's image scan rates a vulnerability
// by its score, and otherwise by the severity. The fixed version is read from the versions Aqua
// names, and only those above the one installed where the package's ecosystem orders them.
func readAquaImport(data []byte, _ plugin.FileTarget) (importRead, error) {
	// An object without resources would decode to no packages and read as a clean scan.
	if !bytes.HasPrefix(bytes.TrimSpace(data), []byte("{")) {
		return importRead{}, errNotAquaJSON
	}
	var file aquaFile
	if err := json.Unmarshal(data, &file); err != nil || (file.Resources == nil && len(file.Summary) == 0) {
		return importRead{}, errNotAquaJSON
	}
	ref := cmpTrimmed(file.Image, file.PullName, file.Digest)
	if ref == "" {
		return importRead{}, aquaIncomplete("the file", "image, pull_name or digest, naming the image it scanned")
	}
	rep := sarif.Report{Tool: aquaTool, Rules: map[string]sarif.Rule{}}
	var rated []string
	seen := map[string]int{}
	var resources []aquaResourceScan
	if file.Resources != nil {
		resources = *file.Resources
	}
	for _, rs := range resources {
		res := rs.Resource
		if cmpTrimmed(res.Name, res.Path) == "" && len(rs.Vulnerabilities) > 0 {
			return importRead{}, aquaIncomplete("a resource in "+ref, "name or path")
		}
		for _, v := range rs.Vulnerabilities {
			if strings.TrimSpace(v.Name) == "" {
				return importRead{}, aquaIncomplete("a vulnerability of "+cmpTrimmed(res.Name, res.Path)+" in "+ref,
					"name, its CVE or advisory id")
			}
			found, scored, err := aquaResult(file, ref, res, v)
			if err != nil {
				return importRead{}, err
			}
			// A package listed twice with one vulnerability is one finding, rated by the worse copy.
			key := found.RuleID + "\x00" + found.Package.Name + "\x00" + found.Package.Version + "\x00" + res.Path
			if at, dup := seen[key]; dup {
				if found.Severity("").Rank() > rep.Results[at].Severity("").Rank() {
					rep.Results[at], rated[at] = found, aquaRated(scored)
				}
				continue
			}
			seen[key] = len(rep.Results)
			rep.Results = append(rep.Results, found)
			rated = append(rated, aquaRated(scored))
			if _, ok := rep.Rules[found.RuleID]; !ok {
				rep.Rules[found.RuleID] = sarif.Rule{Name: found.RuleID, HelpURI: cmpTrimmed(v.NVDURL, v.VendorURL)}
			}
		}
	}

	var run importRun
	run.Tool.Driver = importDriver{Name: aquaTool}
	run.Results = make([]json.RawMessage, len(rep.Results))
	return importRead{rep: rep, meta: importLog{Runs: []importRun{run}}, rated: rated, scored: "CVSS score"}, nil
}

// cmpTrimmed is the first of values that is not blank, trimmed, and "" where all are.
func cmpTrimmed(values ...string) string {
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	return ""
}

// aquaRated names the rating a finding's severity was read from, "" where it was its score.
func aquaRated(scored bool) string {
	if scored {
		return ""
	}
	return "Aqua's severity"
}

// aquaResult is the finding of the vulnerability v of the resource res in the image file describes,
// whose reference is ref, and whether it is rated by its score.
func aquaResult(file aquaFile, ref string, res aquaResource, v aquaVulnerability) (sarif.Result, bool, error) {
	id := strings.TrimSpace(v.Name)
	p := aquaPackageFor(file, res)
	severity := strings.ToLower(strings.TrimSpace(v.AquaSeverity))
	band, known := aquaSeverities[severity]
	if !known {
		return sarif.Result{}, false, fmt.Errorf("aqua_severity %q of %s in %s; Aqua rates a vulnerability critical, "+
			"high, medium, low or negligible. Import the file scannercli wrote, unedited", v.AquaSeverity, id, p.name)
	}
	score, hasScore, ok := jsonCVSSScore(v.AquaScore)
	if !ok {
		return sarif.Result{}, false, fmt.Errorf("aqua_score %s of %s in %s; Aqua writes a number from 0 to 10. "+
			"Import the file scannercli wrote, unedited", string(v.AquaScore), id, p.name)
	}
	// A score that puts the vulnerability below Aqua's own severity is not taken, since a reading of
	// the same flaw as less severe is no reason to rank it lower.
	if hasScore && sarif.SeverityFromScore(score).Rank() < band.Rank() {
		hasScore = false
	}
	installed := strings.TrimSpace(res.Version)
	fixed, whole := aquaFixedVersion(p, installed, v.FixVersion)
	pkg := &sarif.Package{Name: p.name, Version: installed, FixedVersion: fixed, Ecosystem: p.ecosystem}

	var detail []string
	if d := strings.TrimSpace(v.Description); d != "" {
		detail = append(detail, d)
	}
	if src := strings.TrimSpace(res.SrcName); src != "" && src != p.name {
		detail = append(detail, "Built from "+strings.TrimSpace(src+" "+strings.TrimSpace(res.SrcVersion))+".")
	}
	if path := strings.TrimSpace(res.Path); path != "" && path != p.name {
		detail = append(detail, "Found at "+path+".")
	}
	if text := strings.Join(strings.Fields(v.FixVersion), " "); !whole && text != "" {
		// A fix this does not read whole stays in front of the reader, beside the version it read or
		// "no fix available".
		detail = append(detail, "Aqua's fix: "+text+".")
	}
	r := sarif.Result{
		Tool:     aquaTool,
		RuleID:   id,
		Level:    osvLevel(band),
		Location: sarif.Location{URI: ref},
		Image:    ref,
		Package:  pkg,
		HasScore: hasScore,
		Message: trivyVulnMessage(trivyVuln{PkgName: pkg.Name, InstalledVersion: pkg.Version,
			FixedVersion: pkg.FixedVersion}),
		Detail: strings.Join(detail, " "),
		Rating: newRating(band, map[string]string{"severity": severity}, "Aqua "+severity),
	}
	if hasScore {
		r.Score = score
	}
	if p.os {
		r.OperatingSystem = strings.TrimSpace(strings.TrimSpace(file.OS) + " " + strings.TrimSpace(file.Version))
	}
	return r, hasScore, nil
}

// aquaPackageFor is the package res is. One whose format is an operating system's package database's
// is the image's operating system's, in the distribution's ecosystem, or the format's where Draugr
// does not know the distribution. Any other package belongs to the ecosystem its format names where
// Draugr knows it, and to none otherwise: Aqua's java format names a package by its path in the image
// rather than its Maven coordinates. A library Aqua identifies by its path alone is named by the path.
func aquaPackageFor(file aquaFile, res aquaResource) twistcliPackageOf {
	format := strings.ToLower(strings.TrimSpace(res.Format))
	p := twistcliPackageOf{name: cmpTrimmed(res.Name, res.Path), os: slices.Contains(aquaOSFormats, format)}
	if p.os {
		distro := strings.ToLower(strings.TrimSpace(file.OS))
		for _, d := range twistcliDistros {
			if strings.HasPrefix(distro, d.prefix) {
				p.ecosystem = d.ecosystem
				break
			}
		}
	}
	if p.ecosystem == "" && versionorder.PURLType(format) != "" {
		p.ecosystem = format
	}
	if p.ecosystem != "" {
		p.orderedAs = versionorder.Ecosystem("", p.ecosystem)
	}
	return p
}

// aquaFixedVersion is the versions Aqua's fix names, joined as Trivy joins several, and whether that
// is all the fix says. Aqua writes one version, several joined by commas, or either followed by the
// vendor's words on its own lines, or the vendor's words alone; only a first line of versions is read
// as versions, and false keeps the whole text for the reader where anything else is written or no
// version above the installed one is named. Where the package's ecosystem orders its versions, a
// version at or below the one installed is left out, since it fixes an older release line; where it
// does not, every version is kept, there being none to compare them with. No fix needs no more said.
func aquaFixedVersion(p twistcliPackageOf, installed, fix string) (fixed string, whole bool) {
	text := strings.TrimSpace(fix)
	if text == "" {
		return "", true
	}
	first, rest, _ := strings.Cut(text, "\n")
	var listed []string
	for v := range strings.SplitSeq(first, ",") {
		v = strings.TrimSpace(v)
		if strings.ContainsAny(v, " \t") {
			return "", false
		}
		if v != "" && !slices.Contains(listed, v) {
			listed = append(listed, v)
		}
	}
	var have versionorder.Version
	ordered := false
	if p.orderedAs != "" {
		have, ordered = versionorder.Parse(p.orderedAs, installed)
	}
	var versions []string
	for _, v := range listed {
		if ordered {
			if parsed, ok := versionorder.Parse(p.orderedAs, v); ok {
				if order, ok := parsed.Compare(have); ok && order <= 0 {
					continue
				}
			}
		}
		versions = append(versions, v)
	}
	return strings.Join(versions, ", "), len(versions) > 0 && strings.TrimSpace(rest) == ""
}
