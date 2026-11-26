package scanners

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/draugr-dev/draugr/internal/versionorder"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// twistcliTool is the name a finding read from twistcli's file is reported under: the product whose
// console scanned the image, which is the name its readers know it by.
const twistcliTool = "Prisma Cloud"

// errNotTwistcliJSON is the error of a file that is not the JSON twistcli writes of an image scan.
var errNotTwistcliJSON = errors.New("not twistcli's JSON. Write it with " +
	"twistcli images scan --output-file <file> <image>")

// twistcliIncomplete is the error of an image or vulnerability missing what the format needs to place
// and name it: what names it, and the key it lacks.
func twistcliIncomplete(what, key string) error {
	return fmt.Errorf("%s has no %s, which twistcli writes for every one. Import the file twistcli wrote, "+
		"unedited", what, key)
}

// twistcliFile is the JSON `twistcli images scan --output-file` writes. Palo Alto Networks publishes
// no schema for it; the fields are those its output holds.
type twistcliFile struct {
	Results *[]twistcliImage `json:"results"`
}

// twistcliImage is one scanned image. Its compliance results, a check of how the image is built
// rather than a flaw in a package, are left unread.
type twistcliImage struct {
	// ID is the image's ID, sha256:…, and Name the reference it was scanned by, which older files
	// leave out.
	ID   string `json:"id"`
	Name string `json:"name"`
	// Distro is the image's operating system as twistcli names it, "Debian GNU/Linux 12 (bookworm)".
	Distro          string                  `json:"distro"`
	Packages        []twistcliPackage       `json:"packages"`
	Vulnerabilities []twistcliVulnerability `json:"vulnerabilities"`
}

// twistcliPackage is one package the image holds, where the file lists them, with its type: "os"
// for the operating system's, or the language ecosystem's.
type twistcliPackage struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

// twistcliVulnerability is one vulnerability of one package.
type twistcliVulnerability struct {
	// ID is the CVE, or the advisory's own id where it has none.
	ID       string `json:"id"`
	Severity string `json:"severity"`
	// CVSS is the score, written as a number or as a string, absent where nobody scored it.
	CVSS json.RawMessage `json:"cvss"`
	// PackageName is an operating-system package's source package and the binaries built from it,
	// "glibc (used in libc6, libc-bin)", or another package's name.
	PackageName    string `json:"packageName"`
	PackageVersion string `json:"packageVersion"`
	// PackagePath is where an application's package sits in the image, a .jar or a site-packages
	// directory, absent for the operating system's packages.
	PackagePath string `json:"packagePath"`
	// Status is the fix: "fixed in 2.66-4+deb12u1", several versions after "fixed in", "open" where
	// there is none, or absent.
	Status      string `json:"status"`
	Description string `json:"description"`
	Link        string `json:"link"`
}

// twistcliSeverities are the bands of the severities twistcli gives a vulnerability. Important and
// moderate are a distribution's own words for high and medium, which it passes on for that
// distribution's packages.
var twistcliSeverities = map[string]sarif.Severity{
	"critical":  sarif.SeverityCritical,
	"high":      sarif.SeverityHigh,
	"important": sarif.SeverityHigh,
	"medium":    sarif.SeverityMedium,
	"moderate":  sarif.SeverityMedium,
	"low":       sarif.SeverityLow,
}

// twistcliDistros name the operating systems twistcli writes as Draugr's image scan names their
// packages' ecosystem, by the start of the distro's name.
var twistcliDistros = []struct{ prefix, ecosystem string }{
	{"debian", "debian"},
	{"ubuntu", "ubuntu"},
	{"alpine", "alpine"},
	{"red hat", "redhat"},
	{"rhel", "redhat"},
	{"rocky", "rocky"},
	{"centos", "centos"},
	{"almalinux", "alma"},
	{"amazon", "amazon"},
	{"oracle", "oracle"},
	{"sles", "suse"},
	{"suse", "suse"},
	{"opensuse", "suse"},
}

// twistcliPackageOf is what a finding says of the package a vulnerability is in: its name, the
// binaries built from it, and its ecosystem with the rules its versions are ordered by, "" for both
// where twistcli does not say which ecosystem the package belongs to.
type twistcliPackageOf struct {
	name, binaries, ecosystem, orderedAs string
	// os is whether it is one of the image's operating-system packages.
	os bool
}

// readTwistcliImport reads the vulnerable packages in the JSON `twistcli images scan --output-file`
// writes.
//
// A finding is a vulnerability of a package at the version installed, in the image it was found in,
// under its CVE, so the known-exploited and EPSS feeds reach it. It is rated by its CVSS score where
// that is at least as severe as twistcli's severity, as Draugr's image scan rates a vulnerability by
// its score, and otherwise by the severity. The fixed version is read from the fix status, and only
// versions above the one installed where the package's ecosystem orders them.
func readTwistcliImport(data []byte, _ plugin.FileTarget) (importRead, error) {
	// An object without results would decode to no images and read as a clean scan.
	if !bytes.HasPrefix(bytes.TrimSpace(data), []byte("{")) {
		return importRead{}, errNotTwistcliJSON
	}
	var file twistcliFile
	if err := json.Unmarshal(data, &file); err != nil || file.Results == nil {
		return importRead{}, errNotTwistcliJSON
	}
	rep := sarif.Report{Tool: twistcliTool, Rules: map[string]sarif.Rule{}}
	var rated []string
	for _, img := range *file.Results {
		ref := strings.TrimSpace(img.Name)
		if ref == "" {
			ref = strings.TrimSpace(img.ID)
		}
		if ref == "" {
			return importRead{}, twistcliIncomplete("an image", "id, the image it scanned")
		}
		seen := map[string]int{}
		for _, v := range img.Vulnerabilities {
			switch {
			case strings.TrimSpace(v.ID) == "":
				return importRead{}, twistcliIncomplete("a vulnerability in "+ref, "id, its CVE")
			case strings.TrimSpace(v.PackageName) == "":
				return importRead{}, twistcliIncomplete("vulnerability "+v.ID+" in "+ref, "packageName")
			}
			found, scored, err := twistcliResult(img, ref, v)
			if err != nil {
				return importRead{}, err
			}
			// A package listed twice with one vulnerability is one finding, rated by the worse copy.
			key := found.RuleID + "\x00" + found.Package.Name + "\x00" + found.Package.Version + "\x00" + v.PackagePath
			if at, dup := seen[key]; dup {
				if found.Severity("").Rank() > rep.Results[at].Severity("").Rank() {
					rep.Results[at], rated[at] = found, twistcliRated(scored)
				}
				continue
			}
			seen[key] = len(rep.Results)
			rep.Results = append(rep.Results, found)
			rated = append(rated, twistcliRated(scored))
			if _, ok := rep.Rules[found.RuleID]; !ok {
				rep.Rules[found.RuleID] = sarif.Rule{Name: found.RuleID, HelpURI: strings.TrimSpace(v.Link)}
			}
		}
	}

	var run importRun
	run.Tool.Driver = importDriver{Name: twistcliTool}
	run.Results = make([]json.RawMessage, len(rep.Results))
	return importRead{rep: rep, meta: importLog{Runs: []importRun{run}}, rated: rated, scored: "CVSS score"}, nil
}

// twistcliRated names the rating a finding's severity was read from, "" where it was its score.
func twistcliRated(scored bool) string {
	if scored {
		return ""
	}
	return "twistcli's severity"
}

// twistcliResult is the finding of the vulnerability v in the image img, whose reference is ref, and
// whether it is rated by its score.
func twistcliResult(img twistcliImage, ref string, v twistcliVulnerability) (sarif.Result, bool, error) {
	severity := strings.ToLower(strings.TrimSpace(v.Severity))
	band, known := twistcliSeverities[severity]
	if !known {
		return sarif.Result{}, false, fmt.Errorf("severity %q of %s in %s; twistcli rates a vulnerability "+
			"critical, high, medium or low. Import the file twistcli wrote, unedited", v.Severity, v.ID, v.PackageName)
	}
	score, hasScore, ok := twistcliScore(v.CVSS)
	if !ok {
		return sarif.Result{}, false, fmt.Errorf("cvss %s of %s in %s; twistcli writes a number from 0 to 10. "+
			"Import the file twistcli wrote, unedited", string(v.CVSS), v.ID, v.PackageName)
	}
	// A score that puts the vulnerability below twistcli's own severity is not taken, since a reading
	// of the same flaw as less severe is no reason to rank it lower.
	if hasScore && sarif.SeverityFromScore(score).Rank() < band.Rank() {
		hasScore = false
	}
	p := twistcliPackageFor(img, v)
	fixed, whole := twistcliFixedVersion(p, v.PackageVersion, v.Status)
	pkg := &sarif.Package{Name: p.name, Version: strings.TrimSpace(v.PackageVersion), FixedVersion: fixed,
		Ecosystem: p.ecosystem}

	var detail []string
	if d := strings.TrimSpace(v.Description); d != "" {
		detail = append(detail, d)
	}
	if p.binaries != "" {
		detail = append(detail, "Installed as "+p.binaries+".")
	}
	if path := strings.TrimSpace(v.PackagePath); path != "" {
		detail = append(detail, "Found at "+path+".")
	}
	if status := strings.Join(strings.Fields(v.Status), " "); !whole && status != "" {
		// A status this does not read whole stays in front of the reader, beside the version it read
		// or "no fix available".
		detail = append(detail, "twistcli's status: "+status+".")
	}
	r := sarif.Result{
		Tool:     twistcliTool,
		RuleID:   strings.TrimSpace(v.ID),
		Level:    osvLevel(band),
		Location: sarif.Location{URI: ref},
		Image:    ref,
		Package:  pkg,
		HasScore: hasScore,
		Message: trivyVulnMessage(trivyVuln{PkgName: pkg.Name, InstalledVersion: pkg.Version,
			FixedVersion: pkg.FixedVersion}),
		Detail: strings.Join(detail, " "),
		Rating: newRating(band, map[string]string{"severity": severity}, "twistcli "+severity),
	}
	if hasScore {
		r.Score = score
	}
	if p.os {
		r.OperatingSystem = strings.TrimSpace(img.Distro)
	}
	return r, hasScore, nil
}

// twistcliScore reads a CVSS score written as a number or a string, and whether there is one. A
// score that is absent, null or empty is none; ok is false for one that is not a number from 0 to 10.
func twistcliScore(raw json.RawMessage) (score float64, has, ok bool) {
	text := strings.TrimSpace(string(raw))
	if text == "" || text == "null" || text == `""` {
		return 0, false, true
	}
	if unquoted, err := strconv.Unquote(text); err == nil {
		text = strings.TrimSpace(unquoted)
	}
	score, err := strconv.ParseFloat(text, 64)
	if err != nil || score < 0 || score > 10 {
		return 0, false, false
	}
	return score, true, true
}

// twistcliPackageFor is the package the vulnerability v of img is in. It is the operating system's
// where twistcli says so, by naming the binaries built from it or by listing it as an os package, and
// then belongs to the distro's ecosystem; a package the list gives another type belongs to that
// type's ecosystem where Draugr knows it. Any other package is named as twistcli names it, with no
// ecosystem: twistcli lists some language packages, such as an older file's pycrypto, with no path and
// no type, so a package without a path is not known to be the operating system's.
func twistcliPackageFor(img twistcliImage, v twistcliVulnerability) twistcliPackageOf {
	name := strings.TrimSpace(v.PackageName)
	p := twistcliPackageOf{name: name}
	if source, rest, ok := strings.Cut(name, " (used in "); ok && strings.HasSuffix(rest, ")") {
		p.name, p.binaries, p.os = strings.TrimSpace(source), strings.TrimSuffix(rest, ")"), true
	}
	if !p.os && strings.TrimSpace(v.PackagePath) == "" {
		var types []string
		for _, listed := range img.Packages {
			if listed.Name == p.name && listed.Version == v.PackageVersion && !slices.Contains(types, listed.Type) {
				types = append(types, listed.Type)
			}
		}
		if len(types) == 1 {
			switch {
			case types[0] == "os":
				p.os = true
			case versionorder.PURLType(types[0]) != "":
				p.ecosystem = types[0]
				p.orderedAs = versionorder.Ecosystem("", types[0])
			}
		}
	}
	if p.os {
		distro := strings.ToLower(strings.TrimSpace(img.Distro))
		for _, d := range twistcliDistros {
			if strings.HasPrefix(distro, d.prefix) {
				p.ecosystem, p.orderedAs = d.ecosystem, versionorder.Ecosystem("", d.ecosystem)
				break
			}
		}
	}
	return p
}

// twistcliFixedVersion is the versions a fix status names, joined as Trivy joins several, and whether
// that is all the status says: false where the status is not "fixed in" and versions, or names no
// version above installed, so the whole status is kept for the reader. Where the package's ecosystem
// orders its versions, a version at or below the one installed is left out, since it fixes an older
// release line; where it does not, every version is kept, there being none to compare them with. A
// status of open, or none, is no fix, and needs no more said.
func twistcliFixedVersion(p twistcliPackageOf, installed, status string) (fixed string, whole bool) {
	text := strings.Join(strings.Fields(status), " ")
	if text == "" || strings.EqualFold(text, "open") {
		return "", true
	}
	listed, ok := strings.CutPrefix(text, "fixed in ")
	if !ok {
		return "", false
	}
	var have versionorder.Version
	ordered := false
	if p.orderedAs != "" {
		have, ordered = versionorder.Parse(p.orderedAs, installed)
	}
	var versions []string
	for _, v := range strings.Split(listed, ",") {
		v = strings.TrimSpace(v)
		if v == "" || slices.Contains(versions, v) {
			continue
		}
		if ordered {
			if parsed, ok := versionorder.Parse(p.orderedAs, v); ok {
				if order, ok := parsed.Compare(have); ok && order <= 0 {
					continue
				}
			}
		}
		versions = append(versions, v)
	}
	return strings.Join(versions, ", "), len(versions) > 0
}
