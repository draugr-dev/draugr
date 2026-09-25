package scanners

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// Trivy's SARIF says which vulnerability and where; its JSON also says which package.
//
// The package is in the SARIF too, as prose: the message reads "Package: flask\nFixed Version:
// 0.12.3". That is a fact formatted for a human and unavailable to anything else, and parsing it
// back out would be reading a sentence a tool is free to reword. The JSON has the same facts as
// fields, plus a purl, plus the manifest the package was declared in. So it is read instead, and
// the SARIF Draugr publishes is built here rather than by Trivy.
//
// One thing is lost in the swap and put back here: the line. Trivy's SARIF writer resolves a
// package to its line in the manifest; its JSON does not, so a dependency finding pointed at
// `app/requirements.txt` and no further, and a reader had to search the file for the name. The
// same index the license scanner already uses answers it. The manifest is on disk, and finding a
// package's own name in it is what both scanners need.
//
// Everything else the SARIF carried, rule documentation, the advisory link, the CVSS score behind
// `security-severity`. Is in the JSON under another name.

// trivyVulnDoc is the slice of Trivy's JSON this reads.
type trivyVulnDoc struct {
	Metadata struct {
		// OS is the distribution of the image's base layer. Absent for a filesystem scan, and for an
		// image Trivy could not identify, in which case no OS is claimed.
		OS struct {
			Family string `json:"Family"`
			Name   string `json:"Name"`
			// EOSL is Trivy's End Of Service Life: the vendor no longer ships security updates
			// for this release, so "no fix available" on it is permanent rather than pending.
			EOSL bool `json:"EOSL"`
		} `json:"OS"`
		// DiffIDs are the image's layers, bottom first. A finding names one of these.
		DiffIDs     []string `json:"DiffIDs"`
		ImageConfig struct {
			// History is how the image was built, one entry per instruction. Entries that
			// produced no filesystem change are marked empty and consume no DiffID, which is
			// what makes lining the two lists up require care rather than an index.
			History []struct {
				CreatedBy  string `json:"created_by"`
				EmptyLayer bool   `json:"empty_layer"`
			} `json:"history"`
		} `json:"ImageConfig"`
	} `json:"Metadata"`
	Results []trivyVulnResult `json:"Results"`
}

// operatingSystem is the OS as a consumer names it: "debian 11.11".
//
// Empty when Trivy identified no distribution, which is the honest answer for a scratch or
// distroless image. Nothing downstream may invent one: GitLab's schema requires the field with a
// minimum length, and a plausible-looking value there is a claim it will render and act on.
func (d trivyVulnDoc) operatingSystem() string {
	os := d.Metadata.OS
	if os.Family == "" {
		return ""
	}
	if os.Name == "" {
		return os.Family
	}
	return os.Family + " " + os.Name
}

type trivyVulnResult struct {
	// Target is the manifest or layer the packages were found in, "requirements.txt", "go.mod", an
	// image's OS package database. More precise than the SARIF location, which points at the scanned
	// root.
	Target string `json:"Target"`
	Type   string `json:"Type"`
	// Class separates the image's own package database from the language ecosystems installed
	// on top of it. Only the first has an operating system to name; a vulnerable npm package in
	// a Debian image is not a Debian finding.
	Class           string      `json:"Class"`
	Vulnerabilities []trivyVuln `json:"Vulnerabilities"`
	// Packages is every package Trivy read from Target, present when it is run with
	// --list-all-pkgs. Each carries the lines of its own entry in the manifest, which the
	// vulnerabilities do not.
	Packages []trivyPackage `json:"Packages"`
	// ModifiedFindings is what Trivy set aside, present when it was asked to say so. Trivy calls
	// the field experimental, so it is read for what it holds and its absence is not an error: a
	// Trivy that stops sending it, or one too old to send it, leaves the report as it was.
	ModifiedFindings []trivyModified `json:"ExperimentalModifiedFindings"`
}

// trivyModified is one finding Trivy excluded, and who told it to.
type trivyModified struct {
	// Type is what kind of finding was set aside. Only vulnerabilities are read here, because that
	// is what this parser builds.
	Type string `json:"Type"`
	// Status is what Trivy did. `ignored` is an exclusion; anything else is a severity or a status
	// Trivy rewrote, which is not a decision anybody made and is not a suppression.
	Status string `json:"Status"`
	// Statement is the reason, where the exclusion carried one. `.trivyignore` has nowhere to put
	// one, so it is usually empty.
	Statement string `json:"Statement"`
	// Source is the file the rule was written in, which is what a reader needs in order to go and
	// read it.
	Source  string    `json:"Source"`
	Finding trivyVuln `json:"Finding"`
}

// trivyPackage is a package Trivy read, and where in the manifest it read it.
type trivyPackage struct {
	Identifier struct {
		UID string `json:"UID"`
	} `json:"Identifier"`
	Locations []struct {
		StartLine int `json:"StartLine"`
	} `json:"Locations"`
}

// packageLines maps each package's UID to the first line of its entry, for the packages whose
// parser records one.
func (r trivyVulnResult) packageLines() map[string]int {
	out := map[string]int{}
	for _, p := range r.Packages {
		if p.Identifier.UID != "" && len(p.Locations) > 0 && p.Locations[0].StartLine > 0 {
			out[p.Identifier.UID] = p.Locations[0].StartLine
		}
	}
	return out
}

type trivyVuln struct {
	VulnerabilityID  string `json:"VulnerabilityID"`
	PkgName          string `json:"PkgName"`
	InstalledVersion string `json:"InstalledVersion"`
	FixedVersion     string `json:"FixedVersion"`
	Status           string `json:"Status"`
	PkgIdentifier    struct {
		PURL string `json:"PURL"`
		// UID is the package this finding is about, matching a trivyPackage's.
		UID string `json:"UID"`
	} `json:"PkgIdentifier"`
	// Layer is where this package entered the image. Trivy reports it per finding, which is the
	// only reliable way to tell an inherited package from one this component installed.
	Layer struct {
		DiffID string `json:"DiffID"`
	} `json:"Layer"`
	Severity    string `json:"Severity"`
	Title       string `json:"Title"`
	Description string `json:"Description"`
	PrimaryURL  string `json:"PrimaryURL"`
	CVSS        map[string]struct {
		V3Score float64 `json:"V3Score"`
		V40     float64 `json:"V40Score"`
	} `json:"CVSS"`
}

// layers pairs each DiffID with its position and the build step that produced it.
//
// History and DiffIDs are two lists that describe the same image and do not line up: an
// instruction that changes no files (ENV, WORKDIR, CMD) is recorded in history and produces no
// layer. Walking history and consuming a DiffID only for the entries that made one is what keeps
// an instruction from being attributed to the wrong layer, and a misattributed build step is worse
// than none, because it names a line to change that did not introduce the finding.
func (d trivyVulnDoc) layers() map[string]sarif.Layer {
	out := make(map[string]sarif.Layer, len(d.Metadata.DiffIDs))
	next := 0
	for _, h := range d.Metadata.ImageConfig.History {
		if h.EmptyLayer {
			continue
		}
		if next >= len(d.Metadata.DiffIDs) {
			break
		}
		out[d.Metadata.DiffIDs[next]] = sarif.Layer{
			DiffID:    d.Metadata.DiffIDs[next],
			Index:     next,
			Of:        len(d.Metadata.DiffIDs),
			CreatedBy: strings.TrimSpace(h.CreatedBy),
		}
		next++
	}
	// An image whose history is missing or shorter than its layer list still has layers, and the
	// position alone is worth reporting: it is what says whether a finding is near the bottom.
	for i, id := range d.Metadata.DiffIDs {
		if _, ok := out[id]; !ok {
			out[id] = sarif.Layer{DiffID: id, Index: i, Of: len(d.Metadata.DiffIDs)}
		}
	}
	return out
}

// trivyClassOSPkgs is Trivy's name for a result set drawn from the image's own package database.
const trivyClassOSPkgs = "os-pkgs"

// trivyClassLangPkgs is Trivy's name for a result set read from one language ecosystem's file.
const trivyClassLangPkgs = "lang-pkgs"

// trivyListOnly are the ecosystems Trivy lists packages for without looking them up in its
// advisory data, which it says in a warning and nowhere in its JSON. A file of one is not read for
// vulnerabilities, so it is left out of what the scan names as read and the tree walk reports it.
var trivyListOnly = []string{"conda-environment", "conda-pkg"}

// trivyInput is the dependency file a result set was read from, or false for a set that is not one.
//
// Trivy leaves out a file it read no packages from, so the files named here are the ones that
// contributed, and a file in the tree missing from them contributed nothing. The count is what
// --list-all-pkgs lists, which the license scan reports without being asked.
//
// Only over a checkout: an image has no tree to account against, and the files in it are the
// image's rather than a repository's.
func trivyInput(dir, class, target string, packages int) (sarif.Input, bool) {
	if dir == "" || class != trivyClassLangPkgs || target == "" {
		return sarif.Input{}, false
	}
	return sarif.Input{Path: repoRelPath(dir, target), Packages: packages}, true
}

// parseTrivyVulns turns Trivy's JSON into the report Draugr publishes.
func parseTrivyVulns(out []byte, dir string, _ plugin.Config) (sarif.Report, error) {
	var doc trivyVulnDoc
	if err := json.Unmarshal(out, &doc); err != nil {
		return sarif.Report{}, fmt.Errorf("parse trivy JSON: %w", err)
	}
	rep := sarif.Report{Tool: "trivy", Rules: map[string]sarif.Rule{}}
	layers := doc.layers()
	// The line of the package's own entry, from Trivy's parser where it records one. Otherwise the
	// manifest is on disk, this being a filesystem scan, and the entry is looked for there. Zero
	// where neither answers, which is honest: the finding still points at the file.
	lines := newLineIndex(dir)
	lineOf := func(res trivyVulnResult, known map[string]int, v trivyVuln) int {
		if n := known[v.PkgIdentifier.UID]; n > 0 {
			return n
		}
		return lines.find(res.Target, v.PkgName, v.InstalledVersion)
	}
	for _, res := range doc.Results {
		if in, ok := trivyInput(dir, res.Class, res.Target, len(res.Packages)); ok && !slices.Contains(trivyListOnly, res.Type) {
			rep.Inputs = append(rep.Inputs, in)
		}
		known := res.packageLines()
		for _, v := range res.Vulnerabilities {
			found := trivyVulnResultOf(doc, res, v, layers)
			found.Location.StartLine = lineOf(res, known, v)
			rep.Results = append(rep.Results, found)
			if _, seen := rep.Rules[v.VulnerabilityID]; !seen {
				rep.Rules[v.VulnerabilityID] = trivyVulnRule(v)
			}
		}
		// And what Trivy excluded, as findings marked with the decision rather than as absences.
		for _, m := range res.ModifiedFindings {
			found, ok := trivySuppressedResultOf(doc, res, m, layers)
			if !ok {
				continue
			}
			found.Location.StartLine = lineOf(res, known, m.Finding)
			rep.Results = append(rep.Results, found)
			if _, seen := rep.Rules[m.Finding.VulnerabilityID]; !seen {
				rep.Rules[m.Finding.VulnerabilityID] = trivyVulnRule(m.Finding)
			}
		}
	}
	return rep, nil
}

// trivySuppressedResultOf builds a finding Trivy set aside, carrying who set it aside.
//
// Only an exclusion, and only of a vulnerability: Trivy reports a rewritten severity in the same
// place, and a severity somebody changed is not a decision to live with the finding. Anything this
// does not recognize is left out rather than guessed at, which keeps a shape Trivy adds later from
// arriving in the report as an acceptance nobody made.
func trivySuppressedResultOf(
	doc trivyVulnDoc, res trivyVulnResult, m trivyModified, layers map[string]sarif.Layer,
) (sarif.Result, bool) {
	if m.Status != "ignored" || (m.Type != "" && m.Type != "vulnerability") {
		return sarif.Result{}, false
	}
	if m.Finding.VulnerabilityID == "" {
		return sarif.Result{}, false
	}
	found := trivyVulnResultOf(doc, res, m.Finding, layers)
	found.Suppression = &sarif.Suppression{
		// External, because it is: the rule is outside the file the scanner read. The origin is
		// what says whose external, and Draugr's own are told apart by the record they carry.
		Kind:          "external",
		Origin:        sarif.OriginScanner,
		Justification: m.Statement,
		Source:        m.Source,
	}
	return found, true
}

// trivyVulnResultOf builds one finding.
//
// The operating system comes from the document, because Trivy is the only party that knows it.
// The image does not: it is the target's own identity, and is set alongside the location by the
// scanner that knows which image it asked for. One fact, one source.
func trivyVulnResultOf(
	doc trivyVulnDoc, res trivyVulnResult, v trivyVuln, layers map[string]sarif.Layer,
) sarif.Result {
	score, hasScore := trivyVulnScore(v)
	// Only the image's own package database has an operating system to name. A language package
	// installed on top of it belongs to its ecosystem, not to the distribution underneath.
	var operatingSystem string
	endOfLife := false
	if res.Class == trivyClassOSPkgs {
		operatingSystem = doc.operatingSystem()
		// Only claimed alongside the OS it describes. A language package sitting on the image is not
		// made end-of-life by the distribution underneath it, and its fix. If there is one. Comes from
		// its own ecosystem.
		endOfLife = operatingSystem != "" && doc.Metadata.OS.EOSL
	}
	var layer *sarif.Layer
	if l, ok := layers[v.Layer.DiffID]; ok {
		layer = &l
	}
	return sarif.Result{
		OperatingSystem: operatingSystem,
		OSEndOfLife:     endOfLife,
		Layer:           layer,
		Tool:            "trivy",
		RuleID:          v.VulnerabilityID,
		Level:           trivyVulnLevel(v.Severity),
		Message:         trivyVulnMessage(v),
		Location:        sarif.Location{URI: res.Target},
		Score:           score,
		HasScore:        hasScore,
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
// It says what to do rather than restating the identifier: the version to move to is the action,
// and its absence is the more alarming answer. "no fix available" is a decision to make, where a
// version number is a change to schedule.
//
// The action goes first, before the advisory's own words. A line has to fit a column and the
// advisory decides how long its half is, so anything after it is the part that gets cut, and what
// was being cut was the only actionable thing on the line.
func trivyVulnMessage(v trivyVuln) string {
	subject := v.PkgName
	if v.InstalledVersion != "" {
		subject += " " + v.InstalledVersion
	}
	if v.FixedVersion != "" {
		subject += " → " + v.FixedVersion
	} else {
		subject += ", no fix available"
	}
	if title := trimPackagePrefix(v.Title, v.PkgName); title != "" {
		return subject + ": " + title
	}
	return subject
}

// trimPackagePrefix drops a leading "<name>: " from the advisory's own title when the name is
// another spelling of the package the sentence already names.
//
// Advisory titles are written to stand alone, so most of them open with the package. Draugr opens
// with it too, because a title alone does not say which of your dependencies it is about. Together
// they read "Flask 0.12.2: python-flask: Denial of Service", where a third of the line is the same
// word twice and the part a reader acts on is pushed toward the edge.
//
// Repeatedly, because the feeds do it to each other: a title arrives as "requests: Requests:
// Security bypass", one prefix from the ecosystem's advisory and one from the distribution's copy
// of it.
func trimPackagePrefix(title, pkg string) string {
	for {
		head, rest, ok := strings.Cut(title, ": ")
		if !ok || rest == "" {
			return title
		}
		// The same label twice, whatever it is. A distribution's advisory repeats the upstream
		// project's own prefix ("gnutls: gnutls: …", "openssl: OpenSSL: …"), and dropping the
		// repeat loses nothing whether or not it is the package Draugr knows this finding by.
		if next, _, again := strings.Cut(rest, ": "); again && sameName(head, next) {
			title = rest
			continue
		}
		if !sameName(head, pkg) {
			return title
		}
		title = rest
	}
}

// sameName reports whether two spellings name one package.
//
// A distribution renames what it packages, so the advisory says "python-flask" where the lockfile
// says "Flask", and an ecosystem that allows both separators produces "ruamel.yaml" and
// "ruamel-yaml" for one library. Case, separator and the packaging prefix are the three
// differences that carry no information; anything else is a different package and the title stays
// whole.
func sameName(a, b string) bool {
	norm := func(s string) string {
		s = strings.ReplaceAll(strings.ReplaceAll(strings.ToLower(s), "_", "-"), ".", "-")
		for _, prefix := range []string{"python3-", "python-", "golang-", "rubygem-", "node-", "perl-", "php-", "py-"} {
			if rest := strings.TrimPrefix(s, prefix); rest != s {
				return rest
			}
		}
		return s
	}
	return a != "" && norm(a) == norm(b)
}

// trivyVulnLevel maps Trivy's severity onto SARIF's three.
//
// Severity itself is recovered from the score below, which is finer than this, the level exists
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
// Trivy reports a score per source, nvd, ghsa, redhat, and its own SARIF picks one. The highest is
// taken here for the same reason severity is never rounded down: a vendor scoring a flaw lower
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

// parseTrivyImage adapts parseTrivyVulns to the tool adapter's signature.
//
// The target is unused: everything this reads is in Trivy's output, and the one fact that comes
// from the target. The image reference. Is applied by imageRefLocations alongside the location, so
// the two can never disagree.
func parseTrivyImage(out []byte, _ plugin.Target, cfg plugin.Config) (sarif.Report, error) {
	return parseTrivyVulns(out, "", cfg)
}
