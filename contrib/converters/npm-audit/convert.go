package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/draugr-dev/draugr/pkg/converter"
)

// name is the converter's name, which the importing descriptor declares as converter.name.
const name = "npm-audit"

// version is the converter's own version, written into every file.
const version = "1.0.0"

// sets are the properties of Draugr's this converter sets, which the descriptor's converter.sets has
// to list: each finding's package, and the CWE ids npm's advisory names.
var sets = []converter.Property{converter.PropertyPackage, converter.PropertyCWE}

// options are what a run is told beside the two files.
type options struct {
	// auditPath and lockPath are the files as the CI step named them. The lockfile's is where every
	// finding is located, so it is written relative to the repository's root.
	auditPath, lockPath string
	// commit is the commit npm audit ran on, and repository the repository, where it is given.
	commit, repository string
	// written is when the file is written, RFC 3339 in UTC.
	written string
}

// audit is the part of `npm audit --json` (auditReportVersion 2) the converter reads.
type audit struct {
	AuditReportVersion int                      `json:"auditReportVersion"`
	Vulnerabilities    map[string]vulnerability `json:"vulnerabilities"`
}

// vulnerability is one vulnerable package of an audit.
type vulnerability struct {
	Name string `json:"name"`
	// Via lists the advisories against the package itself, as objects, and the vulnerable packages it
	// depends on, as their names. Only the objects are this package's own flaws.
	Via          []json.RawMessage `json:"via"`
	Nodes        []string          `json:"nodes"`
	FixAvailable json.RawMessage   `json:"fixAvailable"`
}

// advisory is one entry of a vulnerability's via that is an advisory rather than a package name.
type advisory struct {
	Source     int      `json:"source"`
	Dependency string   `json:"dependency"`
	Title      string   `json:"title"`
	URL        string   `json:"url"`
	Severity   string   `json:"severity"`
	CWE        []string `json:"cwe"`
	CVSS       struct {
		Score float64 `json:"score"`
	} `json:"cvss"`
}

// fix is fixAvailable where npm states the upgrade, rather than true or false.
type fix struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// lockfile is the part of package-lock.json the converter reads: the version installed at each path.
type lockfile struct {
	Packages map[string]struct {
		Version string `json:"version"`
	} `json:"packages"`
}

// cweID is a CWE id as the contract takes one.
var cweID = regexp.MustCompile(`^CWE-[1-9][0-9]{0,5}$`)

// convert turns an audit and the lockfile it read into a converter file.
func convert(auditData, lockData []byte, o options) (converter.Document, error) {
	var a audit
	if err := json.Unmarshal(auditData, &a); err != nil || a.Vulnerabilities == nil {
		return converter.Document{}, errors.New("not npm audit JSON. Write it with npm audit --json")
	}
	if a.AuditReportVersion != 2 {
		return converter.Document{}, fmt.Errorf("auditReportVersion %d; this converter reads 2", a.AuditReportVersion)
	}
	var lock lockfile
	if len(lockData) > 0 {
		if err := json.Unmarshal(lockData, &lock); err != nil {
			return converter.Document{}, fmt.Errorf("%s is not a package-lock.json, %w", o.lockPath, err)
		}
	}
	sum := sha256.Sum256(auditData)
	doc := converter.Document{
		Contract:   converter.ID,
		Version:    converter.Version,
		Converter:  converter.Converter{Name: name, Version: version},
		Source:     converter.Source{Tool: "npm audit", File: o.auditPath, SHA256: hex.EncodeToString(sum[:])},
		Commit:     o.commit,
		Repository: o.repository,
		Written:    o.written,
		Results:    []converter.Result{},
	}
	names := make([]string, 0, len(a.Vulnerabilities))
	for n := range a.Vulnerabilities {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		v := a.Vulnerabilities[n]
		pkg := packageOf(v, lock)
		for _, adv := range advisories(v) {
			doc.Results = append(doc.Results, resultOf(adv, pkg, o.lockPath))
		}
	}
	return doc, nil
}

// advisories are a vulnerability's own advisories, in the order npm lists them, each once.
func advisories(v vulnerability) []advisory {
	var out []advisory
	seen := map[int]bool{}
	for _, raw := range v.Via {
		var adv advisory
		// A package name, a string, says the flaw is in a dependency, which has its own entry.
		if json.Unmarshal(raw, &adv) != nil || adv.Title == "" || seen[adv.Source] {
			continue
		}
		if adv.Dependency != "" && adv.Dependency != v.Name {
			continue
		}
		seen[adv.Source] = true
		out = append(out, adv)
	}
	return out
}

// packageOf is the package a vulnerability is about: its version from the lockfile's entry for the
// first path npm names, and the version that fixes it where npm's fix is an upgrade of this package.
func packageOf(v vulnerability, lock lockfile) *converter.Package {
	p := &converter.Package{Name: v.Name, Ecosystem: "npm"}
	if len(v.Nodes) > 0 {
		p.Version = lock.Packages[v.Nodes[0]].Version
	}
	var f fix
	if json.Unmarshal(v.FixAvailable, &f) == nil && f.Name == v.Name {
		p.FixedVersion = f.Version
	}
	p.PURL = purl(v.Name, p.Version)
	return p
}

// purl is an npm package's package URL, its scope's @ escaped as the purl specification asks.
func purl(pkg, ver string) string {
	escaped := strings.Replace(pkg, "@", "%40", 1)
	if ver == "" {
		return "pkg:npm/" + escaped
	}
	return "pkg:npm/" + escaped + "@" + url.PathEscape(ver)
}

// resultOf is one advisory against one package as a contract result, located at the lockfile.
func resultOf(adv advisory, pkg *converter.Package, lockPath string) converter.Result {
	r := converter.Result{
		RuleID:   ruleID(adv),
		Message:  adv.Title,
		Severity: severity(adv.Severity),
		Location: &converter.Location{Path: lockPath},
		Package:  pkg,
	}
	if adv.CVSS.Score > 0 {
		score := adv.CVSS.Score
		r.Score = &score
	}
	for _, c := range adv.CWE {
		if cweID.MatchString(c) && !slices.Contains(r.CWE, c) {
			r.CWE = append(r.CWE, c)
		}
	}
	return r
}

// ruleID is the advisory's GitHub advisory id, which npm's url ends in, so the finding correlates
// with another scanner's copy of the same advisory, or npm's own number where the url names none.
func ruleID(adv advisory) string {
	if id := path.Base(adv.URL); strings.HasPrefix(id, "GHSA-") {
		return id
	}
	return "npm-advisory-" + strconv.Itoa(adv.Source)
}

// severity is npm's rating in Draugr's words: moderate is medium, and info is low.
func severity(s string) string {
	switch strings.ToLower(s) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "moderate", "medium":
		return "medium"
	}
	return "low"
}
