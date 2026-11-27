package scanners

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/draugr-dev/draugr/internal/versionorder"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// mendTool is the name a finding read from Mend's file is reported under.
const mendTool = "Mend"

// errNotMendDependencyJSON is the error of a file that is not the JSON Mend's CLI writes of a
// dependency scan.
var errNotMendDependencyJSON = errors.New("not Mend's dependency JSON. Write it with " +
	"mend dep --format json --export-results <file>")

// mendIncomplete is the error of a library or vulnerability missing what the format needs to place
// and name it: what names it, and the key it lacks.
func mendIncomplete(what, key string) error {
	return fmt.Errorf("%s has no %s, which mend dep writes for every one. Import the file mend dep wrote, "+
		"unedited", what, key)
}

// mendLibrary is one library of the list `mend dep --format json` writes, with the libraries it
// brings in as its children. Mend publishes no schema for the file; the fields are those its output
// holds.
type mendLibrary struct {
	// Name is the library's file name, jackson-databind-2.9.5.jar, the only place its version is.
	Name string `json:"name"`
	// DependencyFile is the manifest that declares it, or the direct dependency that brings it in, as
	// a path on the machine that ran the scan.
	DependencyFile  string              `json:"dependencyFile"`
	Vulnerabilities []mendVulnerability `json:"vulnerabilities"`
	Children        []mendLibrary       `json:"children"`
}

// mendVulnerability is one vulnerability of a library. Name is its CVE, or Mend's own WS- id for one
// with none.
type mendVulnerability struct {
	Name        string `json:"name"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	URL         string `json:"url"`
	TopFix      *struct {
		// FixResolution is the fix in the words of Mend's researchers: "Upgrade to version 2.9.8", or
		// several versions and packages.
		FixResolution string `json:"fixResolution"`
	} `json:"topFix"`
}

// mendSeverities are the bands of the severities Mend gives a vulnerability.
var mendSeverities = map[string]sarif.Severity{
	"CRITICAL": sarif.SeverityCritical,
	"HIGH":     sarif.SeverityHigh,
	"MEDIUM":   sarif.SeverityMedium,
	"LOW":      sarif.SeverityLow,
}

// mendArchives are the extensions Mend's library names carry, stripped before the name is split into
// the package and its version, with the ecosystem a library of each belongs to.
var mendArchives = []struct{ ext, ecosystem, orderedAs string }{
	{".jar", "maven", "Maven"},
}

// mendPackage is what a library's file name and its fixes say about its package.
type mendPackage struct {
	// file is the library's file name as Mend writes it.
	file string
	// artifact and version are the file name split; artifact is the whole file name, and version empty,
	// where the name does not split.
	artifact, version string
	// group is the Maven group the library's fixes name, "" where they name none or more than one.
	group string
	// ecosystem is the ecosystem the file's extension names, and orderedAs the rules its versions are
	// ordered by, both "" for an extension not in mendArchives.
	ecosystem, orderedAs string
}

// name is the package's name as a finding carries it: group:artifact where the group is known, as
// Draugr's Maven scanners name it.
func (p mendPackage) name() string {
	if p.group != "" {
		return p.group + ":" + p.artifact
	}
	return p.artifact
}

// mendEntry is one library in one manifest, read once however often the tree repeats it.
type mendEntry struct {
	lib mendLibrary
	// vulns are its vulnerabilities, each once, across every place the tree lists it.
	vulns []mendVulnerability
	// direct is whether the tree lists it as a direct dependency, and roots the direct dependencies it
	// is listed under otherwise, by their key.
	direct bool
	roots  []string
}

// readMendDependencyImport reads the vulnerable libraries in the JSON `mend dep --format json
// --export-results <file>` writes.
//
// A finding is a vulnerability of a library at the version installed, in the manifest that declares
// it or the direct dependency that brings it in, under its CVE where it has one, so the
// known-exploited and EPSS feeds reach it, else Mend's own WS- id. Mend lists a library wherever the
// dependency tree holds it, and each vulnerability of it in one manifest is one finding. The package
// and version are read from the library's file name, its Maven group from its fixes, and the fixed
// version from the fix where it names this package, rated by the severity Mend states.
func readMendDependencyImport(data []byte, ft plugin.FileTarget) (importRead, error) {
	// The file is a list of libraries; anything else would decode to none and read as a clean scan.
	if !bytes.HasPrefix(bytes.TrimSpace(data), []byte("[")) {
		return importRead{}, errNotMendDependencyJSON
	}
	var libs []mendLibrary
	if err := json.Unmarshal(data, &libs); err != nil {
		return importRead{}, errNotMendDependencyJSON
	}

	var order []string
	entries := map[string]*mendEntry{}
	var walk func(libs []mendLibrary, root string) error
	walk = func(libs []mendLibrary, root string) error {
		for _, lib := range libs {
			switch {
			case strings.TrimSpace(lib.Name) == "":
				return mendIncomplete("a library", `name, the file name that gives its package and version`)
			case strings.TrimSpace(lib.DependencyFile) == "":
				return mendIncomplete("library "+lib.Name, "dependencyFile, the manifest that declares it")
			}
			key := lib.Name + "\x00" + lib.DependencyFile
			e, seen := entries[key]
			if !seen {
				e = &mendEntry{lib: lib}
				entries[key] = e
				order = append(order, key)
			}
			for _, v := range lib.Vulnerabilities {
				if strings.TrimSpace(v.Name) == "" {
					return mendIncomplete("a vulnerability of "+lib.Name, "name, its CVE or Mend's id")
				}
				if !slices.ContainsFunc(e.vulns, func(w mendVulnerability) bool { return w.Name == v.Name }) {
					e.vulns = append(e.vulns, v)
				}
			}
			next := root
			if root == "" {
				e.direct, next = true, key
			} else if !slices.Contains(e.roots, root) && root != key {
				e.roots = append(e.roots, root)
			}
			if err := walk(lib.Children, next); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(libs, ""); err != nil {
		return importRead{}, err
	}

	pkgs := make(map[string]mendPackage, len(entries))
	for key, e := range entries {
		pkgs[key] = mendPackageOf(e.lib.Name, e.vulns)
	}
	rep := sarif.Report{Tool: mendTool, Rules: map[string]sarif.Rule{}}
	var rated []string
	for _, key := range order {
		e := entries[key]
		var via []string
		for _, r := range e.roots {
			via = append(via, strings.TrimSpace(pkgs[r].name()+" "+pkgs[r].version))
		}
		for _, v := range e.vulns {
			found, err := mendResult(pkgs[key], e, v, via)
			if err != nil {
				return importRead{}, err
			}
			rep.Results = append(rep.Results, found)
			rated = append(rated, "Mend's severity")
			if _, ok := rep.Rules[found.RuleID]; !ok {
				rep.Rules[found.RuleID] = sarif.Rule{Name: found.RuleID,
					ShortDescription: strings.TrimSpace(v.Description), HelpURI: strings.TrimSpace(v.URL)}
			}
		}
	}
	outside := relativeToCheckouts(rep.Results, checkoutRoots(ft.Repositories))

	var run importRun
	run.Tool.Driver = importDriver{Name: mendTool}
	run.Results = make([]json.RawMessage, len(rep.Results))
	return importRead{rep: rep, outside: outside, meta: importLog{Runs: []importRun{run}}, rated: rated}, nil
}

// mendResult is the finding of one vulnerability of the library e, whose package is p, brought in by
// the direct dependencies via.
func mendResult(p mendPackage, e *mendEntry, v mendVulnerability, via []string) (sarif.Result, error) {
	band, known := mendSeverities[v.Severity]
	if !known {
		return sarif.Result{}, fmt.Errorf("severity %q of %s in %s; Mend rates a vulnerability CRITICAL, HIGH, "+
			"MEDIUM or LOW. Import the file mend dep wrote, unedited", v.Severity, v.Name, e.lib.Name)
	}
	var text string
	if v.TopFix != nil {
		text = strings.Join(strings.Fields(v.TopFix.FixResolution), " ")
	}
	fixed, whole := mendFixedVersion(p, text)
	pkg := &sarif.Package{Name: p.name(), Version: p.version, FixedVersion: fixed, Ecosystem: p.ecosystem}
	if p.group != "" && p.version != "" {
		pkg.PURL = "pkg:maven/" + p.group + "/" + p.artifact + "@" + p.version
	}

	var detail []string
	if d := strings.TrimSpace(v.Description); d != "" {
		detail = append(detail, d)
	}
	if p.version == "" {
		detail = append(detail, "Mend names the library by its file, "+p.file+", which states no version.")
	}
	if !whole && text != "" {
		// A fix this does not read whole stays in front of the reader, beside the version it read or
		// "no fix available".
		detail = append(detail, "Mend's fix: "+text+".")
	}
	switch {
	case len(via) > 0 && e.direct:
		detail = append(detail, "Declared directly and brought in by "+strings.Join(via, ", ")+".")
	case len(via) > 0:
		detail = append(detail, "Brought in by "+strings.Join(via, ", ")+".")
	}
	return sarif.Result{
		Tool:     mendTool,
		RuleID:   v.Name,
		Level:    osvLevel(band),
		Location: sarif.Location{URI: e.lib.DependencyFile},
		Package:  pkg,
		Message: trivyVulnMessage(trivyVuln{PkgName: pkg.Name, InstalledVersion: pkg.Version,
			FixedVersion: pkg.FixedVersion}),
		Detail: strings.Join(detail, " "),
		Rating: newRating(band, map[string]string{"severity": v.Severity}, "Mend "+v.Severity),
	}, nil
}

// mendPackageOf is the package of the library named file, whose vulnerabilities are vulns.
func mendPackageOf(file string, vulns []mendVulnerability) mendPackage {
	p := mendPackage{file: file, artifact: file}
	base := file
	for _, a := range mendArchives {
		if trimmed, ok := strings.CutSuffix(base, a.ext); ok {
			base, p.ecosystem, p.orderedAs = trimmed, a.ecosystem, a.orderedAs
			break
		}
	}
	if artifact, version, ok := mendSplitName(base); ok {
		p.artifact, p.version = artifact, version
	}
	// The group is taken only where the fixes agree on one for this artifact, since a guess would
	// name another package.
	var groups []string
	for _, v := range vulns {
		if v.TopFix == nil {
			continue
		}
		for _, f := range mendFixes(v.TopFix.FixResolution) {
			if f.artifact == p.artifact && f.group != "" && !slices.Contains(groups, f.group) {
				groups = append(groups, f.group)
			}
		}
	}
	if len(groups) == 1 {
		p.group = groups[0]
	}
	return p
}

// mendNameVersion finds where a version starts in a name: the first hyphen followed by a digit.
var mendNameVersion = regexp.MustCompile(`-\d`)

// mendSplitName splits "jackson-databind-2.9.5" at the first hyphen followed by a digit into the
// artifact and its version, and is false for a name that does not split so.
func mendSplitName(s string) (artifact, version string, ok bool) {
	loc := mendNameVersion.FindStringIndex(s)
	if loc == nil || loc[0] == 0 || strings.ContainsAny(s, " :") {
		return "", "", false
	}
	return s[:loc[0]], s[loc[0]+1:], true
}

// mendBareVersion is a version written alone, such as 2.9.8, 2.11.0.rc1 or 11.0.0-M3.
var mendBareVersion = regexp.MustCompile(`^v?\d[0-9A-Za-z.+_-]*$`)

// mendFix is one version a fix names, and the package it is for. group and artifact are both empty
// for a version written before any package is named. read is false for a part of the fix this does
// not read.
type mendFix struct {
	group, artifact, version string
	read                     bool
}

// mendFixes reads the versions a fix names. Mend's fixes are free text: "Upgrade to version " and then
// parts split by ";" or ",", each a version alone, which continues the package named before it,
// group:artifact:version or group:artifact - version, which names a package, or artifact-version.
// A part in another form is not read, and nor is a version alone after it, whose package is unknown.
func mendFixes(resolution string) []mendFix {
	text := strings.TrimSpace(resolution)
	text = strings.TrimSpace(strings.TrimPrefix(text, "Upgrade to version"))
	var out []mendFix
	var group, artifact string
	lost := false
	for _, part := range strings.FieldsFunc(text, func(r rune) bool { return r == ';' || r == ',' }) {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		var f mendFix
		if g, a, v, ok := mendCoordinate(part); ok {
			group, artifact, lost = g, a, false
			f = mendFix{group: g, artifact: a, version: v, read: true}
		} else if mendBareVersion.MatchString(part) {
			f = mendFix{group: group, artifact: artifact, version: part, read: !lost}
		} else if a, v, ok := mendSplitName(part); ok {
			group, artifact, lost = "", a, false
			f = mendFix{artifact: a, version: v, read: true}
		} else {
			lost = true
		}
		out = append(out, f)
	}
	return out
}

// mendCoordinate reads a part of a fix that names a package: group:artifact:version,
// group:artifact - version, or group:artifact-version.
func mendCoordinate(part string) (group, artifact, version string, ok bool) {
	if left, right, dashed := strings.Cut(part, " - "); dashed {
		g, a, found := strings.Cut(strings.TrimSpace(left), ":")
		v := strings.TrimSpace(right)
		if !found || g == "" || a == "" || strings.ContainsAny(g+a, ": ") || !mendBareVersion.MatchString(v) {
			return "", "", "", false
		}
		return g, a, v, true
	}
	fields := strings.Split(part, ":")
	for i := range fields {
		fields[i] = strings.TrimSpace(fields[i])
		if fields[i] == "" || strings.Contains(fields[i], " ") {
			return "", "", "", false
		}
	}
	switch len(fields) {
	case 3:
		if mendBareVersion.MatchString(fields[2]) {
			return fields[0], fields[1], fields[2], true
		}
	case 2:
		if a, v, split := mendSplitName(fields[1]); split {
			return fields[0], a, v, true
		}
	}
	return "", "", "", false
}

// mendFixedVersion is the versions text names as fixes of p above the version installed, joined as
// Trivy joins several, and whether that is all text says: false where it names another package, or a
// part this does not read, or no version above the installed one, so the whole text is kept for the
// reader.
func mendFixedVersion(p mendPackage, text string) (fixed string, whole bool) {
	var installed versionorder.Version
	ordered := false
	if p.version != "" {
		installed, ordered = versionorder.Parse(p.orderedAs, p.version)
	}
	whole = true
	var versions []string
	for _, f := range mendFixes(text) {
		if !f.read || (f.artifact != "" && f.artifact != p.artifact) {
			whole = false
			continue
		}
		v := strings.TrimPrefix(f.version, "v")
		if ordered {
			// A version at or below the one installed fixes an older release line, not this one.
			if parsed, ok := versionorder.Parse(p.orderedAs, v); ok {
				if order, ok := parsed.Compare(installed); ok && order <= 0 {
					continue
				}
			}
		}
		if !slices.Contains(versions, v) {
			versions = append(versions, v)
		}
	}
	if len(versions) == 0 {
		whole = false
	}
	return strings.Join(versions, ", "), whole
}
