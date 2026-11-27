package scanners

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/draugr-dev/draugr/internal/versionorder"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// errNotSemgrepJSON is the error of a file that is not the JSON Semgrep writes of a scan.
var errNotSemgrepJSON = errors.New("not Semgrep's JSON. Write it with semgrep ci --json-output=<file>")

// semgrepIncomplete is the error of a result missing what the format needs to place and name it: what
// names it, and the key it lacks.
func semgrepIncomplete(what, key string) error {
	return fmt.Errorf("%s has no %s, which Semgrep writes for every one. Import the file Semgrep wrote, "+
		"unedited", what, key)
}

// semgrepImportDoc is the part of the JSON `semgrep ci --json-output` and `semgrep scan --json-output`
// write that the import reads, as cli_output in Semgrep's semgrep_output_v1.atd
// (github.com/semgrep/semgrep-interfaces) defines it.
type semgrepImportDoc struct {
	Version string                `json:"version"`
	Results []semgrepImportResult `json:"results"`
	Engine  string                `json:"engine_requested"`
	semgrepCoverage
}

// semgrepImportResult is one result, cli_match: a rule's match at a place in a file.
type semgrepImportResult struct {
	CheckID string `json:"check_id"`
	Path    string `json:"path"`
	Start   struct {
		Line int `json:"line"`
	} `json:"start"`
	End struct {
		Line int `json:"line"`
	} `json:"end"`
	Extra struct {
		Message  string          `json:"message"`
		Severity string          `json:"severity"`
		Metadata json.RawMessage `json:"metadata"`
		// SCA is set on a Supply Chain result, one of a rule that names the dependency it is about.
		SCA *semgrepSCAMatch `json:"sca_info"`
	} `json:"extra"`
}

// semgrepSCAMatch is a Supply Chain result's dependency, sca_match in Semgrep's schema.
type semgrepSCAMatch struct {
	// ReachabilityRule is whether the rule also looks for the vulnerable code in the repository, and
	// Reachable whether it found it there; a rule that does not checks the version alone.
	ReachabilityRule bool `json:"reachability_rule"`
	Reachable        bool `json:"reachable"`
	Match            struct {
		Lockfile string `json:"lockfile"`
		Found    struct {
			Package   string `json:"package"`
			Version   string `json:"version"`
			Ecosystem string `json:"ecosystem"`
			// Transitivity is direct, transitive or unknown.
			Transitivity string `json:"transitivity"`
			LockfilePath string `json:"lockfile_path"`
			LineNumber   int    `json:"line_number"`
		} `json:"found_dependency"`
	} `json:"dependency_match"`
}

// semgrepSeverities are the bands of the severities a Semgrep rule states. Semgrep's schema says
// CRITICAL, HIGH, MEDIUM and LOW replace ERROR as high and WARNING as medium. EXPERIMENT and INVENTORY,
// which it marks deprecated, are low, as INFO is.
var semgrepSeverities = map[string]sarif.Severity{
	"CRITICAL":   sarif.SeverityCritical,
	"HIGH":       sarif.SeverityHigh,
	"ERROR":      sarif.SeverityHigh,
	"MEDIUM":     sarif.SeverityMedium,
	"WARNING":    sarif.SeverityMedium,
	"LOW":        sarif.SeverityLow,
	"INFO":       sarif.SeverityLow,
	"EXPERIMENT": sarif.SeverityLow,
	"INVENTORY":  sarif.SeverityLow,
}

// semgrepSCASeverities are the bands of the severity a Supply Chain rule gives its advisory, in its
// sca-severity metadata, the GitHub advisory database's words.
var semgrepSCASeverities = map[string]sarif.Severity{
	"CRITICAL": sarif.SeverityCritical,
	"HIGH":     sarif.SeverityHigh,
	"MODERATE": sarif.SeverityMedium,
	"MEDIUM":   sarif.SeverityMedium,
	"LOW":      sarif.SeverityLow,
}

// semgrepPURLTypes are the package URL type of each ecosystem Semgrep names a dependency's, where
// Draugr orders that ecosystem's versions.
var semgrepPURLTypes = map[string]string{
	"npm": "npm", "pypi": "pypi", "gem": "gem", "gomod": "golang", "cargo": "cargo", "maven": "maven",
	"composer": "composer", "nuget": "nuget", "pub": "pub", "hex": "hex", "mix": "hex",
}

// readSemgrepImport reads the results of the import's control from the JSON Semgrep writes: its code
// results into sast and its Supply Chain results into sca. A file from a scan with both holds both,
// and is imported once into each control whose results are wanted. Semgrep Secrets results, whose
// rules say product secrets, are read into neither.
//
// A code finding is a rule's match at its file and line, under the rule's id, with the CWE its
// metadata names, rated from the rule's impact and likelihood as Draugr's own Semgrep run rates it,
// and by the rule's severity where it states neither.
//
// A Supply Chain finding is an advisory in a dependency at the version installed, in the lockfile
// that lists it, under its CVE so the known-exploited and EPSS feeds reach it, else its GHSA id,
// else Semgrep's own. The fixed version is read from the rule's sca-fix-versions for this package,
// and only those above the installed version where the ecosystem orders them. It is rated by the
// advisory's sca-severity. A rule that also looks for the vulnerable code matches once for each place
// it finds it; those matches are one finding, and the detail names each place.
//
// Semgrep leaves out of its JSON a result a nosemgrep comment suppressed, so the file holds no
// suppression.
func readSemgrepImport(data []byte, ft plugin.FileTarget) (importRead, error) {
	// Every file Semgrep writes has results, errors and paths; an object without them would decode
	// to no results and read as a clean scan.
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil || top["errors"] == nil || top["paths"] == nil ||
		!bytes.HasPrefix(bytes.TrimSpace(top["results"]), []byte("[")) {
		return importRead{}, errNotSemgrepJSON
	}
	var doc semgrepImportDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return importRead{}, errNotSemgrepJSON
	}
	if ft.Control != "sast" && ft.Control != "sca" {
		return importRead{}, fmt.Errorf("the import names control %q; import this file into sast or sca", ft.Control)
	}
	// The name Semgrep's own SARIF gives the tool, so a code finding merges with Draugr's run of it.
	tool := "Semgrep OSS"
	if doc.Engine == "PRO" {
		tool = "Semgrep PRO"
	}

	rep := sarif.Report{Tool: tool, Rules: map[string]sarif.Rule{}}
	var rated []string
	var deps []*semgrepDependency
	byKey := map[string]*semgrepDependency{}
	for i, r := range doc.Results {
		what := "result " + strconv.Itoa(i+1)
		if strings.TrimSpace(r.CheckID) == "" {
			return importRead{}, semgrepIncomplete(what, "check_id, the rule it matched")
		}
		what += " (" + r.CheckID + ")"
		if strings.TrimSpace(r.Path) == "" {
			return importRead{}, semgrepIncomplete(what, "path")
		}
		var meta map[string]any
		_ = json.Unmarshal(r.Extra.Metadata, &meta)
		switch semgrepProduct(r, meta) {
		case "sast":
			if ft.Control != "sast" {
				continue
			}
			found, rule, how, err := semgrepCodeResult(r, meta, tool)
			if err != nil {
				return importRead{}, fmt.Errorf("%s: %w", what, err)
			}
			rep.Results = append(rep.Results, found)
			rated = append(rated, how)
			if _, seen := rep.Rules[found.RuleID]; !seen {
				rep.Rules[found.RuleID] = rule
			}
		case "sca":
			if ft.Control != "sca" {
				continue
			}
			if err := semgrepAddDependency(&deps, byKey, r, meta, what); err != nil {
				return importRead{}, err
			}
		}
	}
	for _, d := range deps {
		found, rule, how, err := semgrepDependencyResult(d, tool)
		if err != nil {
			return importRead{}, err
		}
		rep.Results = append(rep.Results, found)
		rated = append(rated, how)
		if _, seen := rep.Rules[found.RuleID]; !seen {
			rep.Rules[found.RuleID] = rule
		}
	}
	if ft.Control == "sast" {
		// What Semgrep did not finish is a file of code no rule read in full, as for its own run.
		rep.Inputs = semgrepUnread(semgrepJSON{semgrepCoverage: doc.semgrepCoverage}, "", semgrepLanguages{all: true}, nil)
		for i := range rep.Inputs {
			rep.Inputs[i].Scanner = plugin.ImportScanner
		}
	}
	outside := relativeToCheckouts(rep.Results, checkoutRoots(ft.Repositories))

	var run importRun
	run.Tool.Driver = importDriver{Name: tool, Version: doc.Version}
	run.Results = make([]json.RawMessage, len(rep.Results))
	return importRead{rep: rep, outside: outside, meta: importLog{Runs: []importRun{run}}, rated: rated}, nil
}

// semgrepProduct is the Semgrep product a result belongs to, as Semgrep's rule.py decides it for the
// rule: sca for a rule naming a dependency, which gives the result its sca_info, secrets for a rule
// whose metadata says product secrets, and sast, Semgrep Code, for every other.
func semgrepProduct(r semgrepImportResult, meta map[string]any) string {
	switch {
	case r.Extra.SCA != nil:
		return "sca"
	case meta["product"] == "secrets":
		return "secrets"
	}
	return "sast"
}

// semgrepRuleRating is the rating a rule's severity gives, for a rule that states no impact and
// likelihood, or a Supply Chain rule that states no advisory severity.
func semgrepRuleRating(severity string) (*sarif.Rating, error) {
	stated := strings.ToUpper(strings.TrimSpace(severity))
	band, known := semgrepSeverities[stated]
	if !known {
		return nil, fmt.Errorf("severity %q; a Semgrep rule's severity is CRITICAL, HIGH, MEDIUM, LOW, INFO, "+
			"ERROR or WARNING. Import the file Semgrep wrote, unedited", severity)
	}
	return newRating(band, map[string]string{"severity": stated}, "Semgrep "+stated), nil
}

// semgrepCodeResult is the finding and the rule of one code result, and how it was rated.
func semgrepCodeResult(r semgrepImportResult, meta map[string]any, tool string) (sarif.Result, sarif.Rule, string, error) {
	rating := semgrepRating(meta)
	how := "Semgrep's impact and likelihood"
	if rating == nil {
		var err error
		if rating, err = semgrepRuleRating(r.Extra.Severity); err != nil {
			return sarif.Result{}, sarif.Rule{}, "", err
		}
		how = "Semgrep's severity"
	}
	message := strings.TrimSpace(r.Extra.Message)
	found := sarif.Result{
		Tool:     tool,
		RuleID:   r.CheckID,
		Level:    osvLevel(rating.Severity),
		Message:  cmpTrimmed(message, r.CheckID),
		Location: sarif.Location{URI: r.Path, StartLine: max(r.Start.Line, 0)},
		CWE:      semgrepCWEs(meta["cwe"]),
		Rating:   rating,
	}
	if r.End.Line > r.Start.Line {
		found.Location.EndLine = r.End.Line
	}
	rule := sarif.Rule{Name: r.CheckID, ShortDescription: r.CheckID, FullDescription: message,
		HelpURI: semgrepHelpURI(meta)}
	return found, rule, how, nil
}

// semgrepCWE reads the CWE id at the start of a Semgrep rule's cwe entry, "CWE-78: Improper
// Neutralization …".
var semgrepCWE = regexp.MustCompile(`^CWE-(\d+)\b`)

// semgrepCWEs are the CWE ids a rule's cwe metadata names, a string or a list of them, as "CWE-78",
// in order and once each.
func semgrepCWEs(v any) []string {
	var entries []any
	switch t := v.(type) {
	case string:
		entries = []any{t}
	case []any:
		entries = t
	}
	var out []string
	for _, e := range entries {
		s, _ := e.(string)
		m := semgrepCWE.FindStringSubmatch(strings.ToUpper(strings.TrimSpace(s)))
		if m == nil {
			continue
		}
		if cwe := "CWE-" + m[1]; !slices.Contains(out, cwe) {
			out = append(out, cwe)
		}
	}
	return out
}

// semgrepHelpURI is the page a rule's metadata names for it, its shortlink or its source, or the first
// of its references, "" where it names none.
func semgrepHelpURI(meta map[string]any) string {
	for _, key := range []string{"shortlink", "source"} {
		if s, ok := meta[key].(string); ok && strings.HasPrefix(s, "https://") {
			return s
		}
	}
	if refs, ok := meta["references"].([]any); ok {
		for _, r := range refs {
			if s, ok := r.(string); ok && strings.HasPrefix(s, "https://") {
				return s
			}
		}
	}
	return ""
}

// semgrepDependency is one advisory in one package at one version in one lockfile, which a rule
// looking for the vulnerable code reports once for each place it finds it.
type semgrepDependency struct {
	first semgrepImportResult
	meta  map[string]any
	what  string
	// lockfile is where the dependency is listed, and line its line there, 0 where Semgrep gives none.
	lockfile string
	line     int
	// transitivity is each way the dependency is reached, direct or transitive, as Semgrep states it.
	transitivity []string
	// used are the places in the code a reachability rule found the vulnerable code called.
	used []string
}

// semgrepAddDependency adds Supply Chain result r to the dependency it is about, which it opens where
// no earlier result named it.
func semgrepAddDependency(deps *[]*semgrepDependency, byKey map[string]*semgrepDependency,
	r semgrepImportResult, meta map[string]any, what string) error {
	sca := r.Extra.SCA
	found := sca.Match.Found
	if strings.TrimSpace(found.Package) == "" {
		return semgrepIncomplete(what, "sca_info.dependency_match.found_dependency.package")
	}
	lockfile := cmpTrimmed(found.LockfilePath, sca.Match.Lockfile, r.Path)
	key := strings.Join([]string{r.CheckID, lockfile, found.Ecosystem, found.Package, found.Version}, "\x00")
	d, seen := byKey[key]
	if !seen {
		d = &semgrepDependency{first: r, meta: meta, what: what, lockfile: lockfile, line: max(found.LineNumber, 0)}
		byKey[key] = d
		*deps = append(*deps, d)
	}
	if t := strings.ToLower(strings.TrimSpace(found.Transitivity)); (t == "direct" || t == "transitive") &&
		!slices.Contains(d.transitivity, t) {
		d.transitivity = append(d.transitivity, t)
	}
	if sca.ReachabilityRule && sca.Reachable && r.Path != lockfile {
		at := r.Path
		if r.Start.Line > 0 {
			at += ":" + strconv.Itoa(r.Start.Line)
		}
		if !slices.Contains(d.used, at) {
			d.used = append(d.used, at)
		}
	}
	return nil
}

// semgrepAdvisoryIDs are the advisory's ids a Supply Chain rule's metadata names: its cve, its
// sca-vuln-database-identifier and its ghsa, each a CVE or GHSA id, in that order and once each.
func semgrepAdvisoryIDs(meta map[string]any) []string {
	var ids []string
	for _, key := range []string{"cve", "sca-vuln-database-identifier", "ghsa"} {
		var values []any
		switch t := meta[key].(type) {
		case string:
			values = []any{t}
		case []any:
			values = t
		}
		for _, v := range values {
			s, _ := v.(string)
			if s = strings.TrimSpace(s); checkmarxAdvisory.MatchString(s) && !slices.Contains(ids, s) {
				ids = append(ids, s)
			}
		}
	}
	return ids
}

// semgrepDependencyResult is the finding and the rule of one advisory in one dependency, and how it
// was rated.
func semgrepDependencyResult(d *semgrepDependency, tool string) (sarif.Result, sarif.Rule, string, error) {
	r, meta := d.first, d.meta
	dep := r.Extra.SCA.Match.Found

	ids := semgrepAdvisoryIDs(meta)
	own := r.CheckID
	for _, prefix := range []string{"CVE-", "GHSA-"} {
		if i := slices.IndexFunc(ids, func(id string) bool { return strings.HasPrefix(id, prefix) }); i >= 0 {
			own = ids[i]
			break
		}
	}

	ecosystem := strings.ToLower(strings.TrimSpace(dep.Ecosystem))
	pkg := &sarif.Package{Name: dep.Package, Version: dep.Version, Ecosystem: ecosystem}
	if t := semgrepPURLTypes[ecosystem]; t != "" && dep.Version != "" {
		name := gitlabPURLName(t, dep.Package)
		if t == "maven" {
			name = strings.Replace(dep.Package, ":", "/", 1)
		}
		pkg.PURL = "pkg:" + t + "/" + name + "@" + dep.Version
	}
	osvGoVersion(pkg)
	fixed, named := semgrepFixedVersion(meta["sca-fix-versions"], pkg)
	pkg.FixedVersion = fixed

	var detail []string
	if m := strings.Join(strings.Fields(r.Extra.Message), " "); m != "" {
		detail = append(detail, m)
	}
	if fixed == "" && len(named) > 0 {
		// A fix for an older release line is not one for this version, and stays in front of the
		// reader beside "no fix available".
		detail = append(detail, "Semgrep names "+strings.Join(named, ", ")+" as fixed, none above the installed version.")
	}
	switch {
	case len(d.used) > 0:
		detail = append(detail, "Semgrep found the vulnerable code used at "+strings.Join(d.used, ", ")+".")
	case r.Extra.SCA.ReachabilityRule:
		detail = append(detail, "Semgrep looked for the vulnerable code and found no use of it.")
	}
	switch {
	case slices.Contains(d.transitivity, "direct") && slices.Contains(d.transitivity, "transitive"):
		detail = append(detail, "A direct dependency, and a transitive one.")
	case slices.Contains(d.transitivity, "transitive"):
		detail = append(detail, "A transitive dependency.")
	}

	how := "Semgrep's Supply Chain severity"
	var rating *sarif.Rating
	if s, ok := meta["sca-severity"].(string); ok && strings.TrimSpace(s) != "" {
		stated := strings.ToUpper(strings.TrimSpace(s))
		band, known := semgrepSCASeverities[stated]
		if !known {
			return sarif.Result{}, sarif.Rule{}, "", fmt.Errorf("%s: sca-severity %q; Semgrep rates an advisory "+
				"CRITICAL, HIGH, MODERATE or LOW. Import the file Semgrep wrote, unedited", d.what, s)
		}
		rating = newRating(band, map[string]string{"sca-severity": stated}, "Semgrep "+stated)
	} else {
		var err error
		if rating, err = semgrepRuleRating(r.Extra.Severity); err != nil {
			return sarif.Result{}, sarif.Rule{}, "", fmt.Errorf("%s: %w", d.what, err)
		}
		how = "Semgrep's severity"
	}
	found := sarif.Result{
		Tool:     tool,
		RuleID:   own,
		Level:    osvLevel(rating.Severity),
		Location: sarif.Location{URI: d.lockfile, StartLine: d.line},
		Aliases:  osvAliases(own, ids),
		Package:  pkg,
		CWE:      semgrepCWEs(meta["cwe"]),
		Message: trivyVulnMessage(trivyVuln{PkgName: pkg.Name, InstalledVersion: pkg.Version,
			FixedVersion: pkg.FixedVersion}),
		Detail: strings.Join(detail, " "),
		Rating: rating,
	}
	rule := sarif.Rule{Name: own, ShortDescription: own, HelpURI: semgrepHelpURI(meta)}
	return found, rule, how, nil
}

// semgrepFixedVersion reads a Supply Chain rule's sca-fix-versions, a list of objects each naming a
// package and a version that fixes it, [{"grpcio": "1.53.0"}], as Semgrep's own text output reads it:
// the entries for p's package. It returns those above the installed version, joined as Trivy joins
// several, keeping every one where the ecosystem's versions cannot be ordered, and every version the
// rule names for the package.
func semgrepFixedVersion(v any, p *sarif.Package) (fixed string, named []string) {
	entries, _ := v.([]any)
	for _, e := range entries {
		m, _ := e.(map[string]any)
		s, _ := m[p.Name].(string)
		if s = strings.TrimSpace(s); s != "" && !slices.Contains(named, s) {
			named = append(named, s)
		}
	}
	eco := versionorder.Ecosystem(p.PURL, p.Ecosystem)
	installed, ordered := versionorder.Parse(eco, p.Version)
	var above []string
	for _, s := range named {
		if ordered {
			if parsed, ok := versionorder.Parse(eco, s); ok {
				if order, ok := parsed.Compare(installed); ok && order <= 0 {
					continue
				}
			}
		}
		above = append(above, s)
	}
	return strings.Join(above, ", "), named
}
