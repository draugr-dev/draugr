package scanners

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// gitlabSchemaMajor is the major version of GitLab's security report schemas the import reads, the
// one GitLab 15 and later require of every tool writing them.
const gitlabSchemaMajor = "15"

// gitlabKind is one of GitLab's security report schemas the import reads.
type gitlabKind struct {
	// format is the import format that names it.
	format string
	// scanType is the scan.type a report of it states.
	scanType string
	// name is what the error messages call it, and file the name GitLab gives the report.
	name, file string
	// example is a command that writes one, "" where none outside GitLab's analyzers is known.
	example string
}

// The schemas the import reads.
var (
	gitlabSAST = gitlabKind{saga.ImportFormatGitLabSAST, "sast", "SAST", "gl-sast-report.json",
		"semgrep scan --gitlab-sast"}
	gitlabDependencyScanning = gitlabKind{saga.ImportFormatGitLabDependencyScanning, "dependency_scanning",
		"dependency scanning", "gl-dependency-scanning-report.json", ""}
)

// errGitLabVulnerabilityIncomplete is the error of a vulnerability missing what its schema needs to
// place and name it.
var errGitLabVulnerabilityIncomplete = errors.New("a vulnerability names no file, identifier or package, " +
	"which every one in a GitLab report of this kind carries. Import the file the tool wrote, unedited")

// gitlabDoc is the part of a GitLab security report the import reads, as GitLab's schemas describe it
// (dist/sast-report-format.json and dist/dependency-scanning-report-format.json in
// gitlab.com/gitlab-org/security-products/security-report-schemas).
type gitlabDoc struct {
	Version string `json:"version"`
	Scan    struct {
		Type    string        `json:"type"`
		Status  string        `json:"status"`
		Scanner gitlabScanner `json:"scanner"`
	} `json:"scan"`
	Vulnerabilities []gitlabVulnerability `json:"vulnerabilities"`
}

// gitlabScanner is the tool a report or one of its vulnerabilities names.
type gitlabScanner struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// gitlabVulnerability is one vulnerability of a GitLab report. Message is the field schema 14 had and
// 15 dropped, which Semgrep's own writer of the format still fills instead of Name. Solution is where
// a dependency scanner says which version fixes it.
type gitlabVulnerability struct {
	Name        string        `json:"name"`
	Message     string        `json:"message"`
	Description string        `json:"description"`
	Solution    string        `json:"solution"`
	Severity    string        `json:"severity"`
	Scanner     gitlabScanner `json:"scanner"`
	Location    struct {
		File       string `json:"file"`
		StartLine  int    `json:"start_line"`
		EndLine    int    `json:"end_line"`
		Dependency struct {
			Package struct {
				Name string `json:"name"`
			} `json:"package"`
			Version string `json:"version"`
		} `json:"dependency"`
	} `json:"location"`
	Identifiers []gitlabIdentifier `json:"identifiers"`
}

// gitlabIdentifier names a vulnerability in a rule set or a database. The first of a
// vulnerability's identifiers is its primary one.
type gitlabIdentifier struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
	URL   string `json:"url"`
}

// gitlabSeverities are the bands of GitLab's severities. Info, the mildest a tool can give, is low,
// as Veracode's Informational is. Unknown, and a vulnerability that states none, are absent: no
// rating says nothing about how bad the flaw is, so each ranks high and says it was not rated.
var gitlabSeverities = map[string]sarif.Severity{
	"Critical": sarif.SeverityCritical,
	"High":     sarif.SeverityHigh,
	"Medium":   sarif.SeverityMedium,
	"Low":      sarif.SeverityLow,
	"Info":     sarif.SeverityLow,
}

// readGitLabSASTImport reads a SAST report in GitLab's security report format, the
// gl-sast-report.json GitLab's analyzers write and other tools write for GitLab.
//
// A finding is a vulnerability at its file and line, under its primary identifier, the rule that
// found it, with the CWE ids its identifiers name, rated by the severity the report states.
func readGitLabSASTImport(data []byte, ft plugin.FileTarget) (importRead, error) {
	return readGitLabImport(data, ft, gitlabSAST, gitlabSASTResult)
}

// readGitLabDependencyScanningImport reads a dependency scanning report in GitLab's security report
// format, the gl-dependency-scanning-report.json GitLab's analyzers write and other tools write for
// GitLab.
//
// A finding is a vulnerability of a package at the version installed, in the manifest or lockfile
// the report names, under its CVE where it has one, so the known-exploited and EPSS feeds reach it,
// else its GHSA id, else the report's own id for it. Its fixed version is the one the report's
// solution names, and it is rated by the severity the report states.
func readGitLabDependencyScanningImport(data []byte, ft plugin.FileTarget) (importRead, error) {
	return readGitLabImport(data, ft, gitlabDependencyScanning, gitlabDependencyResult)
}

// readGitLabImport reads a report of kind, making each vulnerability a finding with result.
//
// A report of another schema major version, another scan type or a scan that failed is refused,
// since the file is then not the findings of a finished scan of that kind.
func readGitLabImport(data []byte, ft plugin.FileTarget, kind gitlabKind,
	result func(gitlabVulnerability, string) (sarif.Result, sarif.Rule, string, error)) (importRead, error) {
	notOne := fmt.Errorf("not a GitLab %s report. Import the %s a GitLab analyzer wrote", kind.name, kind.file)
	if kind.example != "" {
		notOne = fmt.Errorf("%w, or the file a tool wrote in that format, such as %s", notOne, kind.example)
	}
	// A file with no vulnerabilities list, or with no scan, would read as a clean scan.
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil || top["scan"] == nil ||
		!bytes.HasPrefix(bytes.TrimSpace(top["vulnerabilities"]), []byte("[")) {
		return importRead{}, notOne
	}
	var doc gitlabDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return importRead{}, notOne
	}
	if major, _, _ := strings.Cut(doc.Version, "."); major != gitlabSchemaMajor {
		return importRead{}, fmt.Errorf("schema version %q. Draugr reads GitLab's %s schema version %s.x, "+
			"which GitLab 15 and later require", doc.Version, kind.name, gitlabSchemaMajor)
	}
	if doc.Scan.Type != kind.scanType {
		return importRead{}, fmt.Errorf("a %q scan, and format %s reads a %s scan. Import the %s",
			doc.Scan.Type, kind.format, kind.name, kind.file)
	}
	if doc.Scan.Status != "success" {
		return importRead{}, fmt.Errorf("scan status %q. Draugr reads a scan that succeeded. Run the scan again",
			doc.Scan.Status)
	}

	tool := cmp.Or(doc.Scan.Scanner.Name, "GitLab "+kind.name)
	rep := sarif.Report{Tool: tool, Rules: map[string]sarif.Rule{}}
	rated := make([]string, 0, len(doc.Vulnerabilities))
	for _, v := range doc.Vulnerabilities {
		found, rule, how, err := result(v, tool)
		if err != nil {
			return importRead{}, err
		}
		rep.Results = append(rep.Results, found)
		rated = append(rated, how)
		if _, seen := rep.Rules[found.RuleID]; !seen {
			rep.Rules[found.RuleID] = rule
		}
	}
	outside := relativeToCheckouts(rep.Results, checkoutRoots(ft.Repositories))

	var run importRun
	run.Tool.Driver = importDriver{Name: tool, Version: doc.Scan.Scanner.Version}
	run.Results = make([]json.RawMessage, len(rep.Results))
	return importRead{rep: rep, outside: outside, meta: importLog{Runs: []importRun{run}}, rated: rated}, nil
}

// gitlabRating is the rating of a severity the report states, and whether GitLab's format has it. An
// empty one is Unknown.
func gitlabRating(severity string) (*sarif.Rating, bool, error) {
	stated := cmp.Or(severity, "Unknown")
	band, known := gitlabSeverities[stated]
	if !known && stated != "Unknown" {
		return nil, false, fmt.Errorf("severity %q; GitLab's format rates a vulnerability Critical, High, "+
			"Medium, Low, Info or Unknown. Import the file the tool wrote, unedited", severity)
	}
	return newRating(band, map[string]string{"severity": stated}, "GitLab "+stated), known, nil
}

// gitlabSASTResult is the finding and the rule of one SAST vulnerability, reported under the scanner
// the vulnerability names, else tool, and how it was rated.
func gitlabSASTResult(v gitlabVulnerability, tool string) (sarif.Result, sarif.Rule, string, error) {
	if len(v.Identifiers) == 0 || v.Identifiers[0].Value == "" || v.Location.File == "" {
		return sarif.Result{}, sarif.Rule{}, "", errGitLabVulnerabilityIncomplete
	}
	primary := v.Identifiers[0]
	rating, known, err := gitlabRating(v.Severity)
	if err != nil {
		return sarif.Result{}, sarif.Rule{}, "", err
	}
	if !known {
		// A tool's rule rated Unknown, not an advisory awaiting a score, so the label says so.
		rating = newRating(sarif.SeverityHigh, rating.Fields, rating.Detail+", not rated, so ranked high")
	}
	message := cmp.Or(v.Name, v.Message, primary.Name)
	found := sarif.Result{
		Tool:     cmp.Or(v.Scanner.Name, tool),
		RuleID:   primary.Value,
		Level:    osvLevel(rating.Severity),
		Message:  message,
		Location: sarif.Location{URI: v.Location.File, StartLine: v.Location.StartLine},
		CWE:      gitlabCWEs(v.Identifiers),
		Rating:   rating,
	}
	if v.Location.EndLine > v.Location.StartLine {
		found.Location.EndLine = v.Location.EndLine
	}
	if d := strings.TrimSpace(v.Description); d != "" && d != message {
		found.Detail = d
	}
	rule := sarif.Rule{Name: primary.Value, ShortDescription: cmp.Or(v.Name, primary.Name), HelpURI: primary.URL}
	return found, rule, "GitLab's severity", nil
}

// gitlabDependencyResult is the finding and the rule of one dependency scanning vulnerability,
// reported under the scanner the vulnerability names, else tool, and how it was rated.
func gitlabDependencyResult(v gitlabVulnerability, tool string) (sarif.Result, sarif.Rule, string, error) {
	dep := v.Location.Dependency
	if len(v.Identifiers) == 0 || v.Location.File == "" || dep.Package.Name == "" {
		return sarif.Result{}, sarif.Rule{}, "", errGitLabVulnerabilityIncomplete
	}
	rating, known, err := gitlabRating(v.Severity)
	if err != nil {
		return sarif.Result{}, sarif.Rule{}, "", err
	}
	own := gitlabAdvisoryID(v.Identifiers)
	var ids []string
	for _, id := range v.Identifiers {
		if t := strings.ToLower(id.Type); t == "cve" || t == "ghsa" {
			ids = append(ids, id.Value)
		}
	}
	ecosystem, purlType := gitlabEcosystem(v.Location.File)
	pkg := &sarif.Package{
		Name:         dep.Package.Name,
		Version:      dep.Version,
		FixedVersion: gitlabFixedVersion(v.Solution),
		Ecosystem:    ecosystem,
	}
	if purlType != "" && dep.Version != "" {
		pkg.PURL = "pkg:" + purlType + "/" + gitlabPURLName(purlType, dep.Package.Name) + "@" + dep.Version
	}
	osvGoVersion(pkg)
	found := sarif.Result{
		Tool:     cmp.Or(v.Scanner.Name, tool),
		RuleID:   own.Value,
		Location: sarif.Location{URI: v.Location.File},
		Aliases:  osvAliases(own.Value, ids),
		Package:  pkg,
		Message: trivyVulnMessage(trivyVuln{PkgName: pkg.Name, InstalledVersion: pkg.Version,
			FixedVersion: pkg.FixedVersion, Title: v.Name}),
		Detail: strings.TrimSpace(v.Description),
	}
	if s := strings.TrimSpace(v.Solution); pkg.FixedVersion == "" && s != "" {
		// A solution this does not read stays in front of the reader, beside "no fix available".
		found.Detail = strings.TrimSpace(found.Detail + "\n\nSolution: " + s)
	}
	how := "GitLab's severity"
	if known {
		found.Rating = rating
		found.Level = osvLevel(rating.Severity)
	} else {
		markNotScored(&found, rating.Fields, found.Message)
		how = "GitLab states Unknown, " + notScoredYet + ", read as high"
	}
	rule := sarif.Rule{Name: own.Value, ShortDescription: v.Name, HelpURI: own.URL}
	return found, rule, how, nil
}

// gitlabAdvisoryID is the identifier a dependency finding is named by: its CVE, which the
// known-exploited and EPSS feeds key on, else its GHSA id, else the primary identifier, the
// scanner's own id for the advisory.
func gitlabAdvisoryID(ids []gitlabIdentifier) gitlabIdentifier {
	for _, want := range []string{"cve", "ghsa"} {
		if i := slices.IndexFunc(ids, func(id gitlabIdentifier) bool {
			return strings.EqualFold(id.Type, want) && id.Value != ""
		}); i >= 0 {
			return ids[i]
		}
	}
	return ids[0]
}

// gitlabEcosystems are the ecosystem Draugr's scanners name and the package URL type of the packages
// a manifest or lockfile lists, by its name. A file of another name leaves both empty.
var gitlabEcosystems = map[string][2]string{
	"go.mod": {"gomod", "golang"}, "go.sum": {"gomod", "golang"},
	"package-lock.json": {"npm", "npm"}, "npm-shrinkwrap.json": {"npm", "npm"}, "yarn.lock": {"npm", "npm"},
	"pnpm-lock.yaml": {"npm", "npm"}, "package.json": {"npm", "npm"},
}

// gitlabEcosystem is the ecosystem and package URL type of the packages file lists.
func gitlabEcosystem(file string) (ecosystem, purlType string) {
	e := gitlabEcosystems[path.Base(strings.ReplaceAll(file, `\`, "/"))]
	return e[0], e[1]
}

// gitlabPURLName is name as a package URL of type writes it: an npm scope's @ is escaped, as the
// package URL specification requires.
func gitlabPURLName(purlType, name string) string {
	if purlType == "npm" {
		return strings.Replace(name, "@", "%40", 1)
	}
	return name
}

// gitlabSolutionFix reads the version a dependency scanner's solution says to upgrade to, as
// Gemnasium writes it, "Upgrade to version 0.3.3 or above." for its own advisories and "Upgrade to
// v1.9.0 or greater." for those it takes from retire.js.
var gitlabSolutionFix = regexp.MustCompile(`^Upgrade to (?:version |v)?(\S+?) or (?:above|greater)\.?$`)

// gitlabFixedVersion is the version solution names as the fix, without a leading "v", or "" where it
// names none in a form this reads: no fix, as a vulnerability whose report gives none is read.
func gitlabFixedVersion(solution string) string {
	m := gitlabSolutionFix.FindStringSubmatch(strings.TrimSpace(solution))
	if m == nil {
		return ""
	}
	return strings.TrimPrefix(m[1], "v")
}

// gitlabCWEs are the CWE ids a vulnerability's identifiers of type cwe name, as "CWE-89", in their
// order and once each. An identifier whose value is not a CWE number is left out.
func gitlabCWEs(ids []gitlabIdentifier) []string {
	var out []string
	for _, id := range ids {
		if !strings.EqualFold(id.Type, "cwe") {
			continue
		}
		n := strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(id.Value)), "CWE-")
		if _, err := strconv.Atoi(n); err != nil {
			continue
		}
		if cwe := "CWE-" + n; !slices.Contains(out, cwe) {
			out = append(out, cwe)
		}
	}
	return out
}
