package scanners

import (
	"bytes"
	"cmp"
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

// checkmarxTool is the name a finding read from Checkmarx One's file is reported under.
const checkmarxTool = "Checkmarx One"

// errNotCheckmarxOneJSON is the error of a file that is not the JSON Checkmarx One's CLI writes.
var errNotCheckmarxOneJSON = errors.New("not Checkmarx One JSON. Write it with " +
	"cx results show --scan-id <id> --report-format json")

// checkmarxIncomplete is the error of a result of kind, "SAST", missing what the format needs to place
// and name it, naming the result by its id where it has one.
func checkmarxIncomplete(kind string, r checkmarxResult, what string) error {
	result := "a " + kind + " result"
	if kind == "SCA" {
		result = "an SCA result"
	}
	if r.ID != "" {
		result += " (id " + r.ID + ")"
	}
	return fmt.Errorf("%s names no %s; every result cx results show writes names them. "+
		"Import the file the CLI wrote, unedited", result, what)
}

// checkmarxTypes are the result types each control reads from the file, by the control. SAST is
// Checkmarx's static analysis, SCA its dependency scan and KICS its infrastructure-as-code scan. The
// file's other types, container images and supply-chain checks, describe no file in the repository.
var checkmarxTypes = map[string]string{"sast": "sast", "sca": "sca", "iac": "kics"}

// checkmarxDoc is the part of the JSON `cx results show --report-format json` writes that the import
// reads, as internal/wrappers/results-json.go in github.com/Checkmarx/ast-cli defines it.
type checkmarxDoc struct {
	Results    []checkmarxResult `json:"results"`
	TotalCount int               `json:"totalCount"`
	ScanID     string            `json:"scanID"`
}

// checkmarxResult is one result of any type. Type decides which of Data's fields it fills.
type checkmarxResult struct {
	Type        string `json:"type"`
	ID          string `json:"id"`
	State       string `json:"state"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Data        struct {
		// SAST and KICS.
		QueryID   json.RawMessage `json:"queryId"`
		QueryName string          `json:"queryName"`
		// SAST: the path the data takes, from where it enters to where it is used.
		Nodes []checkmarxNode `json:"nodes"`
		// SCA.
		PackageIdentifier  string          `json:"packageIdentifier"`
		RecommendedVersion json.RawMessage `json:"recommendedVersion"`
		Package            *struct {
			Locations       []string                `json:"locations"`
			DependencyPaths [][]checkmarxDependency `json:"dependencyPaths"`
			Direct          bool                    `json:"isDirectDependency"`
		} `json:"scaPackageData"`
		// KICS.
		Line     int    `json:"line"`
		Filename string `json:"filename"`
		Value    string `json:"value"`
		Expected string `json:"expectedValue"`
	} `json:"data"`
	Comments struct {
		Comments string `json:"comments"`
	} `json:"comments"`
	Details struct {
		CWE     json.RawMessage `json:"cweId"`
		CVEName string          `json:"cveName"`
	} `json:"vulnerabilityDetails"`
}

// checkmarxNode is one step of a SAST result's data flow.
type checkmarxNode struct {
	Line     int    `json:"line"`
	FileName string `json:"fileName"`
}

// checkmarxDependency is one package on a dependency path, from a direct dependency to the vulnerable
// package.
type checkmarxDependency struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

// checkmarxSeverities are the bands of the severities Checkmarx One gives a result. Info, the
// mildest, is low, as GitLab's Info is. A result that states none is absent: it ranks high and says
// it was not rated.
var checkmarxSeverities = map[string]sarif.Severity{
	"CRITICAL": sarif.SeverityCritical,
	"HIGH":     sarif.SeverityHigh,
	"MEDIUM":   sarif.SeverityMedium,
	"LOW":      sarif.SeverityLow,
	"INFO":     sarif.SeverityLow,
}

// checkmarxSetAside are the triage states that take a result out of what Checkmarx One counts, as its
// CLI's isExploitable reads them. Proposed Not Exploitable is a proposal awaiting review, and counts.
var checkmarxSetAside = []string{"NOT_EXPLOITABLE", "IGNORED"}

// readCheckmarxOneImport reads the results of the import's control from the JSON `cx results show`
// writes: SAST into sast, SCA into sca and KICS into iac. The file holds all three, and is imported
// once into each control whose results are wanted.
//
// A SAST finding is a query's result at the file and line its data flow starts, as Checkmarx's own
// SARIF places it, under the query's name and its CWE. An SCA finding is a vulnerable package at the
// version installed, in each manifest Checkmarx names, under its CVE where it has one, so the
// known-exploited and EPSS feeds reach it, with the recommended version as its fix. A KICS finding is
// a query's result at its file and line, under KICS's query id, as Draugr's own KICS names it. Each
// is rated by the severity Checkmarx states, and a result triaged Not Exploitable or Ignored is one
// the tool suppressed.
//
// A file that does not list as many results as it counts is refused, since results are then missing
// from it or were added to it.
func readCheckmarxOneImport(data []byte, ft plugin.FileTarget) (importRead, error) {
	// The CLI writes all three keys on every file, and no other tool's JSON has them together; a file
	// without them would decode to no results and read as a clean scan.
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil || top["scanID"] == nil || top["totalCount"] == nil || top["results"] == nil {
		return importRead{}, errNotCheckmarxOneJSON
	}
	if v := bytes.TrimSpace(top["results"]); !bytes.HasPrefix(v, []byte("[")) && !bytes.Equal(v, []byte("null")) {
		return importRead{}, errNotCheckmarxOneJSON
	}
	var doc checkmarxDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return importRead{}, errNotCheckmarxOneJSON
	}
	if doc.TotalCount != len(doc.Results) {
		return importRead{}, fmt.Errorf("the file lists %d results and counts %d, so results are missing or "+
			"were added. Import the file cx results show wrote, unedited", len(doc.Results), doc.TotalCount)
	}
	kind, ok := checkmarxTypes[ft.Control]
	if !ok {
		return importRead{}, fmt.Errorf("the import names control %q; import this file into sast, sca or iac",
			ft.Control)
	}

	rep := sarif.Report{Tool: checkmarxTool, Rules: map[string]sarif.Rule{}}
	var rated []string
	for _, r := range doc.Results {
		if r.Type != kind {
			continue
		}
		var found []sarif.Result
		var rule sarif.Rule
		var err error
		switch kind {
		case "sast":
			found, rule, err = checkmarxSAST(r)
		case "sca":
			found, rule, err = checkmarxSCA(r)
		default:
			found, rule, err = checkmarxKICS(r)
		}
		if err != nil {
			return importRead{}, err
		}
		for _, f := range found {
			checkmarxTriage(&f, r)
			how := "Checkmarx's severity"
			if r.Severity == "" {
				how = "Checkmarx states no severity, read as high"
			}
			rep.Results = append(rep.Results, f)
			rated = append(rated, how)
			if _, seen := rep.Rules[f.RuleID]; !seen {
				rep.Rules[f.RuleID] = rule
			}
		}
	}
	outside := relativeToCheckouts(rep.Results, checkoutRoots(ft.Repositories))

	var run importRun
	run.Tool.Driver = importDriver{Name: checkmarxTool}
	run.Results = make([]json.RawMessage, len(rep.Results))
	return importRead{rep: rep, outside: outside, meta: importLog{Runs: []importRun{run}}, rated: rated}, nil
}

// checkmarxRating is the rating of the severity a result states, and whether Checkmarx's list has it.
// An empty one is not stated.
func checkmarxRating(severity string) (*sarif.Rating, bool, error) {
	band, known := checkmarxSeverities[severity]
	if !known && severity != "" {
		return nil, false, fmt.Errorf("severity %q; Checkmarx One rates a result CRITICAL, HIGH, MEDIUM, LOW "+
			"or INFO. Import the file cx results show wrote, unedited", severity)
	}
	stated := cmp.Or(severity, "none")
	return newRating(band, map[string]string{"severity": stated}, "Checkmarx "+stated), known, nil
}

// checkmarxRated rates a code or configuration finding by the severity its result states. A query
// that states none is a rule nobody rated, not an advisory awaiting a score, so the label says so.
func checkmarxRated(found *sarif.Result, severity string) error {
	rating, known, err := checkmarxRating(severity)
	if err != nil {
		return err
	}
	if !known {
		rating = newRating(sarif.SeverityHigh, rating.Fields, "Checkmarx states no severity, not rated, so ranked high")
	}
	found.Rating = rating
	found.Level = osvLevel(rating.Severity)
	return nil
}

// checkmarxPath is a path as Checkmarx writes it, from the root of the scanned source with a leading
// slash, relative to the repository as every other import's paths are.
func checkmarxPath(p string) string {
	return strings.TrimPrefix(strings.ReplaceAll(strings.TrimSpace(p), `\`, "/"), "/")
}

// checkmarxSAST is the finding and the rule of one SAST result.
func checkmarxSAST(r checkmarxResult) ([]sarif.Result, sarif.Rule, error) {
	i := slices.IndexFunc(r.Data.Nodes, func(n checkmarxNode) bool {
		return checkmarxPath(n.FileName) != ""
	})
	if r.Data.QueryName == "" || i < 0 {
		return nil, sarif.Rule{}, checkmarxIncomplete("SAST", r, "query or file")
	}
	start := r.Data.Nodes[i]
	title := strings.ReplaceAll(r.Data.QueryName, "_", " ")
	found := sarif.Result{
		Tool:     checkmarxTool,
		RuleID:   r.Data.QueryName,
		Message:  title,
		Location: sarif.Location{URI: checkmarxPath(start.FileName), StartLine: max(start.Line, 0)},
		CWE:      checkmarxCWEs(r.Details.CWE),
		Detail:   strings.Join(strings.Fields(r.Description), " "),
	}
	if end := r.Data.Nodes[len(r.Data.Nodes)-1]; len(r.Data.Nodes) > 1 && checkmarxPath(end.FileName) != "" {
		// Placed where the data enters, as Checkmarx's SARIF places it; where it is used is often the
		// line to change, so it is named too.
		found.Detail = strings.TrimSpace(found.Detail + " The data flows to " +
			checkmarxPath(end.FileName) + ":" + strconv.Itoa(end.Line) + ".")
	}
	if err := checkmarxRated(&found, r.Severity); err != nil {
		return nil, sarif.Rule{}, err
	}
	return []sarif.Result{found}, sarif.Rule{Name: r.Data.QueryName, ShortDescription: title}, nil
}

// checkmarxKICSQuery reads a KICS query id as Checkmarx One writes it, with a note on where it was
// taken from after the id: "fd54f200-402c-4333-a5a4-36ef6709af2f [Taken from query_id]".
var checkmarxKICSQuery = regexp.MustCompile(`^\s*([^\s\[]+)`)

// checkmarxKICS is the finding and the rule of one KICS result, under KICS's query id, as Draugr's
// own run of KICS names it.
func checkmarxKICS(r checkmarxResult) ([]sarif.Result, sarif.Rule, error) {
	var id string
	if err := json.Unmarshal(r.Data.QueryID, &id); err == nil {
		if m := checkmarxKICSQuery.FindStringSubmatch(id); m != nil {
			id = m[1]
		}
	}
	file := checkmarxPath(r.Data.Filename)
	if id == "" || file == "" {
		return nil, sarif.Rule{}, checkmarxIncomplete("KICS", r, "query or file")
	}
	found := sarif.Result{
		Tool:     checkmarxTool,
		RuleID:   id,
		Message:  cmp.Or(r.Data.QueryName, id),
		Location: sarif.Location{URI: file, StartLine: max(r.Data.Line, 0)},
	}
	switch {
	case r.Data.Value != "" && r.Data.Expected != "":
		found.Detail = r.Data.Value + ". " + r.Data.Expected + "."
	default:
		found.Detail = cmp.Or(r.Data.Value, r.Data.Expected)
	}
	if err := checkmarxRated(&found, r.Severity); err != nil {
		return nil, sarif.Rule{}, err
	}
	rule := sarif.Rule{Name: cmp.Or(r.Data.QueryName, id), ShortDescription: r.Data.QueryName,
		FullDescription: strings.TrimSpace(r.Description)}
	return []sarif.Result{found}, rule, nil
}

// checkmarxAdvisory is an id the known-exploited and EPSS feeds, or an advisory database, name a
// vulnerability by. Checkmarx's own ids for a vulnerability with no CVE, such as Cx35-4f6c, are not.
var checkmarxAdvisory = regexp.MustCompile(`^(CVE-\d{4}-\d+|GHSA(-[23456789cfghjmpqrvwx]{4}){3})$`)

// checkmarxSCA is the findings and the rule of one SCA result, one in each manifest Checkmarx names
// for the package.
func checkmarxSCA(r checkmarxResult) ([]sarif.Result, sarif.Rule, error) {
	pkgData := r.Data.Package
	if r.ID == "" || r.Data.PackageIdentifier == "" || pkgData == nil {
		return nil, sarif.Rule{}, checkmarxIncomplete("SCA", r, "vulnerability, package or manifest")
	}
	var files []string
	for _, l := range pkgData.Locations {
		if p := checkmarxPath(l); p != "" && !slices.Contains(files, p) {
			files = append(files, p)
		}
	}
	if len(files) == 0 {
		return nil, sarif.Rule{}, checkmarxIncomplete("SCA", r, "manifest")
	}

	// The vulnerability's id is its CVE where it has one. The file's cveName is read beside it, and
	// only where it is an advisory id.
	var ids []string
	for _, id := range []string{r.ID, r.Details.CVEName} {
		if id = strings.TrimSpace(id); id != "" && !slices.Contains(ids, id) &&
			(id == r.ID || checkmarxAdvisory.MatchString(id)) {
			ids = append(ids, id)
		}
	}
	own := r.ID
	if i := slices.IndexFunc(ids, func(id string) bool { return strings.HasPrefix(id, "CVE-") }); i >= 0 {
		own = ids[i]
	}

	ecosystem, name, version := checkmarxPackage(r.Data.PackageIdentifier, pkgData.DependencyPaths)
	var fixed string
	_ = json.Unmarshal(r.Data.RecommendedVersion, &fixed)
	pkg := sarif.Package{Name: name, Version: version, FixedVersion: strings.TrimSpace(fixed), Ecosystem: ecosystem}
	if t := versionorder.PURLType(ecosystem); version != "" {
		switch t {
		case "npm", "golang":
			pkg.PURL = "pkg:" + t + "/" + gitlabPURLName(t, name) + "@" + version
		case "maven":
			if group, artifact, ok := strings.Cut(name, ":"); ok {
				pkg.PURL = "pkg:maven/" + group + "/" + artifact + "@" + version
			}
		}
	}
	osvGoVersion(&pkg)

	// Checkmarx gives a vulnerability no title, only a description of a paragraph or more, which is
	// the detail; the message is the package and its fix, as for any dependency finding.
	detail := strings.Join(strings.Fields(r.Description), " ")
	if !pkgData.Direct {
		if via := checkmarxVia(r.Data.PackageIdentifier, pkgData.DependencyPaths); via != "" {
			detail = strings.TrimSpace(detail + " Brought in by " + via + ".")
		}
	}
	rating, known, err := checkmarxRating(r.Severity)
	if err != nil {
		return nil, sarif.Rule{}, err
	}
	out := make([]sarif.Result, 0, len(files))
	for _, file := range files {
		p := pkg
		found := sarif.Result{
			Tool:     checkmarxTool,
			RuleID:   own,
			Location: sarif.Location{URI: file},
			Aliases:  osvAliases(own, ids),
			Package:  &p,
			CWE:      checkmarxCWEs(r.Details.CWE),
			Message: trivyVulnMessage(trivyVuln{PkgName: p.Name, InstalledVersion: p.Version,
				FixedVersion: p.FixedVersion}),
			Detail: detail,
		}
		if known {
			copied := *rating
			found.Rating = &copied
			found.Level = osvLevel(rating.Severity)
		} else {
			markNotScored(&found, rating.Fields, found.Message)
		}
		out = append(out, found)
	}
	return out, sarif.Rule{Name: own, ShortDescription: own}, nil
}

// checkmarxEcosystems are the ecosystem Draugr's scanners name for the prefix Checkmarx's package
// identifiers carry, where the two differ: "Php-guzzlehttp/guzzle-6.3.0" is a Composer package.
var checkmarxEcosystems = map[string]string{"php": "composer", "ruby": "gem"}

// checkmarxPackage is the ecosystem, name and version of the package an SCA result names, as
// "Maven-com.thoughtworks.xstream:xstream-1.4.5". The name and version are read from the dependency
// path that ends at the package, which states them apart; a name or version holding a hyphen leaves
// the identifier alone ambiguous, and it is split at its last hyphen only where no path names it.
func checkmarxPackage(identifier string, paths [][]checkmarxDependency) (ecosystem, name, version string) {
	prefix, rest, _ := strings.Cut(identifier, "-")
	ecosystem = strings.ToLower(prefix)
	if e, ok := checkmarxEcosystems[ecosystem]; ok {
		ecosystem = e
	}
	for _, path := range paths {
		for _, node := range path {
			if node.ID == identifier && node.Name != "" {
				return ecosystem, node.Name, node.Version
			}
		}
	}
	if i := strings.LastIndex(rest, "-"); i > 0 {
		return ecosystem, rest[:i], rest[i+1:]
	}
	return ecosystem, rest, ""
}

// checkmarxVia names the direct dependencies that bring in a package that is not itself one: the
// first package on each dependency path that ends elsewhere.
func checkmarxVia(identifier string, paths [][]checkmarxDependency) string {
	var via []string
	for _, path := range paths {
		if len(path) == 0 || path[0].ID == identifier || path[0].Name == "" {
			continue
		}
		if s := strings.TrimSpace(path[0].Name + " " + path[0].Version); !slices.Contains(via, s) {
			via = append(via, s)
		}
	}
	return strings.Join(via, ", ")
}

// checkmarxCWEs is the CWE a result names, as "CWE-79". SAST writes it as a number and SCA as a
// string, "CWE-78"; one that is neither, such as "NVD-CWE-Other", names none.
func checkmarxCWEs(raw json.RawMessage) []string {
	var n int
	if err := json.Unmarshal(raw, &n); err == nil {
		if n > 0 {
			return []string{"CWE-" + strconv.Itoa(n)}
		}
		return nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil
	}
	s = strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(s)), "CWE-")
	if v, err := strconv.Atoi(s); err != nil || v <= 0 {
		return nil
	}
	return []string{"CWE-" + s}
}

// checkmarxTriage records a result triaged Not Exploitable or Ignored in Checkmarx One as one the tool
// suppressed, with the state and the comment given as the reason. The import's suppressions setting
// then decides whether it is set aside or counted, as for any tool's suppression.
func checkmarxTriage(found *sarif.Result, r checkmarxResult) {
	state := strings.ToUpper(strings.TrimSpace(r.State))
	if !slices.Contains(checkmarxSetAside, state) {
		return
	}
	reason := "triaged " + strings.ReplaceAll(state, "_", " ")
	if c := strings.TrimSpace(r.Comments.Comments); c != "" {
		reason += " (" + c + ")"
	}
	// No Service: the triage is the tool's own record, kept with the scan's results, as a suppression
	// in its settings is, and the report counts it as the tool's.
	found.Suppression = &sarif.Suppression{
		Kind:          "external",
		Origin:        sarif.OriginScanner,
		Justification: reason,
	}
}
