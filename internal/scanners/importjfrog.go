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

// jfrogTool is the name a finding read from JFrog's file is reported under.
const jfrogTool = "JFrog Xray"

// errNotJFrogSimpleJSON is the error of a file that is not the simple-json JFrog's CLI writes.
var errNotJFrogSimpleJSON = errors.New("not JFrog simple-json. Write it with jf audit --format simple-json")

// errJFrogVulnerabilityIncomplete is the error of a vulnerability missing what the format needs to
// place and name it.
var errJFrogVulnerabilityIncomplete = errors.New("a vulnerability names no package, advisory id or manifest, " +
	"which every one jf audit writes carries. Import the file jf audit wrote, unedited")

// jfrogDoc is the part of the simple-json JFrog's CLI writes that the import reads, as
// utils/formats/simplejsonapi.go in github.com/jfrog/jfrog-cli-security defines it, a file JFrog keeps
// stable as an API.
type jfrogDoc struct {
	Vulnerabilities    []jfrogVulnerability `json:"vulnerabilities"`
	SecurityViolations []jfrogVulnerability `json:"securityViolations"`
	Errors             []struct {
		FilePath     string `json:"filePath"`
		ErrorMessage string `json:"errorMessage"`
	} `json:"errors"`
	// The code findings, each with the violations a watch raised for them.
	SAST              []jfrogCodeRow `json:"sast"`
	SASTViolations    []jfrogCodeRow `json:"sastViolations"`
	Secrets           []jfrogCodeRow `json:"secrets"`
	SecretsViolations []jfrogCodeRow `json:"secretsViolations"`
	IaC               []jfrogCodeRow `json:"iac"`
	IaCViolations     []jfrogCodeRow `json:"iacViolations"`
	// Status holds each scan's status code: absent where the scan did not run, 0 where it succeeded.
	Status struct {
		SCA     *int `json:"scaScanStatusCode"`
		SAST    *int `json:"sastScanStatusCode"`
		Secrets *int `json:"secretsScanStatusCode"`
		IaC     *int `json:"iacScanStatusCode"`
	} `json:"scansStatus"`
}

// jfrogCodeRow is one SAST, secrets or IaC finding, or a violation a watch raised for one, a
// SourceCodeRow in simplejsonapi.go.
type jfrogCodeRow struct {
	Severity                string   `json:"severity"`
	RuleID                  string   `json:"ruleId"`
	CWE                     []string `json:"cwe"`
	ScannerShortDescription string   `json:"scannerShortDescription"`
	ScannerDescription      string   `json:"scannerDescription"`
	File                    string   `json:"file"`
	StartLine               int      `json:"startLine"`
	StartColumn             int      `json:"startColumn"`
	EndLine                 int      `json:"endLine"`
	Finding                 string   `json:"finding"`
	// Applicability is, on a secret, whether JFrog found the token live.
	Applicability *struct {
		Status             string `json:"status"`
		ScannerDescription string `json:"scannerDescription"`
	} `json:"applicability"`
}

// jfrogScan is what one control reads from the file: the scan whose status says whether it ran, the
// jf audit flag that runs it, and, for a code scan, its rows and the tool its findings are reported
// under.
type jfrogScan struct {
	name, flag, tool string
	status           func(*jfrogDoc) *int
	rows             func(*jfrogDoc) []jfrogCodeRow
}

// jfrogScans are the controls the file is read into, by control.
var jfrogScans = map[string]jfrogScan{
	"sca": {name: "dependency", flag: "--sca", tool: jfrogTool,
		status: func(d *jfrogDoc) *int { return d.Status.SCA }},
	"sast": {name: "SAST", flag: "--sast", tool: "JFrog SAST",
		status: func(d *jfrogDoc) *int { return d.Status.SAST },
		rows:   func(d *jfrogDoc) []jfrogCodeRow { return slices.Concat(d.SAST, d.SASTViolations) }},
	"secrets": {name: "secrets", flag: "--secrets", tool: "JFrog Secrets",
		status: func(d *jfrogDoc) *int { return d.Status.Secrets },
		rows:   func(d *jfrogDoc) []jfrogCodeRow { return slices.Concat(d.Secrets, d.SecretsViolations) }},
	"iac": {name: "IaC", flag: "--iac", tool: "JFrog IaC",
		status: func(d *jfrogDoc) *int { return d.Status.IaC },
		rows:   func(d *jfrogDoc) []jfrogCodeRow { return slices.Concat(d.IaC, d.IaCViolations) }},
}

// jfrogVulnerability is one vulnerable package, or one security violation a watch raised for one.
type jfrogVulnerability struct {
	Severity      string   `json:"severity"`
	Name          string   `json:"impactedPackageName"`
	Version       string   `json:"impactedPackageVersion"`
	Type          string   `json:"impactedPackageType"`
	Summary       string   `json:"summary"`
	Applicable    string   `json:"applicable"`
	FixedVersions []string `json:"fixedVersions"`
	CVEs          []struct {
		ID string `json:"id"`
	} `json:"cves"`
	IssueID string `json:"issueId"`
	// Components are the direct dependencies that bring the package in, each at the manifest it is
	// declared in.
	Components []struct {
		Name     string `json:"name"`
		Version  string `json:"version"`
		Location *struct {
			File string `json:"file"`
		} `json:"location"`
	} `json:"components"`
}

// jfrogSeverities are the bands of the severities Xray gives a vulnerability. Information, the
// mildest, is low. Unknown, and a vulnerability that states none, are absent: each ranks high and
// says it was not scored yet.
var jfrogSeverities = map[string]sarif.Severity{
	"Critical":    sarif.SeverityCritical,
	"High":        sarif.SeverityHigh,
	"Medium":      sarif.SeverityMedium,
	"Low":         sarif.SeverityLow,
	"Information": sarif.SeverityLow,
}

// readJFrogSimpleJSONImport reads the findings of the import's control from the simple-json `jf audit`
// writes: its dependency vulnerabilities into sca, and its SAST, secrets and IaC findings into those
// controls.
//
// A dependency finding is a vulnerable package at the version installed, in each manifest that declares a
// direct dependency bringing it in, under its CVE where it has one, so the known-exploited and EPSS
// feeds reach it, else Xray's own id for it. Its fixed version is the one Xray names, and it is rated
// by the severity Xray states. A security violation a watch raised is read the same way, and a
// vulnerability listed as both is one finding.
//
// A file whose scan for the control did not run or failed, or that records an error, is refused,
// since it is then not the findings of a finished scan.
func readJFrogSimpleJSONImport(data []byte, ft plugin.FileTarget) (importRead, error) {
	// Every file jf audit writes in this format has both keys, and no other tool's JSON does; a file
	// without them would decode to no vulnerabilities and read as a clean scan.
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil || top["scansStatus"] == nil || top["vulnerabilities"] == nil {
		return importRead{}, errNotJFrogSimpleJSON
	}
	if v := bytes.TrimSpace(top["vulnerabilities"]); !bytes.HasPrefix(v, []byte("[")) && !bytes.Equal(v, []byte("null")) {
		return importRead{}, errNotJFrogSimpleJSON
	}
	var doc jfrogDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return importRead{}, errNotJFrogSimpleJSON
	}
	scan, ok := jfrogScans[ft.Control]
	if !ok {
		return importRead{}, fmt.Errorf("the import names control %q; import this file into sca, sast, "+
			"secrets or iac", ft.Control)
	}
	switch status := scan.status(&doc); {
	case status == nil:
		return importRead{}, fmt.Errorf("no %s scan: the file records none. Run jf audit without "+
			"selecting scanners, or with %s", scan.name, scan.flag)
	case *status != 0:
		return importRead{}, fmt.Errorf("the %s scan did not succeed (status %d). Draugr reads a "+
			"scan that succeeded. Run jf audit again", scan.name, *status)
	case len(doc.Errors) > 0:
		e := doc.Errors[0]
		what := "the scan"
		if e.FilePath != "" {
			what += " of " + e.FilePath
		}
		return importRead{}, fmt.Errorf("%s failed (%s), so findings may be missing from the file. Fix it and "+
			"run jf audit again", what, strings.TrimSpace(e.ErrorMessage))
	}
	if scan.rows != nil {
		return jfrogCodeImport(scan, scan.rows(&doc), ft)
	}

	rep := sarif.Report{Tool: jfrogTool, Rules: map[string]sarif.Rule{}}
	var rated []string
	seen := map[string]bool{}
	for _, v := range slices.Concat(doc.Vulnerabilities, doc.SecurityViolations) {
		found, err := jfrogResults(v)
		if err != nil {
			return importRead{}, err
		}
		for _, f := range found {
			key := strings.Join([]string{f.RuleID, f.Package.Name, f.Package.Version, f.Location.URI}, "\x00")
			if seen[key] {
				continue
			}
			seen[key] = true
			how := "Xray's severity"
			if f.Rating != nil && f.Rating.Detail == notScoredYet {
				how = "Xray states " + jfrogSeverityStated(v.Severity) + ", " + notScoredYet + ", read as high"
			}
			rep.Results = append(rep.Results, f)
			rated = append(rated, how)
			if _, ok := rep.Rules[f.RuleID]; !ok {
				rep.Rules[f.RuleID] = sarif.Rule{Name: f.RuleID, ShortDescription: v.Summary}
			}
		}
	}
	outside := relativeToCheckouts(rep.Results, checkoutRoots(ft.Repositories))

	var run importRun
	run.Tool.Driver = importDriver{Name: jfrogTool}
	run.Results = make([]json.RawMessage, len(rep.Results))
	return importRead{rep: rep, outside: outside, meta: importLog{Runs: []importRun{run}}, rated: rated}, nil
}

// jfrogSeverityStated is severity as the file states it, Unknown where it states none.
func jfrogSeverityStated(severity string) string {
	if severity == "" {
		return "Unknown"
	}
	return severity
}

// jfrogResults are the findings of one vulnerability, one in each manifest a direct dependency that
// brings the package in is declared in.
func jfrogResults(v jfrogVulnerability) ([]sarif.Result, error) {
	var files []string
	for _, c := range v.Components {
		if c.Location != nil && c.Location.File != "" && !slices.Contains(files, c.Location.File) {
			files = append(files, c.Location.File)
		}
	}
	if v.Name == "" || len(files) == 0 {
		return nil, errJFrogVulnerabilityIncomplete
	}
	stated := jfrogSeverityStated(v.Severity)
	band, known := jfrogSeverities[stated]
	if !known && stated != "Unknown" {
		return nil, fmt.Errorf("severity %q; Xray rates a vulnerability Critical, High, Medium, Low, "+
			"Information or Unknown. Import the file jf audit wrote, unedited", v.Severity)
	}

	var ids []string
	for _, c := range v.CVEs {
		ids = append(ids, c.ID)
	}
	if strings.HasPrefix(v.IssueID, "XRAY-") {
		ids = append(ids, v.IssueID)
	}
	ids = slices.DeleteFunc(ids, func(id string) bool { return id == "" })
	if len(ids) == 0 {
		return nil, errJFrogVulnerabilityIncomplete
	}
	own := ids[0]

	fixed, unread := jfrogFixedVersion(v.FixedVersions)
	pkg := sarif.Package{Name: v.Name, Version: v.Version, FixedVersion: fixed, Ecosystem: v.Type}
	if t := versionorder.PURLType(v.Type); (t == "npm" || t == "golang") && v.Version != "" {
		pkg.PURL = "pkg:" + t + "/" + gitlabPURLName(t, v.Name) + "@" + v.Version
	}
	osvGoVersion(&pkg)

	var detail []string
	if len(unread) > 0 {
		// A fix this does not read stays in front of the reader, beside "no fix available".
		detail = append(detail, "Xray lists the fixed versions as "+strings.Join(unread, ", ")+".")
	}
	if via := jfrogVia(v); via != "" {
		detail = append(detail, "Brought in by "+via+".")
	}
	if a := strings.TrimSpace(v.Applicable); a != "" {
		detail = append(detail, "JFrog's contextual analysis: "+a+".")
	}

	out := make([]sarif.Result, 0, len(files))
	for _, file := range files {
		p := pkg
		found := sarif.Result{
			Tool:     jfrogTool,
			RuleID:   own,
			Location: sarif.Location{URI: file},
			Aliases:  osvAliases(own, ids),
			Package:  &p,
			Message: trivyVulnMessage(trivyVuln{PkgName: p.Name, InstalledVersion: p.Version,
				FixedVersion: p.FixedVersion, Title: v.Summary}),
			Detail: strings.Join(detail, " "),
		}
		if known {
			found.Rating = newRating(band, map[string]string{"severity": stated}, "Xray "+stated)
			found.Level = osvLevel(band)
		} else {
			markNotScored(&found, map[string]string{"severity": stated}, found.Message)
		}
		out = append(out, found)
	}
	return out, nil
}

// jfrogExactVersion is a fixed version as Xray writes one, a range holding that version alone,
// "[4.17.19]".
var jfrogExactVersion = regexp.MustCompile(`^\[\s*([^\s,()\[\]]+)\s*\]$`)

// jfrogFixedVersion is the versions fixedVersions names as fixes, joined as Trivy joins several, and
// those it lists in a form this does not read.
func jfrogFixedVersion(listed []string) (fixed string, unread []string) {
	var versions []string
	for _, f := range listed {
		f = strings.TrimSpace(f)
		if m := jfrogExactVersion.FindStringSubmatch(f); m != nil {
			versions = append(versions, strings.TrimPrefix(m[1], "v"))
		} else if f != "" {
			unread = append(unread, f)
		}
	}
	return strings.Join(versions, ", "), unread
}

// jfrogVia names the direct dependencies that bring in a package that is not itself one.
func jfrogVia(v jfrogVulnerability) string {
	var via []string
	for _, c := range v.Components {
		if c.Name == "" || (c.Name == v.Name && c.Version == v.Version) {
			continue
		}
		if s := strings.TrimSpace(c.Name + " " + c.Version); !slices.Contains(via, s) {
			via = append(via, s)
		}
	}
	return strings.Join(via, ", ")
}

// errJFrogCodeIncomplete is the error of a code finding missing what the format needs to place and
// name it.
var errJFrogCodeIncomplete = errors.New("a finding names no rule or file, which every one jf audit " +
	"writes carries. Import the file jf audit wrote, unedited")

// jfrogCodeImport reads one code scan's findings, each at its file and line under JFrog's rule id,
// rated by the severity JFrog states. A finding a watch also raised as a violation is one finding.
func jfrogCodeImport(scan jfrogScan, rows []jfrogCodeRow, ft plugin.FileTarget) (importRead, error) {
	rep := sarif.Report{Tool: scan.tool, Rules: map[string]sarif.Rule{}}
	var rated []string
	seen := map[string]bool{}
	for _, row := range rows {
		file := strings.TrimSpace(strings.ReplaceAll(row.File, `\`, "/"))
		if row.RuleID == "" || file == "" {
			return importRead{}, errJFrogCodeIncomplete
		}
		key := fmt.Sprintf("%s\x00%s\x00%d\x00%d", row.RuleID, file, row.StartLine, row.StartColumn)
		if seen[key] {
			continue
		}
		seen[key] = true

		found := sarif.Result{
			Tool:     scan.tool,
			RuleID:   row.RuleID,
			Message:  cmp.Or(strings.TrimSpace(row.Finding), row.ScannerShortDescription, row.RuleID),
			Location: sarif.Location{URI: file, StartLine: max(row.StartLine, 0)},
			CWE:      jfrogCWEs(row.CWE),
		}
		if row.EndLine > row.StartLine {
			found.Location.EndLine = row.EndLine
		}
		if a := row.Applicability; a != nil && strings.TrimSpace(a.Status) != "" {
			// Whether the token is live is kept for the reader and changes no priority: a secret
			// JFrog could not confirm is still a secret in the repository.
			found.Detail = "JFrog's token validation: " + strings.TrimSpace(a.Status)
			if d := strings.TrimSpace(a.ScannerDescription); d != "" {
				found.Detail += " (" + d + ")"
			}
			found.Detail += "."
		}
		how, err := jfrogCodeRated(&found, row.Severity)
		if err != nil {
			return importRead{}, err
		}
		rep.Results = append(rep.Results, found)
		rated = append(rated, how)
		if _, ok := rep.Rules[row.RuleID]; !ok {
			rep.Rules[row.RuleID] = sarif.Rule{Name: row.RuleID, ShortDescription: row.ScannerShortDescription,
				FullDescription: strings.TrimSpace(row.ScannerDescription)}
		}
	}
	outside := relativeToCheckouts(rep.Results, checkoutRoots(ft.Repositories))

	var run importRun
	run.Tool.Driver = importDriver{Name: scan.tool}
	run.Results = make([]json.RawMessage, len(rep.Results))
	return importRead{rep: rep, outside: outside, meta: importLog{Runs: []importRun{run}}, rated: rated}, nil
}

// jfrogCodeRated rates a code finding by the severity JFrog states, and says how. A rule JFrog gives
// Unknown, or no severity, is one nobody rated, so it ranks high and says so.
func jfrogCodeRated(found *sarif.Result, severity string) (string, error) {
	stated := jfrogSeverityStated(severity)
	fields := map[string]string{"severity": stated}
	band, known := jfrogSeverities[stated]
	switch {
	case known:
		found.Rating = newRating(band, fields, "JFrog "+stated)
	case stated == "Unknown":
		found.Rating = newRating(sarif.SeverityHigh, fields, "JFrog states Unknown, not rated, so ranked high")
	default:
		return "", fmt.Errorf("severity %q; JFrog rates a finding Critical, High, Medium, Low, Information "+
			"or Unknown. Import the file jf audit wrote, unedited", severity)
	}
	found.Level = osvLevel(found.Rating.Severity)
	if !known {
		return "JFrog states Unknown, read as high", nil
	}
	return "JFrog's severity", nil
}

// jfrogCWEs are the CWEs JFrog lists on a SAST finding, written "73" or "CWE-73", as CWE-73.
func jfrogCWEs(listed []string) []string {
	var out []string
	for _, c := range listed {
		c = strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(c)), "CWE-")
		if n, err := strconv.Atoi(c); err == nil && n > 0 && !slices.Contains(out, "CWE-"+strconv.Itoa(n)) {
			out = append(out, "CWE-"+strconv.Itoa(n))
		}
	}
	return out
}
