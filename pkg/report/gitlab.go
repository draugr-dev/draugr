package report

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// GitLab reads its own schema, not SARIF. There is no upload endpoint either: a job declares
// `artifacts: reports: <type>: <file>` and the runner collects it, so what GitLab needs from
// Draugr is a report format rather than a publisher.
//
// gitlabSchemaVersion is the security report schema these documents declare. GitLab validates
// against it and rejects a document whose version it does not know, so this moves deliberately —
// see pkg/report/testdata/gitlab, which holds the schemas the tests check against.
const gitlabSchemaVersion = "15.2.4"

// gitlabSecurityReporter renders one of GitLab's typed security reports.
//
// Typed, because GitLab routes findings by the report they arrive in: its deduplication, its
// merge-request widget and its approval policies all key on the scan type. A dependency CVE filed
// as `sast` is a finding in the wrong drawer, and the drawer is what a policy looks in.
//
// Only the types Draugr can fill honestly are registered. `container_scanning` requires an image
// and an operating system on every finding, which Draugr's image findings do not yet carry as
// fields — so it is absent, and `gitlab-codequality` carries those findings in the meantime. A
// schema's required field filled with a guess is worse than a report that does not exist.
type gitlabSecurityReporter struct {
	format   string
	scanType string
	// controls are the Draugr controls whose findings belong in this report.
	controls []string
	// needsCommit marks a report whose schema requires the scanned commit on every finding.
	needsCommit bool
	// needsPackage marks a report whose schema requires a structured package on every finding.
	needsPackage bool
}

func (r gitlabSecurityReporter) Format() string { return r.format }

type glReport struct {
	Version         string   `json:"version"`
	Scan            glScan   `json:"scan"`
	Vulnerabilities []glVuln `json:"vulnerabilities"`
}

type glScan struct {
	Analyzer  glScanner `json:"analyzer"`
	Scanner   glScanner `json:"scanner"`
	Type      string    `json:"type"`
	StartTime string    `json:"start_time"`
	EndTime   string    `json:"end_time"`
	Status    string    `json:"status"`
}

type glScanner struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Version string   `json:"version"`
	Vendor  glVendor `json:"vendor"`
}

type glVendor struct {
	Name string `json:"name"`
}

type glVuln struct {
	ID          string         `json:"id"`
	Name        string         `json:"name,omitempty"`
	Description string         `json:"description,omitempty"`
	Severity    string         `json:"severity,omitempty"`
	Identifiers []glIdentifier `json:"identifiers"`
	Location    glLocation     `json:"location"`
	Links       []glLink       `json:"links,omitempty"`
}

type glIdentifier struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
	URL   string `json:"url,omitempty"`
}

type glLocation struct {
	File       string        `json:"file,omitempty"`
	StartLine  int           `json:"start_line,omitempty"`
	Commit     *glCommit     `json:"commit,omitempty"`
	Dependency *glDependency `json:"dependency,omitempty"`
}

// glDependency is what GitLab's dependency_scanning schema requires of every finding: which
// package, at which version.
type glDependency struct {
	Package glDependencyPackage `json:"package"`
	Version string              `json:"version"`
}

type glDependencyPackage struct {
	Name string `json:"name"`
}

type glCommit struct {
	SHA string `json:"sha"`
}

type glLink struct {
	URL string `json:"url"`
}

func (r gitlabSecurityReporter) Render(w io.Writer, d Data) error {
	vulns, err := r.vulnerabilities(d)
	if err != nil {
		return err
	}
	end := d.Generated
	if end.IsZero() {
		end = time.Now()
	}
	who := gitlabScanner(d)
	doc := glReport{
		Version: gitlabSchemaVersion,
		Scan: glScan{
			Analyzer: who, Scanner: who, Type: r.scanType,
			StartTime: gitlabTime(end.Add(-d.Run.Stats.Duration)),
			EndTime:   gitlabTime(end),
			Status:    gitlabScanStatus(d),
		},
		Vulnerabilities: vulns,
	}
	return writeJSON(w, doc)
}

// vulnerabilities collects this report's controls, most-urgent first.
func (r gitlabSecurityReporter) vulnerabilities(d Data) ([]glVuln, error) {
	out := []glVuln{}
	for _, f := range gitlabFindings(d, r.controls) {
		v := glVuln{
			ID:          f.res.Fingerprint(),
			Name:        f.res.RuleID,
			Description: f.res.Message,
			Severity:    gitlabSeverity(f.res.Severity("")),
			Identifiers: []glIdentifier{gitlabIdentifier(f.res, f.helpURI)},
			Location: glLocation{
				File:      f.res.Location.URI,
				StartLine: f.res.Location.StartLine,
			},
		}
		if r.needsPackage {
			// The schema requires the package, and a finding without one is not a dependency
			// finding — a control reporting both would otherwise contribute rows GitLab rejects
			// the whole document over.
			if f.res.Package == nil || f.res.Package.Name == "" {
				continue
			}
			v.Location.Dependency = &glDependency{
				Package: glDependencyPackage{Name: f.res.Package.Name},
				Version: f.res.Package.Version,
			}
			// A line number means nothing for a package declared in a manifest, and GitLab renders
			// it as a position in a file where the package may sit on another line entirely.
			v.Location.StartLine = 0
		}
		if f.helpURI != "" {
			v.Links = []glLink{{URL: f.helpURI}}
		}
		if r.needsCommit {
			// The schema requires it, so a document without it is not one GitLab will read. Saying
			// that beats writing a placeholder into an artifact somebody treats as a record.
			sha := gitlabCommitFor(d, f.res.Repository)
			if sha == "" {
				return nil, fmt.Errorf(
					"%s needs the commit each finding was found at, and this run recorded none "+
						"(git could not be asked); use --report gitlab-codequality instead", r.format)
			}
			v.Location.Commit = &glCommit{SHA: sha}
		}
		out = append(out, v)
	}
	return out, nil
}

// glFinding pairs a result with the rule documentation its own report carries.
type glFinding struct {
	res     sarif.Result
	helpURI string
}

// gitlabFindings returns the active findings of the named controls, most-urgent first.
//
// Suppressed findings are left out. GitLab has no notion of a finding somebody already decided to
// accept — it would show one as open and wait to be dismissed, which asks for the decision the Saga
// already records, with the reason and the person attached. They remain in Draugr's own report,
// marked, which is where that evidence belongs.
func gitlabFindings(d Data, controls []string) []glFinding {
	want := map[string]bool{}
	for _, c := range controls {
		want[c] = true
	}
	names := make([]string, 0, len(d.Run.Controls))
	for name := range d.Run.Controls {
		if want[name] || len(controls) == 0 {
			names = append(names, name)
		}
	}
	sort.Strings(names)

	var out []glFinding
	for _, name := range names {
		rep := d.Run.Controls[name].Report
		for _, res := range rep.Results {
			if res.Suppressed() {
				continue
			}
			out = append(out, glFinding{res: res, helpURI: rep.HelpURI(res.RuleID)})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return gitlabRank(out[i].res) > gitlabRank(out[j].res)
	})
	return out
}

// gitlabRank orders findings by priority first, then severity — the order Draugr ranks in, kept so
// a truncated read of either report starts at the same place the console does.
func gitlabRank(res sarif.Result) int {
	band := map[string]int{"P1": 4, "P2": 3, "P3": 2, "P4": 1}[res.Priority]
	return band*10 + res.Severity("").Rank()
}

var cveID = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

// gitlabIdentifier describes what was found in the vocabulary GitLab deduplicates on.
//
// A CVE is named as one, because GitLab correlates its own findings and everyone else's through
// that identifier and a rule reported under a private type is a second copy of the same
// vulnerability. Anything else is typed by the tool that raised it, which is true and does not
// claim a shared namespace the rule is not in.
func gitlabIdentifier(res sarif.Result, helpURI string) glIdentifier {
	id := glIdentifier{Type: strings.ToLower(res.Tool), Name: res.RuleID, Value: res.RuleID, URL: helpURI}
	switch {
	case cveID.MatchString(res.RuleID):
		id.Type = "cve"
	case strings.HasPrefix(res.RuleID, "GHSA-"):
		id.Type = "ghsa"
	case id.Type == "":
		id.Type = "draugr"
	}
	return id
}

// gitlabSeverity maps Draugr's severity ladder onto GitLab's.
//
// The flaw's severity, not its Draugr priority. GitLab's merge-request approval policies gate on
// this field, and a priority has already folded in the component's exposure and criticality —
// feeding it here would have those policies apply that context a second time.
func gitlabSeverity(s sarif.Severity) string {
	switch s {
	case sarif.SeverityCritical:
		return "Critical"
	case sarif.SeverityHigh:
		return "High"
	case sarif.SeverityMedium:
		return "Medium"
	case sarif.SeverityLow:
		return "Low"
	default:
		return "Unknown"
	}
}

// gitlabScanStatus reports whether the run completed.
//
// A control whose scanner never ran found nothing because it looked at nothing, and a report that
// called that success would be a clean bill of health for a scan that did not happen.
func gitlabScanStatus(d Data) string {
	if len(d.Run.ScanErrors) > 0 || len(erroredControls(d)) > 0 {
		return "failure"
	}
	return "success"
}

func gitlabScanner(d Data) glScanner {
	version := d.Version
	if version == "" {
		version = "unknown"
	}
	return glScanner{
		ID: "draugr", Name: "Draugr", Version: version,
		Vendor: glVendor{Name: "Draugr"},
	}
}

// gitlabTime renders a timestamp the way GitLab's schema expects: local, without a zone.
func gitlabTime(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05") }

// gitlabCommitFor finds the commit a finding's repository was read at.
//
// Falls back to the only repository when the finding names none — with one repository there is no
// ambiguity, and with several a finding that names none did not come from a checkout.
func gitlabCommitFor(d Data, repository string) string {
	if repository == "" && len(d.Repositories) == 1 {
		return d.Repositories[0].Revision
	}
	for _, r := range d.Repositories {
		if sarif.SameRepository(r.URL, repository) {
			return r.Revision
		}
	}
	return ""
}

// gitlabCodeQualityReporter renders GitLab's Code Quality report.
//
// The one GitLab surface that works on every tier: the Vulnerability Report and the merge-request
// security widget are Ultimate, and Code Quality shows in the merge request's Reports tab whatever
// the plan. So this carries **every** finding regardless of control — including the ones no typed
// security report can hold — and is the reason nothing Draugr finds is invisible on a Free project.
type gitlabCodeQualityReporter struct{}

func (gitlabCodeQualityReporter) Format() string { return "gitlab-codequality" }

type glCodeQuality struct {
	Description string    `json:"description"`
	CheckName   string    `json:"check_name"`
	Fingerprint string    `json:"fingerprint"`
	Severity    string    `json:"severity"`
	Location    glCQPlace `json:"location"`
}

type glCQPlace struct {
	Path  string   `json:"path"`
	Lines glCQLine `json:"lines"`
}

type glCQLine struct {
	Begin int `json:"begin"`
}

func (gitlabCodeQualityReporter) Render(w io.Writer, d Data) error {
	out := []glCodeQuality{}
	for _, f := range gitlabFindings(d, nil) {
		out = append(out, glCodeQuality{
			Description: gitlabCodeQualityDescription(f.res),
			CheckName:   f.res.RuleID,
			Fingerprint: f.res.Fingerprint(),
			Severity:    gitlabCodeQualitySeverity(f.res.Priority),
			Location: glCQPlace{
				Path:  f.res.Location.URI,
				Lines: glCQLine{Begin: max(f.res.Location.StartLine, 1)},
			},
		})
	}
	return writeJSON(w, out)
}

// gitlabCodeQualitySeverity maps Draugr's priority onto Code Quality's ladder.
//
// Priority here, not severity — the opposite of the security reports, and for the reason those use
// severity. Code Quality has no policy engine behind it; it is a list a reviewer reads in order,
// and the order worth reading is the one that already accounts for what the component is exposed to
// and how much it matters. The flaw's own severity is kept in the description, so nothing is lost.
func gitlabCodeQualitySeverity(priority string) string {
	switch priority {
	case "P1":
		return "blocker"
	case "P2":
		return "critical"
	case "P3":
		return "major"
	case "P4":
		return "minor"
	default:
		return "info"
	}
}

// gitlabCodeQualityDescription is the one line a reviewer reads in the widget, so it leads with
// what was found and keeps the severity the priority was computed from.
func gitlabCodeQualityDescription(res sarif.Result) string {
	parts := []string{}
	if sev := res.Severity(""); sev != "" {
		parts = append(parts, strings.ToUpper(string(sev)))
	}
	if res.Message != "" {
		parts = append(parts, firstLine(res.Message))
	} else {
		parts = append(parts, res.RuleID)
	}
	return strings.Join(parts, ": ")
}

// firstLine keeps a description to one line. Several scanners relay a paragraph, and the widget
// renders it in a table cell.
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}
