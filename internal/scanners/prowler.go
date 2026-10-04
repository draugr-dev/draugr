package scanners

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/draugr-dev/draugr/internal/english"
	"github.com/draugr-dev/draugr/internal/gcpaccess"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// prowlerScannerName identifies the scanner behind the "cloud" control.
const prowlerScannerName = "prowler"

// prowlerRulePrefix namespaces Prowler's check identifiers among every other scanner's rules.
const prowlerRulePrefix = "prowler/"

// prowlerDefaultCompliance is the framework a Google Cloud account is checked against: the newest
// CIS Google Cloud Platform Foundation Benchmark Prowler maps.
const prowlerDefaultCompliance = "cis_5.0_gcp"

// prowlerConfigSchema is the JSON Schema for the scanner's Saga config.
const prowlerConfigSchema = `{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "compliance": {
      "type": "string",
      "pattern": "^(.*\\$\\{\\{.*\\}\\}.*|[a-z0-9_.]+_gcp)$",
      "description": "The Prowler compliance framework to run, such as cis_4.0_gcp. Defaults to cis_5.0_gcp. ` +
	"`prowler gcp --list-compliance`" + ` lists them."
    }
  }
}`

// permissionTester asks which permissions the credentials hold on a project.
type permissionTester interface {
	Granted(ctx context.Context, project string, perms []string) ([]string, error)
}

// prowlerScanner checks a live cloud account by running Prowler against it.
//
// Prowler is the operator's to install: Draugr runs the `prowler` on PATH, and `draugr tools
// install` does not fetch it.
// Before it runs, the scanner asks the provider which of the permissions Prowler's checks read the
// credentials hold, because a denied read is the one failure Prowler does not report. Depending
// on the check it passes, fails or disappears. A check that reads a service the credentials cannot
// is reported unread rather than taken from Prowler's output either way.
type prowlerScanner struct {
	info   plugin.ScannerInfo
	run    func(ctx context.Context, argv []string) ([]byte, error)
	access func(ctx context.Context) (permissionTester, error)
}

// NewProwler returns the scanner for the "cloud" control.
func NewProwler() plugin.Scanner {
	return prowlerScanner{
		info: plugin.ScannerInfo{
			Name:         prowlerScannerName,
			Origin:       "prowler-cloud",
			Binary:       "prowler",
			Controls:     []string{"cloud"},
			TargetKinds:  []plugin.TargetKind{plugin.TargetAccount},
			ConfigSchema: json.RawMessage(prowlerConfigSchema),
		},
		run: execArgv,
		access: func(ctx context.Context) (permissionTester, error) {
			return gcpaccess.New(ctx)
		},
	}
}

// Info describes the scanner.
func (s prowlerScanner) Info() plugin.ScannerInfo { return s.info }

// CacheVersion reports Prowler's version (implements plugin.CacheVersioner). The checks and what
// they read travel with the release, so a cached answer from another one answers another question.
func (s prowlerScanner) CacheVersion(ctx context.Context) string {
	if v := sharedProwlerVersion.version(ctx); v != "" {
		return "prowler@" + v
	}
	return ""
}

// Scan checks the account the target names and converts Prowler's findings to SARIF.
func (s prowlerScanner) Scan(ctx context.Context, target plugin.Target, cfg plugin.Config) (sarif.Report, error) {
	account, ok := target.(plugin.AccountTarget)
	if !ok {
		return sarif.Report{}, fmt.Errorf("prowler: unsupported target %T (want a cloud account)", target)
	}
	if account.Provider != "gcp" {
		return sarif.Report{}, fmt.Errorf("prowler: Draugr checks Google Cloud accounts, not %q", account.Provider)
	}
	compliance := prowlerDefaultCompliance
	if v, _ := cfg["compliance"].(string); v != "" {
		compliance = v
	}

	// The check list first: it needs only Prowler, so a machine without it is told that before
	// anything about its credentials.
	checks, err := s.frameworkChecks(ctx, compliance)
	if err != nil {
		return sarif.Report{}, err
	}
	denied, err := s.preflight(ctx, account.ID)
	if err != nil {
		return sarif.Report{}, err
	}

	dir, err := os.MkdirTemp("", "draugr-prowler-")
	if err != nil {
		return sarif.Report{}, fmt.Errorf("prowler: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	argv := []string{
		"prowler", "gcp", "--project-id", account.ID, "--compliance", compliance,
		"--output-formats", "json-ocsf", "--output-directory", dir, "--output-filename", "scan",
		"--log-level", "ERROR", "--log-file", filepath.Join(dir, "prowler.log"), "--only-logs",
		"--no-color",
		// Exit 3 means "found something". Findings are the report's to judge, not an error.
		"--ignore-exit-code-3",
	}
	if _, err := s.run(ctx, argv); err != nil {
		return sarif.Report{}, fmt.Errorf("run prowler: %w", err)
	}
	findings, err := readOCSF(filepath.Join(dir, "scan.ocsf.json"))
	if err != nil {
		return sarif.Report{}, err
	}
	// Prowler reports a passed check as a finding too, so a run with none decided nothing: an
	// account with nothing at all to check still has an IAM policy and audit settings. A changed
	// output name or a run that stopped early lands here, and must not read as a clean account.
	if len(findings) == 0 && len(checks) > 0 {
		return sarif.Report{}, fmt.Errorf("prowler: no result for any of the %d %s checks on project %s",
			len(checks), compliance, account.ID)
	}
	// The log is the backstop: a read the preflight could not foresee, denied mid-scan.
	logged, above := loggedDenials(filepath.Join(dir, "prowler.log"))
	for service, reason := range logged {
		if _, known := denied[service]; !known {
			denied[service] = reason
		}
	}
	report := prowlerReport(account, compliance, checks, findings, denied)
	if len(above) > 0 {
		report.Provenance[0].Fields = append(report.Provenance[0].Fields,
			sarif.Field{Key: "organization", Value: "not read, " + strings.Join(above, ", ")})
	}
	return report, nil
}

// preflight asks which services' reads the credentials are denied, by service, with the first
// missing permission. Credentials that cannot read the project at all are an error: the account
// is a target the run did not reach, not one with some checks unread.
func (s prowlerScanner) preflight(ctx context.Context, project string) (map[string]string, error) {
	tester, err := s.access(ctx)
	if err != nil {
		return nil, fmt.Errorf("prowler: %w", err)
	}
	granted, err := tester.Granted(ctx, project, gcpPermissions())
	if err != nil {
		return nil, fmt.Errorf("prowler: %w", err)
	}
	if len(granted) == 0 {
		return nil, fmt.Errorf("prowler: the credentials hold none of the permissions the checks read "+
			"on project %s; grant roles/viewer and roles/serviceusage.serviceUsageConsumer", project)
	}
	return deniedServices(granted), nil
}

// frameworkChecks lists the checks the framework maps, from the installed Prowler, so the count of
// what was decided is out of the checks this release runs.
func (s prowlerScanner) frameworkChecks(ctx context.Context, compliance string) ([]string, error) {
	out, err := s.run(ctx, []string{"prowler", "gcp", "--list-checks-json", "--compliance", compliance})
	if err != nil {
		return nil, fmt.Errorf("run prowler: list the checks of %s: %w", compliance, err)
	}
	var listed map[string][]string
	if err := json.Unmarshal(lastJSON(out), &listed); err != nil {
		return nil, fmt.Errorf("prowler: unreadable check list for %s: %w", compliance, err)
	}
	checks := listed["gcp"]
	if len(checks) == 0 {
		return nil, fmt.Errorf("prowler: compliance framework %s maps no Google Cloud checks; "+
			"`prowler gcp --list-compliance` lists the ones that do", compliance)
	}
	slices.Sort(checks)
	return checks, nil
}

// lastJSON is the JSON object at the end of a tool's output, past any line it printed first.
func lastJSON(out []byte) []byte {
	if i := bytes.IndexByte(out, '{'); i >= 0 {
		return out[i:]
	}
	return out
}

// ocsfFinding is the part of a Prowler OCSF finding Draugr reads. `resources[].data` is never
// read: it carries what a service returned, which includes secrets such as function keys.
type ocsfFinding struct {
	Message      string `json:"message"`
	Severity     string `json:"severity"`
	StatusCode   string `json:"status_code"`
	StatusDetail string `json:"status_detail"`
	Metadata     struct {
		EventCode string `json:"event_code"`
	} `json:"metadata"`
	FindingInfo struct {
		Title string `json:"title"`
		Desc  string `json:"desc"`
	} `json:"finding_info"`
	Resources []struct {
		UID    string `json:"uid"`
		Name   string `json:"name"`
		Region string `json:"region"`
	} `json:"resources"`
	Remediation struct {
		Desc       string   `json:"desc"`
		References []string `json:"references"`
	} `json:"remediation"`
	Unmapped struct {
		Compliance map[string][]string `json:"compliance"`
	} `json:"unmapped"`
}

// readOCSF reads Prowler's findings. No file is no findings, which Scan judges against the checks
// it asked for.
func readOCSF(path string) ([]ocsfFinding, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- a file Prowler wrote into a directory this scan made
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("prowler: %w", err)
	}
	var out []ocsfFinding
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("prowler: unreadable findings: %w", err)
	}
	return out, nil
}

// denialRE finds a permission failure in Prowler's log, and apiRE the Google API it was calling.
var (
	denialRE = regexp.MustCompile(`(?i)\b403\b|PERMISSION_DENIED|permission denied|does not have .*permission`)
	apiRE    = regexp.MustCompile(`https://([a-z]+)\.googleapis\.com|services/([a-z]+)\.googleapis\.com`)
	moduleRE = regexp.MustCompile(`"module":\s*"([a-z]+)_service"`)
	// permissionRE is the permission a Google error names: "Permission 'logging.sinks.list' denied".
	permissionRE = regexp.MustCompile(`Permission '([a-zA-Z0-9_.]+)' denied`)
	// aboveRE is a request against the organization or a folder rather than the project.
	aboveRE = regexp.MustCompile(`googleapis\.com/(?:v[0-9a-z]+/)?(?:organizations|folders)/`)
)

// loggedDenials reads Prowler's log for permission failures: within the project, the services
// they leave unread, each with the denied permission where the log names it; above it, the
// permissions denied on the organization or a folder.
//
// Prowler also reads organization settings, log sinks and essential contacts, where the
// credentials reach that far. Those are outside the account the descriptor declares, so a denial
// there leaves no project check unread; it is reported as what the scan could not see rather than
// discarded.
//
// The log is one JSON object a line, written from a template that does not escape the message, so
// it is read with patterns rather than decoded.
func loggedDenials(path string) (project map[string]string, above []string) {
	project = map[string]string{}
	f, err := os.Open(path) // #nosec G304 -- a file Prowler wrote into a directory this scan made
	if err != nil {
		return project, nil
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
	for sc.Scan() {
		line := sc.Text()
		if !denialRE.MatchString(line) {
			continue
		}
		reason := "denied a permission Prowler's log does not name"
		if m := permissionRE.FindStringSubmatch(line); m != nil {
			reason = "denied " + m[1]
		}
		if aboveRE.MatchString(line) {
			if !slices.Contains(above, reason) {
				above = append(above, reason)
			}
			continue
		}
		for _, service := range deniedIn(line) {
			if _, seen := project[service]; !seen {
				project[service] = reason
			}
		}
	}
	slices.Sort(above)
	return project, above
}

// deniedIn names the services a denial line is about: the API whose service-usage entry it asked
// for, else the API it called, else the module that logged it.
func deniedIn(line string) []string {
	if m := apiRE.FindAllStringSubmatch(line, -1); m != nil {
		// A services/<api>.googleapis.com path names the service being gated, which is more
		// specific than the Service Usage host the request went to.
		for _, sub := range m {
			if sub[2] != "" {
				if s, ok := gcpAPIService[sub[2]]; ok {
					return []string{s}
				}
			}
		}
		for _, sub := range m {
			if s, ok := gcpAPIService[sub[1]]; ok {
				return []string{s}
			}
		}
	}
	if m := moduleRE.FindStringSubmatch(line); m != nil {
		// iam_service.py holds three clients, so a denial it logs leaves all three in doubt.
		if m[1] == "iam" {
			return []string{"iam", "accessapproval", "essentialcontacts"}
		}
		if _, ok := gcpServiceReads[m[1]]; ok {
			return []string{m[1]}
		}
	}
	return nil
}

// prowlerReport turns Prowler's findings into SARIF, setting aside every check a denied service
// leaves unread.
func prowlerReport(account plugin.AccountTarget, compliance string, checks []string, findings []ocsfFinding,
	denied map[string]string,
) sarif.Report {
	report := sarif.Report{Tool: prowlerScannerName, Rules: map[string]sarif.Rule{}}
	unread := map[string]bool{}
	for _, check := range checks {
		for _, service := range checkReads(check) {
			if reason, ok := denied[service]; ok {
				unread[check] = true
				report.Unchecked = append(report.Unchecked, sarif.Unchecked{
					Scanner: prowlerScannerName, Check: check, Group: service, Reason: reason,
				})
				break
			}
		}
	}
	inFramework := map[string]bool{}
	for _, c := range checks {
		inFramework[c] = true
	}
	taxonomy, version := cisTaxonomy(compliance)
	decided := map[string]bool{}
	for _, f := range findings {
		check := f.Metadata.EventCode
		if unread[check] || !inFramework[check] {
			continue
		}
		status := strings.ToUpper(f.StatusCode)
		if status == "PASS" || status == "FAIL" {
			decided[check] = true
		}
		if status != "FAIL" || !inRegions(f, account.Regions) {
			continue
		}
		level, score := prowlerSeverity(f.Severity)
		ruleID := prowlerRulePrefix + check
		uri := prowlerLocation(account, f)
		report.Results = append(report.Results, sarif.Result{
			Tool:     prowlerScannerName,
			RuleID:   ruleID,
			Level:    level,
			Score:    score,
			HasScore: true,
			Message:  firstNonEmpty(f.StatusDetail, f.Message),
			Location: sarif.Location{URI: uri},
		})
		rule := sarif.Rule{
			Name:             f.FindingInfo.Title,
			ShortDescription: f.FindingInfo.Title,
			FullDescription:  strings.TrimSpace(f.Remediation.Desc),
		}
		if len(f.Remediation.References) > 0 {
			rule.HelpURI = f.Remediation.References[0]
		}
		for _, id := range f.Unmapped.Compliance[taxonomy] {
			rule.Taxa = append(rule.Taxa, sarif.Taxon{Taxonomy: cisGCPTaxonomy, ID: id, Version: version})
		}
		report.Rules[ruleID] = rule
	}
	for check := range decided {
		report.Decided = append(report.Decided, sarif.Taxon{Taxonomy: prowlerScannerName, ID: check})
	}
	slices.SortFunc(report.Decided, func(a, b sarif.Taxon) int { return strings.Compare(a.ID, b.ID) })
	scope := "whole account"
	if len(account.Regions) > 0 {
		scope = english.Count(len(account.Regions), "region") + " " + strings.Join(account.Regions, ", ")
	}
	report.Provenance = []sarif.Provenance{{
		Tool: prowlerScannerName,
		Fields: []sarif.Field{
			{Key: "benchmark", Value: compliance},
			{Key: "coverage", Value: fmt.Sprintf("%d of %d checks decided", len(decided), len(checks))},
			{Key: "scope", Value: scope},
		},
	}}
	return report
}

// prowlerLocation is where a finding is: the account for a finding about the project itself,
// otherwise the resource's path when Prowler gives one, and its identifier when it does not. A
// project's name is its display name, "draugr cloud fixture", which locates nothing.
func prowlerLocation(account plugin.AccountTarget, f ocsfFinding) string {
	if len(f.Resources) > 0 {
		r := f.Resources[0]
		switch {
		case r.UID == account.ID || (r.UID == "" && r.Name == ""):
		case strings.Contains(r.Name, "/"):
			return r.Name
		case r.UID == "" || allDigits(r.UID):
			// A numeric ID names a resource to an API and to nobody reading a report.
			return r.Name
		default:
			return r.UID
		}
	}
	return account.Provider + "/" + account.ID
}

func allDigits(s string) bool {
	return s != "" && strings.Trim(s, "0123456789") == ""
}

// cisGCPTaxonomy names the benchmark a check's requirement belongs to.
const cisGCPTaxonomy = "CIS Google Cloud Platform Foundation Benchmark"

// cisTaxonomy is the key Prowler files a framework's requirement IDs under in a finding, and the
// framework's version: "CIS-5.0" and "5.0" for cis_5.0_gcp.
func cisTaxonomy(compliance string) (key, version string) {
	parts := strings.Split(compliance, "_")
	if len(parts) < 2 || parts[0] != "cis" {
		return "", ""
	}
	return "CIS-" + parts[1], parts[1]
}

// inRegions reports whether a finding belongs to a component claiming regions: every finding when
// it claims the whole account, and only those in a claimed region, or a zone of one, when it
// narrows. A finding with no region, or a global or multi-region one, is the whole account's.
func inRegions(f ocsfFinding, regions []string) bool {
	if len(regions) == 0 {
		return true
	}
	if len(f.Resources) == 0 {
		return false
	}
	at := strings.ToLower(f.Resources[0].Region)
	for _, r := range regions {
		r = strings.ToLower(r)
		if at == r || strings.HasPrefix(at, r+"-") {
			return true
		}
	}
	return false
}

// prowlerSeverity maps Prowler's severity to a SARIF level and the score other configuration
// scanners give the same severity.
func prowlerSeverity(severity string) (sarif.Level, float64) {
	switch strings.ToLower(severity) {
	case "critical":
		return sarif.LevelError, 9.5
	case "high":
		return sarif.LevelError, 8.0
	case "medium":
		return sarif.LevelWarning, 5.5
	case "low":
		return sarif.LevelNote, 2.0
	}
	return sarif.LevelNote, 0
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
