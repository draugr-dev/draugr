package scanners

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/draugr-dev/draugr/internal/awsaccess"
	"github.com/draugr-dev/draugr/internal/english"
	"github.com/draugr-dev/draugr/internal/gcpaccess"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// prowlerScannerName identifies the scanner behind the "cloud" control.
const prowlerScannerName = "prowler"

// prowlerRulePrefix namespaces Prowler's check identifiers among every other scanner's rules.
const prowlerRulePrefix = "prowler/"

// prowlerCloud is what differs between the clouds Prowler checks.
type prowlerCloud struct {
	// name is Prowler's word for the cloud: its subcommand, the suffix of its frameworks and the
	// key of its check list.
	name string
	// label is the cloud's name in a message.
	label string
	// unit is what the cloud calls an account.
	unit string
	// compliance is the framework an account is checked against unless `compliance` names another
	// of the same cloud's: the newest CIS foundations benchmark Prowler maps.
	compliance string
	// taxonomy names the benchmark a check's requirement belongs to.
	taxonomy string
	// reads lists the services a check reads, where that is more than, or other than, the service
	// its name starts with.
	reads map[string][]string
	// keepsPartlyRead says a check with results keeps them when a service it reads had a denial,
	// marked partly read. Otherwise every check of a denied service is unread and its results
	// discarded.
	keepsPartlyRead bool
}

// prowlerClouds are the clouds the scanner checks, by the descriptor's `provider:`.
//
// The two clouds treat a denied service differently because their denials differ in reach. A
// Google Cloud permission is checked on the project, so one missing denies the service's every
// read. An AWS denial is of one action, often on one resource, which some checks of the service do
// not need, and setting aside every check of the service would set aside real findings: on a
// read-only role against CIS 7.0, most of the framework.
var prowlerClouds = map[string]prowlerCloud{
	"gcp": {name: "gcp", label: "Google Cloud", unit: "project", compliance: "cis_5.0_gcp",
		taxonomy: "CIS Google Cloud Platform Foundation Benchmark", reads: gcpCheckReads},
	"aws": {name: "aws", label: "AWS", unit: "account", compliance: "cis_7.0_aws",
		taxonomy: "CIS Amazon Web Services Foundations Benchmark", reads: awsCheckReads, keepsPartlyRead: true},
}

// checkReads is the services a check reads.
func (c prowlerCloud) checkReads(check string) []string {
	if reads, ok := c.reads[check]; ok {
		return reads
	}
	service, _, _ := strings.Cut(check, "_")
	return []string{service}
}

// prowlerConfigSchema is the JSON Schema for the scanner's Saga config.
const prowlerConfigSchema = `{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "compliance": {
      "type": "string",
      "pattern": "^(.*\\$\\{\\{.*\\}\\}.*|[a-z0-9_.]+_(gcp|aws))$",
      "description": "The Prowler compliance framework to run, such as cis_4.0_gcp or cis_6.0_aws. It applies to the accounts of the cloud its suffix names; the others are checked against cis_5.0_gcp on Google Cloud and cis_7.0_aws on AWS. ` +
	"`prowler <gcp|aws> --list-compliance`" + ` lists them."
    }
  }
}`

// framework is the compliance framework an account is checked against: the configured one when it
// is the account's cloud's, the cloud's default otherwise.
func (c prowlerCloud) framework(cfg plugin.Config) string {
	if v, _ := cfg["compliance"].(string); strings.HasSuffix(v, "_"+c.name) {
		return v
	}
	return c.compliance
}

// permissionTester asks which permissions the credentials hold on a project.
type permissionTester interface {
	Granted(ctx context.Context, project string, perms []string) ([]string, error)
}

// prowlerMutelist replaces the mutelist Prowler applies when given none, which mutes the resources
// AWS Control Tower creates. A muted finding never reaches the report, and Draugr's own excludes
// are where a finding is suppressed, with a reason somebody gave.
const prowlerMutelist = "Mutelist: {}\n"

// prowlerScanner checks a live cloud account by running Prowler against it.
//
// Prowler is the operator's to install: Draugr runs the `prowler` on PATH, and `draugr tools
// install` does not fetch it.
// On Google Cloud, before it runs, the scanner asks the provider which of the permissions Prowler's
// checks read the credentials hold, because a denied read is the one failure Prowler does not
// report. Depending on the check it passes, fails or disappears. A check that reads a service the
// credentials cannot is reported unread rather than taken from Prowler's output either way.
//
// On AWS, before it runs, the scanner asks STS which identity the credentials are and refuses one in
// another account, then asks IAM's policy simulator which of the actions Prowler's services call
// the identity's policies allow. A read-only role may not ask that, and then Prowler's log alone
// says what was denied. A check of a denied service with no result is unread; one with results
// keeps them and is marked partly read.
type prowlerScanner struct {
	info     plugin.ScannerInfo
	run      func(ctx context.Context, argv []string) ([]byte, error)
	access   func(ctx context.Context) (permissionTester, error)
	identify func(ctx context.Context) (awsaccess.Identifier, error)
	simulate func(ctx context.Context) (awsaccess.Simulator, error)
}

// prowlerData is what Prowler contacts besides the APIs of the account it checks. None of it is in
// a CIS framework's checks, so a scan against the default frameworks contacts the cloud's APIs
// alone; a `compliance` framework that includes the checks below contacts these too.
var prowlerData = []plugin.DataSource{
	{
		// codepipeline_project_repo_private asks, without credentials, whether a pipeline's source
		// repository answers to anybody.
		Name:    "AWS CodePipeline source repositories, outside the CIS checks",
		Hosts:   []string{"github.com", "gitlab.com"},
		PerScan: true,
	},
	{
		// route53_dangling_ip_subdomain_takeover compares records with the addresses AWS owns.
		Name:    "AWS IP address ranges, outside the CIS checks",
		Hosts:   []string{"ip-ranges.amazonaws.com"},
		PerScan: true,
	},
	{
		// The Lambda and ECR checks that read code or image layers follow the presigned link the API
		// returns, to a bucket AWS runs in the function's or repository's region.
		Name:    "AWS Lambda code and ECR image layers, outside the CIS checks",
		Hosts:   []string{"*.s3.<region>.amazonaws.com"},
		PerScan: true,
	},
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
			Data:         prowlerData,
		},
		run: execArgv,
		access: func(ctx context.Context) (permissionTester, error) {
			return gcpaccess.New(ctx)
		},
		identify: func(ctx context.Context) (awsaccess.Identifier, error) {
			return awsaccess.New(ctx)
		},
		simulate: func(ctx context.Context) (awsaccess.Simulator, error) {
			return awsaccess.NewIAM(ctx)
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
	cloud, ok := prowlerClouds[account.Provider]
	if !ok {
		return sarif.Report{}, fmt.Errorf("prowler: Draugr checks Google Cloud and AWS accounts, not %q", account.Provider)
	}
	compliance := cloud.framework(cfg)

	// The check list first: it needs only Prowler, so a machine without it is told that before
	// anything about its credentials.
	checks, err := s.frameworkChecks(ctx, cloud, compliance)
	if err != nil {
		return sarif.Report{}, err
	}
	denied := map[string]string{}
	permissions := ""
	switch cloud.name {
	case "gcp":
		denied, err = s.preflight(ctx, account.ID)
	case "aws":
		var caller awsaccess.Caller
		caller, err = s.confirmCaller(ctx, account.ID)
		if err == nil {
			denied, permissions = s.awsPreflight(ctx, caller)
		}
	}
	if err != nil {
		return sarif.Report{}, err
	}

	dir, err := os.MkdirTemp("", "draugr-prowler-")
	if err != nil {
		return sarif.Report{}, fmt.Errorf("prowler: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	argv, err := prowlerArgv(cloud, account, compliance, dir)
	if err != nil {
		return sarif.Report{}, err
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
		return sarif.Report{}, fmt.Errorf("prowler: no result for any of the %d %s checks on %s %s",
			len(checks), compliance, cloud.unit, account.ID)
	}
	// The log is the backstop: a read the preflight could not foresee, denied mid-scan. Each cloud's
	// errors read differently, so each has its own patterns.
	var logged map[string]string
	var above []string
	switch cloud.name {
	case "gcp":
		logged, above = loggedDenials(filepath.Join(dir, "prowler.log"))
	case "aws":
		logged = awsLoggedDenials(filepath.Join(dir, "prowler.log"))
	}
	for service, reason := range logged {
		if _, known := denied[service]; !known {
			denied[service] = reason
		}
	}
	report := prowlerReport(account, cloud, compliance, checks, findings, denied)
	if len(above) > 0 {
		report.Provenance[0].Fields = append(report.Provenance[0].Fields,
			sarif.Field{Key: "organization", Value: "not read, " + strings.Join(above, ", ")})
	}
	if permissions != "" {
		report.Provenance[0].Fields = append(report.Provenance[0].Fields,
			sarif.Field{Key: "permissions", Value: permissions})
	}
	return report, nil
}

// awsPreflight asks IAM's policy simulator which of the actions Prowler's services call the
// caller's policies allow, and names each service one is denied for. It also says where the
// denials will come from: the simulation and then the log, or the log alone where the caller may not
// ask IAM about its own role, which a read-only role commonly may not. Neither is an error, because
// the log still names every denied call Prowler makes.
func (s prowlerScanner) awsPreflight(ctx context.Context, caller awsaccess.Caller) (map[string]string, string) {
	const fromLog = "read from Prowler's log"
	sim, err := s.simulate(ctx)
	if err != nil {
		slog.DebugContext(ctx, "AWS permission preflight not made", "error", err)
		return map[string]string{}, fromLog
	}
	denied, err := awsaccess.Denied(ctx, sim, caller, awsActions())
	if err != nil {
		slog.DebugContext(ctx, "AWS permission preflight not made", "caller", caller.ARN, "error", err)
		return map[string]string{}, fromLog
	}
	return awsDeniedServices(denied), "checked before the scan"
}

// prowlerArgv is the scan's command line. The findings go to dir as OCSF, the log beside them.
func prowlerArgv(cloud prowlerCloud, account plugin.AccountTarget, compliance, dir string) ([]string, error) {
	argv := []string{"prowler", cloud.name}
	switch cloud.name {
	case "gcp":
		argv = append(argv, "--project-id", account.ID)
	case "aws":
		mutelist := filepath.Join(dir, "mutelist.yaml")
		if err := os.WriteFile(mutelist, []byte(prowlerMutelist), 0o600); err != nil {
			return nil, fmt.Errorf("prowler: %w", err)
		}
		argv = append(argv, "--mutelist-file", mutelist)
		if len(account.Regions) > 0 {
			// Prowler knows each region's name and refuses one it does not, in lower case.
			argv = append(argv, "--region")
			for _, r := range account.Regions {
				argv = append(argv, strings.ToLower(r))
			}
		}
	}
	return append(argv, "--compliance", compliance,
		"--output-formats", "json-ocsf", "--output-directory", dir, "--output-filename", "scan",
		"--log-level", "ERROR", "--log-file", filepath.Join(dir, "prowler.log"), "--only-logs",
		"--no-color",
		// Exit 3 means "found something". Findings are the report's to judge, not an error.
		"--ignore-exit-code-3",
	), nil
}

// confirmCaller asks STS which identity the credentials are, and refuses one outside the declared
// account: Prowler reads whichever account the credentials reach and names it in its output, so a
// wrong profile is a complete report about another account.
func (s prowlerScanner) confirmCaller(ctx context.Context, account string) (awsaccess.Caller, error) {
	id, err := s.identify(ctx)
	if err != nil {
		return awsaccess.Caller{}, fmt.Errorf("prowler: %w", err)
	}
	caller, err := awsaccess.Confirm(ctx, id, account)
	if err != nil {
		return awsaccess.Caller{}, fmt.Errorf("prowler: %w", err)
	}
	return caller, nil
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
func (s prowlerScanner) frameworkChecks(ctx context.Context, cloud prowlerCloud, compliance string) ([]string, error) {
	out, err := s.run(ctx, []string{"prowler", cloud.name, "--list-checks-json", "--compliance", compliance})
	if err != nil {
		return nil, fmt.Errorf("run prowler: list the checks of %s: %w", compliance, err)
	}
	var listed map[string][]string
	if err := json.Unmarshal(lastJSON(out), &listed); err != nil {
		return nil, fmt.Errorf("prowler: unreadable check list for %s: %w", compliance, err)
	}
	checks := listed[cloud.name]
	if len(checks) == 0 {
		return nil, fmt.Errorf("prowler: compliance framework %s maps no %s checks; "+
			"`prowler %s --list-compliance` lists the ones that do", compliance, cloud.label, cloud.name)
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

// prowlerReport turns Prowler's findings into SARIF. A check reading a denied service is unread
// and its results set aside; on a cloud that keeps them, a check with a result keeps it and is
// partly read instead. Neither counts as decided.
func prowlerReport(account plugin.AccountTarget, cloud prowlerCloud, compliance string, checks []string,
	findings []ocsfFinding, denied map[string]string,
) sarif.Report {
	report := sarif.Report{Tool: prowlerScannerName, Rules: map[string]sarif.Rule{}}
	inFramework := map[string]bool{}
	for _, c := range checks {
		inFramework[c] = true
	}
	// A result is a pass or a fail. MANUAL says Prowler could not judge the check, which is no
	// result to keep.
	answered := map[string]bool{}
	for _, f := range findings {
		if status := strings.ToUpper(f.StatusCode); status == "PASS" || status == "FAIL" {
			answered[f.Metadata.EventCode] = true
		}
	}
	unread, partly := map[string]bool{}, map[string]bool{}
	for _, check := range checks {
		for _, service := range cloud.checkReads(check) {
			if reason, ok := denied[service]; ok {
				u := sarif.Unchecked{Scanner: prowlerScannerName, Check: check, Group: service, Reason: reason}
				if cloud.keepsPartlyRead && answered[check] {
					u.PartlyRead = true
					partly[check] = true
				} else {
					unread[check] = true
				}
				report.Unchecked = append(report.Unchecked, u)
				break
			}
		}
	}
	taxonomy, version := cisTaxonomy(compliance)
	decided := map[string]bool{}
	for _, f := range findings {
		check := f.Metadata.EventCode
		if unread[check] || !inFramework[check] {
			continue
		}
		status := strings.ToUpper(f.StatusCode)
		if (status == "PASS" || status == "FAIL") && !partly[check] {
			decided[check] = true
		}
		if status != "FAIL" || !inRegions(account.Provider, f, account.Regions) {
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
			rule.Taxa = append(rule.Taxa, sarif.Taxon{Taxonomy: cloud.taxonomy, ID: id, Version: version})
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

// prowlerLocation is where a finding is: the account for a finding about the account itself,
// otherwise the resource's ARN on AWS, its path when Prowler gives one, and its identifier when it
// does not. A project's name is its display name, "draugr cloud fixture", which locates nothing.
func prowlerLocation(account plugin.AccountTarget, f ocsfFinding) string {
	if len(f.Resources) > 0 {
		r := f.Resources[0]
		switch {
		case r.UID == account.ID || (r.UID == "" && r.Name == ""):
		case strings.HasPrefix(r.UID, "arn:"):
			// An ARN names one resource in every AWS account and region, which a name does not.
			return r.UID
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

// awsAccountWide are the prefixes of the AWS checks about the account as a whole. Prowler files
// their findings under the region it audited first, the profile's on a full scan and the first
// claimed one on a narrowed scan, so their region says where Prowler asked rather than where the
// thing is. Read from Prowler 5.48.0 runs against one account, whole and narrowed to a region: the
// IAM, account and Organizations findings, and the CloudWatch metric-filter alarms over the
// account's trail, moved to the narrowed region, while CloudTrail's stayed in the trail's home
// region and are regional.
var awsAccountWide = []string{
	"iam_",
	"account_",
	"organizations_",
	"cloudwatch_log_metric_filter_",
	"cloudwatch_changes_",
}

// awsIsAccountWide reports whether an AWS check is about the account as a whole.
func awsIsAccountWide(check string) bool {
	for _, prefix := range awsAccountWide {
		if strings.HasPrefix(check, prefix) {
			return true
		}
	}
	return false
}

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
// narrows. A finding with no region, or a global or multi-region one, is the whole account's, and so
// is an AWS finding awsAccountWide names, whatever region it carries.
func inRegions(provider string, f ocsfFinding, regions []string) bool {
	if len(regions) == 0 {
		return true
	}
	if len(f.Resources) == 0 || (provider == "aws" && awsIsAccountWide(f.Metadata.EventCode)) {
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
