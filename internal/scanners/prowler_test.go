package scanners

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/awsaccess"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// grantAll is a tester holding every permission the checks read, except those it is told to deny.
type grantAll struct {
	deny    []string
	err     error
	project string
}

func (g *grantAll) Granted(_ context.Context, project string, perms []string) ([]string, error) {
	g.project = project
	if g.err != nil {
		return nil, g.err
	}
	var out []string
	for _, p := range perms {
		if !slices.Contains(g.deny, p) {
			out = append(out, p)
		}
	}
	return out, nil
}

// fakeProwler answers the two invocations the scanner makes: the framework's check list, and a scan
// that writes findings and a log into the directory it is given.
type fakeProwler struct {
	checks   []string
	findings []map[string]any
	log      string
	scanErr  error
	listErr  error
	argv     [][]string
	// mutelist is the mutelist file the scan was given, as it read when the scan ran.
	mutelist string
}

func (f *fakeProwler) run(_ context.Context, argv []string) ([]byte, error) {
	f.argv = append(f.argv, argv)
	if slices.Contains(argv, "--list-checks-json") {
		if f.listErr != nil {
			return nil, f.listErr
		}
		out, _ := json.Marshal(map[string][]string{argv[1]: f.checks})
		return append([]byte("_                         _\n"), out...), nil
	}
	if f.scanErr != nil {
		return nil, f.scanErr
	}
	if path := argAfter(argv, "--mutelist-file"); path != "" {
		data, err := os.ReadFile(path) // #nosec G304 -- a file the scanner wrote into its own directory
		if err != nil {
			return nil, err
		}
		f.mutelist = string(data)
	}
	dir := argAfter(argv, "--output-directory")
	if f.findings != nil {
		data, _ := json.Marshal(f.findings)
		if err := os.WriteFile(filepath.Join(dir, "scan.ocsf.json"), data, 0o600); err != nil {
			return nil, err
		}
	}
	if f.log != "" {
		if err := os.WriteFile(argAfter(argv, "--log-file"), []byte(f.log), 0o600); err != nil {
			return nil, err
		}
	}
	return nil, nil
}

// ocsf is a Prowler finding as its OCSF output writes one, data and all.
func ocsf(check, status, severity, region, uid string) map[string]any {
	return map[string]any{
		"message": "message for " + check, "severity": severity, "status_code": status,
		"status_detail": check + " " + status + " on " + uid,
		"metadata":      map[string]any{"event_code": check},
		"finding_info":  map[string]any{"title": "Title of " + check, "desc": "desc"},
		"resources": []map[string]any{{
			"uid": uid, "name": uid, "region": region,
			"data": map[string]any{"metadata": map[string]any{"key": "s3cr3t-function-key"}},
		}},
		"remediation": map[string]any{"desc": "Fix " + check, "references": []string{"https://docs.example/" + check}},
		"unmapped":    map[string]any{"compliance": map[string][]string{"CIS-5.0": {"3.6"}, "CIS-4.0": {"3.6"}}},
	}
}

var shopProd = plugin.AccountTarget{Account: "shop-prod", Provider: "gcp", ID: "shop-prod-4821"}

func newTestProwler(f *fakeProwler, g *grantAll) prowlerScanner {
	s := NewProwler().(prowlerScanner)
	s.run = f.run
	s.access = func(context.Context) (permissionTester, error) { return g, nil }
	s.identify = func(context.Context) (awsaccess.Identifier, error) { return callerIn("111111111111"), nil }
	return s
}

// callerIn is an STS answer for a role session in account.
type callerIn string

func (c callerIn) CallerIdentity(context.Context) (awsaccess.Caller, error) {
	return awsaccess.Caller{Account: string(c), ARN: "arn:aws:sts::" + string(c) + ":assumed-role/audit/scan"}, nil
}

var webProd = plugin.AccountTarget{Account: "web-prod", Provider: "aws", ID: "111111111111"}

// The scan of an AWS account: the framework's checks listed from Prowler, the caller confirmed to be
// in the declared account, then one Prowler run with the Control Tower mutelist replaced by an empty
// one. The finding values are made up for the test, in the shape the scanner reads.
func TestProwlerChecksAnAWSAccount(t *testing.T) {
	f := &fakeProwler{
		checks: []string{"cloudtrail_multi_region_enabled", "s3_bucket_public_access"},
		findings: []map[string]any{
			ocsf("s3_bucket_public_access", "FAIL", "critical", "us-east-1", "arn:aws:s3:::shop-assets"),
			ocsf("cloudtrail_multi_region_enabled", "PASS", "high", "us-east-1", "111111111111"),
		},
	}
	f.findings[0]["unmapped"] = map[string]any{"compliance": map[string][]string{"CIS-7.0": {"2.1.4"}}}
	report, err := newTestProwler(f, &grantAll{}).Scan(context.Background(), webProd, nil)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"prowler", "aws", "--list-checks-json", "--compliance", "cis_7.0_aws"}; !slices.Equal(f.argv[0], want) {
		t.Errorf("check list argv = %v, want %v", f.argv[0], want)
	}
	scan := f.argv[1]
	dir := argAfter(scan, "--output-directory")
	want := []string{
		"prowler", "aws", "--mutelist-file", filepath.Join(dir, "mutelist.yaml"), "--compliance", "cis_7.0_aws",
		"--output-formats", "json-ocsf", "--output-directory", dir, "--output-filename", "scan",
		"--log-level", "ERROR", "--log-file", filepath.Join(dir, "prowler.log"), "--only-logs", "--no-color",
		"--ignore-exit-code-3",
	}
	if !slices.Equal(scan, want) {
		t.Errorf("scan argv = %v\nwant %v", scan, want)
	}
	if f.mutelist != "Mutelist: {}\n" {
		t.Errorf("mutelist = %q, want an empty one", f.mutelist)
	}
	if len(report.Results) != 1 || report.Results[0].Location.URI != "arn:aws:s3:::shop-assets" || report.Results[0].Score != 9.5 {
		t.Fatalf("results = %+v, want the bucket at its ARN", report.Results)
	}
	rule := report.Rules["prowler/s3_bucket_public_access"]
	if len(rule.Taxa) != 1 || rule.Taxa[0] != (sarif.Taxon{Taxonomy: "CIS Amazon Web Services Foundations Benchmark", ID: "2.1.4", Version: "7.0"}) {
		t.Errorf("taxa = %+v", rule.Taxa)
	}
	got := report.Provenance[0].Describe()
	for _, part := range []string{"benchmark: cis_7.0_aws", "coverage: 2 of 2 checks decided", "scope: whole account",
		"permissions: not checked; a denied read counts as Prowler reported it"} {
		if !strings.Contains(got, part) {
			t.Errorf("provenance = %q, want %q in it", got, part)
		}
	}
}

// A component claiming regions narrows Prowler to them, in the lower case Prowler's region names
// take, and a framework named for the account's cloud replaces its default.
func TestProwlerNarrowsAnAWSScanToTheClaimedRegions(t *testing.T) {
	f := &fakeProwler{
		checks: []string{"cloudtrail_multi_region_enabled", "cloudwatch_changes_to_vpcs_alarm_configured",
			"cloudwatch_log_metric_filter_root_usage", "ec2_instance_public_ip", "iam_root_mfa_enabled"},
		findings: []map[string]any{
			ocsf("ec2_instance_public_ip", "FAIL", "medium", "eu-west-1", "arn:aws:ec2:eu-west-1:111111111111:instance/i-1"),
			ocsf("ec2_instance_public_ip", "FAIL", "medium", "ap-south-1", "arn:aws:ec2:ap-south-1:111111111111:instance/i-2"),
			ocsf("cloudtrail_multi_region_enabled", "FAIL", "high", "us-east-1", "arn:aws:cloudtrail:us-east-1:111111111111:trail/main"),
			// About the account, filed under the region Prowler audited first: the whole account's.
			ocsf("iam_root_mfa_enabled", "FAIL", "critical", "us-east-1", "arn:aws:iam::111111111111:root"),
			ocsf("cloudwatch_log_metric_filter_root_usage", "FAIL", "medium", "eu-west-1", "111111111111"),
			ocsf("cloudwatch_changes_to_vpcs_alarm_configured", "FAIL", "medium", "eu-west-1", "111111111111"),
		},
	}
	narrowed := webProd
	narrowed.Regions = []string{"US-EAST-1", "eu-west-1"}
	report, err := newTestProwler(f, &grantAll{}).Scan(context.Background(), narrowed,
		plugin.Config{"compliance": "cis_6.0_aws"})
	if err != nil {
		t.Fatal(err)
	}
	scan := f.argv[1]
	at := slices.Index(scan, "--region")
	if at < 0 || !slices.Equal(scan[at+1:at+3], []string{"us-east-1", "eu-west-1"}) || scan[at+3] != "--compliance" ||
		argAfter(scan, "--compliance") != "cis_6.0_aws" {
		t.Errorf("argv = %v", scan)
	}
	if got := report.Provenance[0].Describe(); !strings.Contains(got, "scope: 2 regions US-EAST-1, eu-west-1") {
		t.Errorf("provenance = %q", got)
	}
	var located []string
	for _, r := range report.Results {
		located = append(located, r.Location.URI)
	}
	slices.Sort(located)
	want := []string{"arn:aws:cloudtrail:us-east-1:111111111111:trail/main", "arn:aws:ec2:eu-west-1:111111111111:instance/i-1"}
	if !slices.Equal(located, want) {
		t.Errorf("results at %v\nwant %v: the claimed regions' resources, none of the account's", located, want)
	}

	// The same findings for a component claiming the whole account: every one.
	whole, err := newTestProwler(f, &grantAll{}).Scan(context.Background(), webProd, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(whole.Results) != len(f.findings) {
		t.Errorf("whole account = %d results, want %d", len(whole.Results), len(f.findings))
	}
}

func TestAWSAccountWideChecks(t *testing.T) {
	for check, want := range map[string]bool{
		"iam_root_mfa_enabled":                                true,
		"account_maintain_current_contact_details":            true,
		"organizations_delegated_administrators":              true,
		"cloudwatch_log_metric_filter_root_usage":             true,
		"cloudwatch_changes_to_network_acls_alarm_configured": true,
		"cloudtrail_multi_region_enabled":                     false,
		"cloudwatch_cross_account_sharing_disabled":           false,
		"ec2_instance_public_ip":                              false,
	} {
		if got := awsIsAccountWide(check); got != want {
			t.Errorf("%s: account-wide = %v, want %v", check, got, want)
		}
	}
	// A Google Cloud check of the same name keeps its own region rule.
	f := ocsfFinding{}
	f.Metadata.EventCode = "iam_sa_no_administrative_privileges"
	f.Resources = append(f.Resources, struct {
		UID    string `json:"uid"`
		Name   string `json:"name"`
		Region string `json:"region"`
	}{UID: "sa", Region: "us-central1"})
	if !inRegions("gcp", f, []string{"us-central1"}) || inRegions("aws", f, []string{"us-central1"}) {
		t.Error("the account-wide rule is not AWS's alone")
	}
}

// One `compliance` serves every account the control checks, so a framework of one cloud applies to
// that cloud's accounts and the others keep their default; the measured-against line names the one
// each ran.
func TestAFrameworkAppliesToItsOwnCloud(t *testing.T) {
	gcp, aws := prowlerClouds["gcp"], prowlerClouds["aws"]
	for _, c := range []struct {
		cloud prowlerCloud
		set   string
		want  string
	}{
		{aws, "", "cis_7.0_aws"},
		{aws, "cis_6.0_aws", "cis_6.0_aws"},
		{aws, "cis_4.0_gcp", "cis_7.0_aws"},
		{gcp, "cis_6.0_aws", "cis_5.0_gcp"},
		{gcp, "cis_4.0_gcp", "cis_4.0_gcp"},
	} {
		if got := c.cloud.framework(plugin.Config{"compliance": c.set}); got != c.want {
			t.Errorf("%s with %q = %s, want %s", c.cloud.name, c.set, got, c.want)
		}
	}
	// The option's description is where `draugr controls --options` and an editor say what an
	// account is checked against when it is unset.
	for _, cloud := range prowlerClouds {
		if !strings.Contains(prowlerConfigSchema, cloud.compliance) {
			t.Errorf("the compliance option does not name %s's default, %s", cloud.label, cloud.compliance)
		}
	}
}

// Credentials that resolve to another account would produce a complete report about that account,
// so the scan stops before Prowler runs, naming both.
func TestProwlerRefusesCredentialsForAnotherAWSAccount(t *testing.T) {
	f := &fakeProwler{checks: []string{"a_b"}}
	s := newTestProwler(f, &grantAll{})
	s.identify = func(context.Context) (awsaccess.Identifier, error) { return callerIn("222222222222"), nil }
	_, err := s.Scan(context.Background(), webProd, nil)
	if err == nil || !strings.Contains(err.Error(), "in account 222222222222, not the declared account 111111111111") {
		t.Errorf("err = %v", err)
	}
	if len(f.argv) != 1 {
		t.Errorf("prowler ran %d times, want the check list alone: %v", len(f.argv), f.argv)
	}

	s.identify = func(context.Context) (awsaccess.Identifier, error) { return nil, awsaccess.ErrNoCredentials }
	if _, err := s.Scan(context.Background(), webProd, nil); !errors.Is(err, awsaccess.ErrNoCredentials) {
		t.Errorf("no credentials = %v", err)
	}
}

func TestProwlerArgvStopsWhereTheMutelistCannotBeWritten(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	if _, err := prowlerArgv(prowlerClouds["aws"], webProd, "cis_7.0_aws", missing); err == nil {
		t.Error("a mutelist in a missing directory was accepted")
	}
}

// A denied service sets aside every check that reads it, whatever Prowler said about them, and
// names it once per check with the permission that was missing. The rest are judged: a FAIL is a
// finding, a PASS a decided check, and a MANUAL neither.
func TestProwlerSetsAsideWhatADeniedServiceLeavesUnread(t *testing.T) {
	f := &fakeProwler{
		checks: []string{"cloudsql_instance_public_ip", "compute_firewall_ssh_access_from_the_internet_allowed",
			"compute_instance_public_ip", "iam_account_access_approval_enabled", "logging_sink_created"},
		findings: []map[string]any{
			ocsf("compute_firewall_ssh_access_from_the_internet_allowed", "FAIL", "high", "global", "fw/default-allow-ssh"),
			ocsf("compute_instance_public_ip", "PASS", "medium", "us-central1-a", "vm/web-1"),
			// A denied read made Prowler fail this one; it is unread, not a finding.
			ocsf("cloudsql_instance_public_ip", "FAIL", "critical", "us-central1", "sql/orders"),
			ocsf("iam_account_access_approval_enabled", "MANUAL", "low", "global", "shop-prod-4821"),
			// Not in the framework: Prowler ran it for another reason, and the report is the framework's.
			ocsf("gke_cluster_no_default_service_account", "FAIL", "high", "us-central1", "gke/x"),
		},
	}
	g := &grantAll{deny: []string{"cloudsql.instances.list"}}
	report, err := newTestProwler(f, g).Scan(context.Background(), shopProd, nil)
	if err != nil {
		t.Fatal(err)
	}
	if g.project != "shop-prod-4821" {
		t.Errorf("asked about %q", g.project)
	}
	if len(report.Results) != 1 {
		t.Fatalf("results = %+v, want the firewall alone", report.Results)
	}
	r := report.Results[0]
	if r.RuleID != "prowler/compute_firewall_ssh_access_from_the_internet_allowed" || r.Level != sarif.LevelError ||
		r.Score != 8.0 || r.Location.URI != "fw/default-allow-ssh" {
		t.Errorf("result = %+v", r)
	}
	rule := report.Rules[r.RuleID]
	if rule.HelpURI == "" || rule.FullDescription == "" || len(rule.Taxa) != 1 || rule.Taxa[0].ID != "3.6" || rule.Taxa[0].Version != "5.0" {
		t.Errorf("rule = %+v", rule)
	}
	want := []sarif.Unchecked{{Scanner: "prowler", Check: "cloudsql_instance_public_ip", Group: "cloudsql", Reason: "denied cloudsql.instances.list"}}
	if !slices.Equal(report.Unchecked, want) {
		t.Errorf("unchecked = %+v, want %+v", report.Unchecked, want)
	}
	var decided []string
	for _, d := range report.Decided {
		decided = append(decided, d.ID)
	}
	if !slices.Equal(decided, []string{"compute_firewall_ssh_access_from_the_internet_allowed", "compute_instance_public_ip"}) {
		t.Errorf("decided = %v", decided)
	}
	if got := report.Provenance[0].Describe(); !strings.Contains(got, "benchmark: cis_5.0_gcp") ||
		!strings.Contains(got, "coverage: 2 of 5 checks decided") || !strings.Contains(got, "scope: whole account") {
		t.Errorf("provenance = %q", got)
	}
	// What a service returned is never carried into the report.
	raw, _ := json.Marshal(report)
	if strings.Contains(string(raw), "s3cr3t-function-key") {
		t.Error("a resource's data reached the report")
	}
}

// A component claiming regions gets the findings in them and their zones, and none of the account's
// own; the scan is asked for the project and its framework either way.
func TestProwlerNarrowsToTheRegionsAComponentClaims(t *testing.T) {
	f := &fakeProwler{
		checks: []string{"compute_instance_public_ip", "iam_sa_no_administrative_privileges"},
		findings: []map[string]any{
			ocsf("compute_instance_public_ip", "FAIL", "medium", "us-central1-a", "vm/web-1"),
			ocsf("compute_instance_public_ip", "FAIL", "medium", "europe-west1-b", "vm/eu-1"),
			ocsf("iam_sa_no_administrative_privileges", "FAIL", "high", "global", "sa/admin"),
		},
	}
	narrowed := shopProd
	narrowed.Regions = []string{"US-CENTRAL1"}
	report, err := newTestProwler(f, &grantAll{}).Scan(context.Background(), narrowed,
		plugin.Config{"compliance": "cis_4.0_gcp"})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Results) != 1 || report.Results[0].Location.URI != "vm/web-1" {
		t.Errorf("results = %+v, want the us-central1 instance alone", report.Results)
	}
	if got := report.Provenance[0].Describe(); !strings.Contains(got, "scope: 1 region US-CENTRAL1") ||
		!strings.Contains(got, "benchmark: cis_4.0_gcp") {
		t.Errorf("provenance = %q", got)
	}
	scan := f.argv[len(f.argv)-1]
	if argAfter(scan, "--project-id") != "shop-prod-4821" || argAfter(scan, "--compliance") != "cis_4.0_gcp" ||
		!slices.Contains(scan, "--ignore-exit-code-3") {
		t.Errorf("argv = %v", scan)
	}
}

// A read the preflight did not foresee, denied mid-scan, still leaves its checks unread: the log
// names the API, and the service-usage path names the service being gated.
func TestProwlerReadsDenialsFromItsLog(t *testing.T) {
	f := &fakeProwler{
		checks:   []string{"cloudsql_instance_public_ip", "dns_dnssec_disabled", "compute_instance_public_ip"},
		findings: []map[string]any{ocsf("dns_dnssec_disabled", "PASS", "medium", "global", "zone/a")},
		log: `{"timestamp": "t", "filename": "service.py:80", "level": "ERROR", "module": "service", "message": "HttpError[80]: <HttpError 403 when requesting https://serviceusage.googleapis.com/v1/projects/shop-prod-4821/services/sqladmin.googleapis.com returned "Permission denied">"}
{"timestamp": "t", "filename": "compute_service.py:99", "level": "ERROR", "module": "compute_service", "message": "HttpError 403 returned "Permission 'compute.zones.list' denied on resource '//compute.googleapis.com/projects/shop-prod-4821'""}
{"timestamp": "t", "level": "ERROR", "message": "an unrelated failure"}
{"timestamp": "t", "filename": "logging_service.py:74", "level": "ERROR", "module": "logging_service", "message": "HttpError[57]: <HttpError 403 when requesting https://logging.googleapis.com/v2/organizations/463126129727/sinks?alt=json returned "Permission 'logging.sinks.list' denied on resource '//logging.googleapis.com/organizations/463126129727' (or it may not exist).""}
{"timestamp": "t", "filename": "service.py:78", "level": "ERROR", "module": "service", "message": "dns API has not been used in project shop-prod-4821 before or it is disabled."}
`,
	}
	report, err := newTestProwler(f, &grantAll{}).Scan(context.Background(), shopProd, nil)
	if err != nil {
		t.Fatal(err)
	}
	var groups []string
	for _, u := range report.Unchecked {
		groups = append(groups, u.Group+":"+u.Check+":"+u.Reason)
	}
	slices.Sort(groups)
	want := []string{
		"cloudsql:cloudsql_instance_public_ip:denied a permission Prowler's log does not name",
		"compute:compute_instance_public_ip:denied compute.zones.list",
	}
	if !slices.Equal(groups, want) {
		t.Errorf("unread = %v\nwant %v", groups, want)
	}
	// A denial on the organization leaves the project's logging checks alone and is said in the
	// account of the run; a disabled API is no denial at all.
	if got := report.Provenance[0].Describe(); !strings.Contains(got, "organization: not read, denied logging.sinks.list") {
		t.Errorf("provenance = %q", got)
	}
}

func TestDeniedIn(t *testing.T) {
	for line, want := range map[string][]string{
		`... https://sqladmin.googleapis.com/v1/projects/p/instances ...`:                       {"cloudsql"},
		`... https://serviceusage.googleapis.com/v1/projects/p/services/storage.googleapis.com`: {"cloudstorage"},
		`{"module": "iam_service", "message": "403"}`:                                           {"iam", "accessapproval", "essentialcontacts"},
		`{"module": "kms_service", "message": "403"}`:                                           {"kms"},
		`{"module": "unknown_service", "message": "403"}`:                                       nil,
		`no service named`: nil,
	} {
		if got := deniedIn(line); !slices.Equal(got, want) {
			t.Errorf("deniedIn(%q) = %v, want %v", line, got, want)
		}
	}
	if project, above := loggedDenials(filepath.Join(t.TempDir(), "missing.log")); len(project) != 0 || len(above) != 0 {
		t.Errorf("a missing log named %v and %v", project, above)
	}
}

// An account the scan cannot read at all is an error, so the run counts it as a target not
// reached; so is a Prowler that cannot list or run the framework.
func TestProwlerRefusesWhatItCannotCheck(t *testing.T) {
	noCreds := errors.New("no Google Cloud credentials found")
	for name, tc := range map[string]struct {
		target plugin.Target
		f      *fakeProwler
		g      *grantAll
		access error
		want   string
	}{
		"no credentials":                  {shopProd, &fakeProwler{checks: []string{"a_b"}}, &grantAll{}, noCreds, "no Google Cloud credentials found"},
		"an unreadable project":           {shopProd, &fakeProwler{checks: []string{"a_b"}}, &grantAll{err: errors.New("project shop-prod-4821 does not exist, or the credentials cannot read it")}, nil, "cannot read it"},
		"no permission at all":            {shopProd, &fakeProwler{checks: []string{"a_b"}}, &grantAll{deny: gcpPermissions()}, nil, "hold none of the permissions the checks read on project shop-prod-4821"},
		"a framework with no checks":      {shopProd, &fakeProwler{}, &grantAll{}, nil, "maps no Google Cloud checks"},
		"a check list that fails":         {shopProd, &fakeProwler{listErr: errors.New("exit status 2")}, &grantAll{}, nil, "list the checks of cis_5.0_gcp"},
		"a scan that fails":               {shopProd, &fakeProwler{checks: []string{"a_b"}, scanErr: errors.New("exit status 1")}, &grantAll{}, nil, "run prowler: exit status 1"},
		"another provider":                {plugin.AccountTarget{Provider: "azure", ID: "1"}, &fakeProwler{}, &grantAll{}, nil, `Draugr checks Google Cloud and AWS accounts, not "azure"`},
		"an AWS framework with no checks": {webProd, &fakeProwler{}, &grantAll{}, nil, "cis_7.0_aws maps no AWS checks; `prowler aws --list-compliance`"},
		"an AWS scan with no result":      {webProd, &fakeProwler{checks: []string{"a_b"}}, &grantAll{}, nil, "no result for any of the 1 cis_7.0_aws checks on account 111111111111"},
		"another kind of target":          {plugin.ImageTarget{Ref: "a:1"}, &fakeProwler{}, &grantAll{}, nil, "unsupported target"},
	} {
		t.Run(name, func(t *testing.T) {
			s := newTestProwler(tc.f, tc.g)
			if tc.access != nil {
				s.access = func(context.Context) (permissionTester, error) { return nil, tc.access }
			}
			_, err := s.Scan(context.Background(), tc.target, nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

// Prowler reports passed checks as findings, so a run with none decided nothing, and a missing or
// renamed findings file must not read as an account with nothing wrong.
func TestProwlerWithNoFindingsIsAnError(t *testing.T) {
	f := &fakeProwler{checks: []string{"compute_instance_public_ip"}}
	_, err := newTestProwler(f, &grantAll{}).Scan(context.Background(), shopProd, nil)
	if err == nil || !strings.Contains(err.Error(), "no result for any of the 1 cis_5.0_gcp checks") {
		t.Errorf("err = %v, want the undecided checks named", err)
	}
}

func TestReadOCSFRefusesAFileItCannotRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scan.ocsf.json")
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readOCSF(path); err == nil {
		t.Error("an unreadable findings file was accepted")
	}
	if _, err := readOCSF(t.TempDir()); err == nil {
		t.Error("a directory was read as findings")
	}
}

func TestProwlerSeverityAndTaxonomy(t *testing.T) {
	for sev, want := range map[string]struct {
		level sarif.Level
		score float64
	}{"Critical": {sarif.LevelError, 9.5}, "high": {sarif.LevelError, 8.0}, "Medium": {sarif.LevelWarning, 5.5},
		"low": {sarif.LevelNote, 2.0}, "informational": {sarif.LevelNote, 0}} {
		if level, score := prowlerSeverity(sev); level != want.level || score != want.score {
			t.Errorf("%s = %s %v", sev, level, score)
		}
	}
	if key, v := cisTaxonomy("cis_5.0_gcp"); key != "CIS-5.0" || v != "5.0" {
		t.Errorf("cis_5.0_gcp = %q %q", key, v)
	}
	if key, _ := cisTaxonomy("hipaa_gcp"); key != "" {
		t.Errorf("hipaa_gcp = %q", key)
	}
	if got := firstNonEmpty(" ", "b"); got != "b" {
		t.Errorf("firstNonEmpty = %q", got)
	}
	if got := firstMatch(prowlerVersionRE)([]byte("Prowler 5.44.0 (You are running the latest version, yay!)")); got != "5.44.0" {
		t.Errorf("version = %q", got)
	}
}

// Every check the reads table lists reads only services whose permissions it knows, so a check is
// never called readable for want of an entry.
func TestEveryServiceACheckReadsHasPermissions(t *testing.T) {
	for check, services := range gcpCheckReads {
		for _, s := range services {
			if _, ok := gcpServiceReads[s]; !ok {
				t.Errorf("%s reads %s, which has no permissions listed", check, s)
			}
		}
	}
	for api, s := range gcpAPIService {
		if _, ok := gcpServiceReads[s]; !ok {
			t.Errorf("API %s maps to %s, which has no permissions listed", api, s)
		}
	}
	perms := gcpPermissions()
	if perms[0] != gcpServiceGate || len(slices.Compact(slices.Sorted(slices.Values(perms)))) != len(perms) {
		t.Errorf("permissions are not the gate first and each once: %v", perms[:3])
	}
	if got := deniedServices([]string{gcpServiceGate})["compute"]; got != "denied compute.instances.list" {
		t.Errorf("compute = %q", got)
	}
	if got := deniedServices(nil)["compute"]; got != "denied "+gcpServiceGate {
		t.Errorf("with nothing granted, compute = %q", got)
	}
	// Checked on each dataset and bucket, so a project never reports them held, even to its owner
	// (asked of a real project on 2026-10-03). Asking would call the service denied for everybody.
	for _, p := range []string{"bigquery.tables.list", "bigquery.tables.get", "storage.buckets.getIamPolicy"} {
		if slices.Contains(perms, p) {
			t.Errorf("the preflight asks the project for %s, which the project never reports", p)
		}
	}
}

func TestProwlerLocation(t *testing.T) {
	finding := func(uid, name string) ocsfFinding {
		var f ocsfFinding
		f.Resources = append(f.Resources, struct {
			UID    string `json:"uid"`
			Name   string `json:"name"`
			Region string `json:"region"`
		}{UID: uid, Name: name})
		return f
	}
	for _, c := range []struct {
		f    ocsfFinding
		want string
	}{
		// What Prowler 5.44.0 writes against a real project.
		{finding("shop-prod-4821", "shop prod"), "gcp/shop-prod-4821"},
		{finding("sa@shop-prod-4821.iam.gserviceaccount.com", "projects/shop-prod-4821/serviceAccounts/sa@shop-prod-4821.iam.gserviceaccount.com"),
			"projects/shop-prod-4821/serviceAccounts/sa@shop-prod-4821.iam.gserviceaccount.com"},
		{finding("cloudasset.googleapis.com", "Cloud Asset Inventory"), "cloudasset.googleapis.com"},
		{finding("default", "default"), "default"},
		{finding("8814202563123", "draugr-fixture-1-ssh"), "draugr-fixture-1-ssh"},
		{finding("", "fw-1"), "fw-1"},
		{finding("arn:aws:iam::111111111111:role/admin", "admin"), "arn:aws:iam::111111111111:role/admin"},
		{ocsfFinding{}, "gcp/shop-prod-4821"},
	} {
		if got := prowlerLocation(shopProd, c.f); got != c.want {
			t.Errorf("prowlerLocation(%+v) = %q, want %q", c.f.Resources, got, c.want)
		}
	}
}
