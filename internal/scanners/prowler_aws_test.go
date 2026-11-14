package scanners

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/awsaccess"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// The AWS fixtures are a Prowler 5.48.0 run of cis_7.0_aws with a read-only role, redacted:
// prowler.log is one line per denied service call, and scan.ocsf.json one finding per check and
// status, with only the fields the scanner reads.
const awsFixtures = "testdata/prowler-aws"

// recordedAWSDenials are the services the recorded log names, each with the reason the scanner
// gives. Read by hand from the log: the action where the error names one, the first in order where
// it names several, and the operation where it names none.
var recordedAWSDenials = map[string]string{
	"accessanalyzer": "denied access-analyzer:ListAnalyzers",
	"account":        "denied account:GetContactInformation",
	"cloudtrail":     "denied the GetEventSelectors call",
	"cloudwatch":     "denied cloudwatch:DescribeAlarms",
	"efs":            "denied elasticfilesystem:DescribeAccessPoints",
	"elbv2":          "denied elasticloadbalancing:DescribeRules",
	"eventbridge":    "denied events:ListEndpoints",
	"iam":            "denied iam:GenerateCredentialReport",
	"kms":            "denied kms:DescribeKey",
	"macie":          "denied macie2:GetMacieSession",
	"organizations":  "denied the DescribeOrganization call",
	"s3":             "denied s3:GetAccountPublicAccessBlock",
	"secretsmanager": "denied secretsmanager:ListSecrets",
	"sns":            "denied sns:GetTopicAttributes",
}

func TestAWSLoggedDenialsReadTheRecordedLog(t *testing.T) {
	got := awsLoggedDenials(filepath.Join(awsFixtures, "prowler.log"))
	if !maps.Equal(got, recordedAWSDenials) {
		t.Errorf("denials = %v\nwant %v", got, recordedAWSDenials)
	}
}

// A throttled call, an error that is not a denial and a line from no service are not denials. EC2's
// UnauthorizedOperation is one, though it names no action. The lines are synthetic, in the recorded
// log's shape.
func TestAWSLoggedDenialsAreDenialsOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "prowler.log")
	log := strings.Join([]string{
		`{"module": "iam_service", "message": "us-east-1 -- ClientError[872]: An error occurred (Throttling) when calling the ListRoleTags operation (reached max retries: 3): Rate exceeded"}`,
		`{"module": "rds_service", "message": "us-east-1 -- ClientError[1]: An error occurred (DBInstanceNotFound) when calling the DescribeDBInstances operation: gone"}`,
		`{"module": "__main__", "message": "An error occurred (AccessDenied) when calling the ListBuckets operation"}`,
		`{"module": "ec2_service", "message": "us-east-1 -- ClientError[9]: An error occurred (UnauthorizedOperation) when calling the GetEbsEncryptionByDefault operation: You are not authorized to perform this operation."}`,
	}, "\n")
	if err := os.WriteFile(path, []byte(log), 0o600); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"ec2": "denied the GetEbsEncryptionByDefault call"}
	if got := awsLoggedDenials(path); !maps.Equal(got, want) {
		t.Errorf("denials = %v, want %v", got, want)
	}
	if got := awsLoggedDenials(filepath.Join(t.TempDir(), "missing.log")); len(got) != 0 {
		t.Errorf("a missing log = %v", got)
	}
}

// memberAccountLog is what Prowler logs at WARNING in an AWS member account, which is neither the
// organization's management account nor a delegated administrator, in the recorded log's shape.
func memberAccountLog() string {
	line := func(file, module, message string) string {
		return `{"timestamp": "2026-11-07 00:00:00,000", "filename": "` + file + `", "level": "WARNING", "module": "` +
			module + `", "message": "` + message + `"}`
	}
	return strings.Join([]string{
		line("iam_service.py:1", "iam_service", "us-east-1 -- AccountNotManagementOrDelegatedAdministratorException[1]: "+
			"An error occurred (AccountNotManagementOrDelegatedAdministratorException) when calling the "+
			"ListOrganizationsFeatures operation: Input account 111111111111 is neither management account nor delegated admin."),
		line("organizations.py:1", "organizations", "us-east-1 -- AccessDeniedException[1]: An error occurred "+
			"(AccessDeniedException) when calling the DescribeAccount operation: You don't have permissions to access this resource."),
		line("organizations_service.py:1", "organizations_service", "us-east-1 -- AccessDeniedException[1]: An error occurred "+
			"(AccessDeniedException) when calling the ListPolicies operation: You don't have permissions to access this resource."),
	}, "\n") + "\n"
}

// In a member account, Prowler logs the Organizations calls it is refused at WARNING, and the two
// checks reading Organizations emit nothing there. The scan reads the log at that level, so both
// are unread with the denial rather than missing from the count unexplained. The refusal from the
// provider's own lookup, outside a service module, and IAM's precondition, which is not a denial,
// leave IAM's other checks decided.
func TestAMemberAccountsOrganizationsDenialsAreRead(t *testing.T) {
	f := &fakeProwler{
		checks: []string{
			"iam_password_policy_minimum_length_14", "iam_root_credentials_management_enabled",
			"organizations_delegated_administrators",
		},
		findings: []map[string]any{
			ocsf("iam_password_policy_minimum_length_14", "PASS", "medium", "us-east-1", "111111111111"),
		},
		log: memberAccountLog(),
	}
	report, err := newTestProwler(f, &grantAll{}).Scan(context.Background(), webProd, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := argAfter(f.argv[1], "--log-level"); got != "WARNING" {
		t.Errorf("--log-level %s, want WARNING, where Prowler logs these denials", got)
	}
	partly, unread := partlyAndUnread(report)
	if len(partly) != 0 {
		t.Errorf("partly read = %v, want none", partly)
	}
	if want := []string{"iam_root_credentials_management_enabled", "organizations_delegated_administrators"}; !slices.Equal(unread, want) {
		t.Errorf("unread = %v, want %v", unread, want)
	}
	for _, u := range report.Unchecked {
		if u.Group != "organizations" || u.Reason != "denied the ListPolicies call" {
			t.Errorf("row %s = group %q, reason %q; want organizations, denied the ListPolicies call", u.Check, u.Group, u.Reason)
		}
	}
	if len(report.Decided) != 1 || report.Decided[0].ID != "iam_password_policy_minimum_length_14" {
		t.Errorf("decided = %+v, want only the IAM check Prowler answered", report.Decided)
	}
}

// On AWS too, LOG_LEVEL above WARNING hides the denials the scan reads, and the measured-against line
// says so. INFO hides none of them.
func TestAnAWSLogLevelHidingWarningsIsSaid(t *testing.T) {
	for level, hides := range map[string]bool{"ERROR": true, "CRITICAL": true, "INFO": false, "": false} {
		f := &fakeProwler{
			checks:   []string{"iam_password_policy_minimum_length_14"},
			findings: []map[string]any{ocsf("iam_password_policy_minimum_length_14", "PASS", "medium", "us-east-1", "111111111111")},
		}
		s := newTestProwler(f, &grantAll{})
		s.getenv = func(k string) string {
			if k == "LOG_LEVEL" {
				return level
			}
			return ""
		}
		report, err := s.Scan(context.Background(), webProd, nil)
		if err != nil {
			t.Fatal(err)
		}
		got := report.Provenance[0].Describe()
		if said := strings.Contains(got, "LOG_LEVEL="+level+" hides Prowler's warnings, Organizations denials"); said != hides {
			t.Errorf("LOG_LEVEL=%q: provenance = %q", level, got)
		}
	}
}

// recordedAWSScan is the recorded run as the fake Prowler replays it: every CIS 7.0 check listed,
// the recorded findings and the recorded log.
func recordedAWSScan(t *testing.T) *fakeProwler {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(awsFixtures, "scan.ocsf.json"))
	if err != nil {
		t.Fatal(err)
	}
	var findings []map[string]any
	if err := json.Unmarshal(data, &findings); err != nil {
		t.Fatal(err)
	}
	log, err := os.ReadFile(filepath.Join(awsFixtures, "prowler.log"))
	if err != nil {
		t.Fatal(err)
	}
	return &fakeProwler{checks: slices.Sorted(maps.Keys(awsCheckReads)), findings: findings, log: string(log)}
}

// partly returns the checks a report marks partly read and those it marks unread.
func partlyAndUnread(r sarif.Report) (partly, unread []string) {
	for _, u := range r.Unchecked {
		if u.PartlyRead {
			partly = append(partly, u.Check)
		} else {
			unread = append(unread, u.Check)
		}
	}
	return partly, unread
}

// On the recorded run, with no preflight, a check of a service the log names as denied is unread
// when Prowler gave it no pass or fail, and partly read, its findings kept, when it did. Setting
// aside every check of a denied service instead would set aside 56 of the 82 checks and two failed
// CloudTrail checks with them.
func TestProwlerReadsTheRecordedAWSDenialsPerCheck(t *testing.T) {
	f := recordedAWSScan(t)
	report, err := newTestProwler(f, &grantAll{}).Scan(context.Background(), webProd, nil)
	if err != nil {
		t.Fatal(err)
	}
	partly, unread := partlyAndUnread(report)
	wantPartly := []string{
		"cloudtrail_kms_encryption_enabled", "cloudtrail_log_file_validation_enabled", "cloudtrail_multi_region_enabled",
		"efs_encryption_at_rest_enabled", "elbv2_logging_enabled",
		"iam_aws_attached_policy_no_administrative_privileges", "iam_check_saml_providers_sts",
		"iam_customer_attached_policy_no_administrative_privileges", "iam_password_policy_minimum_length_14",
		"iam_password_policy_reuse_24", "iam_policy_attached_only_to_group_or_roles",
		"iam_policy_cloudshell_admin_not_attached", "iam_support_role_created", "iam_user_console_access_unused",
		"sns_topics_not_publicly_accessible",
	}
	if !slices.Equal(partly, wantPartly) {
		t.Errorf("partly read = %v\nwant %v", partly, wantPartly)
	}
	if len(unread) != 41 {
		t.Errorf("%d checks unread, want 41: %v", len(unread), unread)
	}
	// A check with only MANUAL results is unread: Prowler judged nothing there to keep.
	for _, check := range []string{"account_maintain_current_contact_details", "cloudwatch_log_metric_filter_root_usage"} {
		if !slices.Contains(unread, check) {
			t.Errorf("%s is not unread", check)
		}
	}
	// The cloudwatch checks read CloudTrail first, so a row names the CloudTrail denial.
	for _, u := range report.Unchecked {
		if u.Check == "cloudwatch_log_metric_filter_root_usage" && (u.Group != "cloudtrail" || u.Reason != "denied the GetEventSelectors call") {
			t.Errorf("row = %+v", u)
		}
	}

	var failed []string
	for _, r := range report.Results {
		failed = append(failed, strings.TrimPrefix(r.RuleID, prowlerRulePrefix))
	}
	wantFailed := []string{
		"cloudtrail_log_file_validation_enabled", "cloudtrail_multi_region_enabled", "ec2_ebs_default_encryption",
		"ec2_instance_imdsv2_enabled", "ec2_networkacl_allow_ingress_any_port", "ec2_networkacl_allow_ingress_tcp_port_22",
		"ec2_networkacl_allow_ingress_tcp_port_3389", "rds_instance_multi_az",
	}
	if !slices.Equal(failed, wantFailed) {
		t.Errorf("findings = %v\nwant every recorded FAIL, %v", failed, wantFailed)
	}
	for _, d := range report.Decided {
		if slices.Contains(partly, d.ID) || slices.Contains(unread, d.ID) {
			t.Errorf("%s is decided and set aside", d.ID)
		}
	}
	got := report.Provenance[0].Describe()
	for _, part := range []string{"coverage: 18 of 82 checks decided", "permissions: read from Prowler's log"} {
		if !strings.Contains(got, part) {
			t.Errorf("provenance = %q, want %q in it", got, part)
		}
	}
}

// With a preflight the caller may make, the simulation names the denied services before the scan,
// with the action it denied, and the log adds the services it did not foresee. Synthetic: the
// recorded role was denied the simulation.
func TestProwlerChecksAWSPermissionsBeforeTheScan(t *testing.T) {
	f := recordedAWSScan(t)
	s := newTestProwler(f, &grantAll{})
	sim := &fakeSimulator{denied: []string{"ec2:GetEbsEncryptionByDefault", "iam:GetRole", "kms:ListAliases"}}
	s.simulate = func(context.Context) (awsaccess.Simulator, error) { return sim, nil }
	report, err := s.Scan(context.Background(), webProd, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(sim.asked, awsActions()) {
		t.Errorf("asked about %v", sim.asked)
	}
	reasons := map[string]string{}
	for _, u := range report.Unchecked {
		reasons[u.Group] = u.Reason
	}
	for service, want := range map[string]string{
		"ec2":  "denied ec2:GetEbsEncryptionByDefault", // the simulation alone
		"iam":  "denied iam:GetRole",                   // both; the simulation's stands
		"kms":  "denied kms:ListAliases",
		"sns":  "denied sns:GetTopicAttributes", // the log alone
		"rds":  "",
		"vpc":  "",
		"glue": "",
	} {
		if reasons[service] != want {
			t.Errorf("%s = %q, want %q", service, reasons[service], want)
		}
	}
	// The failed EC2 checks are partly read, their findings kept.
	partly, _ := partlyAndUnread(report)
	if !slices.Contains(partly, "ec2_ebs_default_encryption") || len(report.Results) != 8 {
		t.Errorf("partly read = %v, %d findings", partly, len(report.Results))
	}
	if got := report.Provenance[0].Describe(); !strings.Contains(got, "permissions: simulated before the scan, then read from Prowler's log") {
		t.Errorf("provenance = %q", got)
	}
}

// A preflight IAM cannot be asked, for want of credentials, of iam:GetRole or of the simulation, is
// no error: the scan goes on, and the log says what was denied.
func TestAnAWSPreflightNotMadeFallsBackToTheLog(t *testing.T) {
	for name, simulate := range map[string]func(context.Context) (awsaccess.Simulator, error){
		"no simulator":        func(context.Context) (awsaccess.Simulator, error) { return nil, awsaccess.ErrNoCredentials },
		"a denied simulation": func(context.Context) (awsaccess.Simulator, error) { return &fakeSimulator{deny: true}, nil },
		"a denied GetRole":    func(context.Context) (awsaccess.Simulator, error) { return deniedGetRole{}, nil },
	} {
		t.Run(name, func(t *testing.T) {
			s := newTestProwler(recordedAWSScan(t), &grantAll{})
			s.simulate = simulate
			report, err := s.Scan(context.Background(), webProd, nil)
			if err != nil {
				t.Fatal(err)
			}
			if got := report.Provenance[0].Describe(); !strings.Contains(got, "permissions: read from Prowler's log") {
				t.Errorf("provenance = %q", got)
			}
			if len(report.Unchecked) != 56 {
				t.Errorf("%d checks set aside, want the log's 56", len(report.Unchecked))
			}
		})
	}
}

// deniedGetRole is a role that may not look itself up.
type deniedGetRole struct{}

func (deniedGetRole) RoleARN(context.Context, string) (string, error) {
	return "", errors.New("AccessDenied: not authorized to perform: iam:GetRole")
}

func (deniedGetRole) Allowed(context.Context, string, []string) ([]string, error) {
	return nil, errors.New("not reached")
}

// Each action asked about is one of a service a check reads, so a denial in the simulation always
// lands on a check, and each service's list holds no action twice.
func TestAWSActionsBelongToServicesTheChecksRead(t *testing.T) {
	read := map[string]bool{}
	for _, services := range awsCheckReads {
		for _, s := range services {
			read[s] = true
		}
	}
	for service, actions := range awsServiceActions {
		if !read[service] {
			t.Errorf("%s is asked about and no check reads it", service)
		}
		if len(slices.Compact(slices.Clone(actions))) != len(actions) || !slices.IsSorted(actions) {
			t.Errorf("%s: %v, want sorted and each once", service, actions)
		}
		for _, a := range actions {
			if prefix, name, ok := strings.Cut(a, ":"); !ok || prefix == "" || name == "" || strings.ContainsAny(a, "*?") {
				t.Errorf("%s: %q is not one action", service, a)
			}
		}
	}
	if got := awsDeniedServices([]string{"s3:ListAccessPoints", "s3:GetBucketLocation"}); got["s3"] != "denied s3:GetBucketLocation" || len(got) != 1 {
		t.Errorf("denied services = %v", got)
	}
}

// Every check of the default framework has its reads listed, so none falls back to its name.
func TestEveryCISAWSCheckHasItsReads(t *testing.T) {
	if len(awsCheckReads) != 82 {
		t.Errorf("%d checks, want cis_7.0_aws's 82", len(awsCheckReads))
	}
	aws := prowlerClouds["aws"]
	if got := aws.checkReads("cloudwatch_changes_to_vpcs_alarm_configured"); !slices.Equal(got, []string{"cloudtrail", "cloudwatch"}) {
		t.Errorf("a listed check = %v", got)
	}
	if got := aws.checkReads("dynamodb_tables_kms_cmk_encryption_enabled"); !slices.Equal(got, []string{"dynamodb"}) {
		t.Errorf("an unlisted check = %v", got)
	}
}
