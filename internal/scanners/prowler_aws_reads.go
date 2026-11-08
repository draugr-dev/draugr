package scanners

import (
	"bufio"
	"maps"
	"os"
	"regexp"
	"slices"
	"strings"
)

// What each Prowler check reads on AWS, the IAM actions the scanner asks about before the scan, and
// how a denied call reads in Prowler's log.
//
// A check's reads are the Prowler service modules whose clients it imports. Prowler starts a
// service by making every call the module makes, whichever of its checks run, so a call denied in a
// module is a read every check of that module was refused.

// awsCheckReads lists the Prowler service modules each CIS 7.0 AWS check reads, in the order a
// reader is told about them: the first denied one names the row. Taken from Prowler 5.44.0's source
// by check_services.py, which reads it as text: for each check, every
// `from prowler.providers.aws.services.<service>...<name>_client import` in the check's module and
// in the helper modules it imports, followed to the end. Regenerate it by running that over the
// installed `prowler` package with the framework's check list, which prints this table as JSON. A
// check this does not list, from another framework, reads the service its name starts with.
var awsCheckReads = map[string][]string{
	"accessanalyzer_enabled":                                                              {"accessanalyzer"},
	"account_maintain_current_contact_details":                                            {"account"},
	"account_security_contact_information_is_registered":                                  {"account"},
	"apigateway_restapi_logging_enabled":                                                  {"apigateway"},
	"apigatewayv2_api_access_logging_enabled":                                             {"apigatewayv2"},
	"awslambda_function_not_publicly_accessible":                                          {"awslambda"},
	"cloudfront_distributions_logging_enabled":                                            {"cloudfront"},
	"cloudtrail_kms_encryption_enabled":                                                   {"cloudtrail"},
	"cloudtrail_log_file_validation_enabled":                                              {"cloudtrail"},
	"cloudtrail_logs_s3_bucket_access_logging_enabled":                                    {"cloudtrail", "s3"},
	"cloudtrail_multi_region_enabled":                                                     {"cloudtrail"},
	"cloudtrail_s3_dataevents_read_enabled":                                               {"cloudtrail", "s3"},
	"cloudtrail_s3_dataevents_write_enabled":                                              {"cloudtrail", "s3"},
	"cloudwatch_changes_to_network_acls_alarm_configured":                                 {"cloudtrail", "cloudwatch"},
	"cloudwatch_changes_to_network_gateways_alarm_configured":                             {"cloudtrail", "cloudwatch"},
	"cloudwatch_changes_to_network_route_tables_alarm_configured":                         {"cloudtrail", "cloudwatch"},
	"cloudwatch_changes_to_vpcs_alarm_configured":                                         {"cloudtrail", "cloudwatch"},
	"cloudwatch_log_metric_filter_and_alarm_for_aws_config_configuration_changes_enabled": {"cloudtrail", "cloudwatch"},
	"cloudwatch_log_metric_filter_and_alarm_for_cloudtrail_configuration_changes_enabled": {"cloudtrail", "cloudwatch"},
	"cloudwatch_log_metric_filter_authentication_failures":                                {"cloudtrail", "cloudwatch"},
	"cloudwatch_log_metric_filter_aws_organizations_changes":                              {"cloudtrail", "cloudwatch"},
	"cloudwatch_log_metric_filter_disable_or_scheduled_deletion_of_kms_cmk":               {"cloudtrail", "cloudwatch"},
	"cloudwatch_log_metric_filter_for_s3_bucket_policy_changes":                           {"cloudtrail", "cloudwatch"},
	"cloudwatch_log_metric_filter_policy_changes":                                         {"cloudtrail", "cloudwatch"},
	"cloudwatch_log_metric_filter_root_usage":                                             {"cloudtrail", "cloudwatch"},
	"cloudwatch_log_metric_filter_security_group_changes":                                 {"cloudtrail", "cloudwatch"},
	"cloudwatch_log_metric_filter_sign_in_without_mfa":                                    {"cloudtrail", "cloudwatch"},
	"cloudwatch_log_metric_filter_unauthorized_api_calls":                                 {"cloudtrail", "cloudwatch"},
	"config_recorder_all_regions_enabled":                                                 {"config"},
	"ec2_ebs_default_encryption":                                                          {"ec2"},
	"ec2_instance_imdsv2_enabled":                                                         {"ec2"},
	"ec2_instance_port_cifs_exposed_to_internet":                                          {"ec2", "vpc"},
	"ec2_instance_profile_attached":                                                       {"ec2"},
	"ec2_networkacl_allow_ingress_any_port":                                               {"ec2"},
	"ec2_networkacl_allow_ingress_tcp_port_22":                                            {"ec2"},
	"ec2_networkacl_allow_ingress_tcp_port_3389":                                          {"ec2"},
	"ec2_securitygroup_allow_ingress_from_internet_to_all_ports":                          {"ec2", "vpc"},
	"ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22":                        {"ec2", "vpc"},
	"ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_3389":                      {"ec2", "vpc"},
	"ec2_securitygroup_default_restrict_traffic":                                          {"ec2", "vpc"},
	"efs_encryption_at_rest_enabled":                                                      {"efs"},
	"elbv2_logging_enabled":                                                               {"elbv2"},
	"eventbridge_bus_exposed":                                                             {"eventbridge"},
	"glacier_vaults_policy_public_access":                                                 {"glacier"},
	"iam_avoid_root_usage":                                                                {"iam"},
	"iam_aws_attached_policy_no_administrative_privileges":                                {"iam"},
	"iam_check_saml_providers_sts":                                                        {"iam"},
	"iam_customer_attached_policy_no_administrative_privileges":                           {"iam"},
	"iam_no_expired_server_certificates_stored":                                           {"iam"},
	"iam_no_root_access_key":                                                              {"iam"},
	"iam_password_policy_minimum_length_14":                                               {"iam"},
	"iam_password_policy_reuse_24":                                                        {"iam"},
	"iam_policy_attached_only_to_group_or_roles":                                          {"iam"},
	"iam_policy_cloudshell_admin_not_attached":                                            {"iam"},
	"iam_root_credentials_management_enabled":                                             {"iam", "organizations"},
	"iam_root_hardware_mfa_enabled":                                                       {"iam"},
	"iam_root_mfa_enabled":                                                                {"iam"},
	"iam_rotate_access_key_90_days":                                                       {"iam"},
	"iam_support_role_created":                                                            {"iam"},
	"iam_user_accesskey_unused":                                                           {"iam"},
	"iam_user_console_access_unused":                                                      {"iam"},
	"iam_user_mfa_enabled_console_access":                                                 {"iam"},
	"kms_cmk_rotation_enabled":                                                            {"kms"},
	"kms_key_not_publicly_accessible":                                                     {"kms"},
	"macie_is_enabled":                                                                    {"macie", "s3"},
	"organizations_delegated_administrators":                                              {"organizations"},
	"rds_cluster_multi_az":                                                                {"rds"},
	"rds_instance_minor_version_upgrade_enabled":                                          {"rds"},
	"rds_instance_multi_az":                                                               {"rds"},
	"rds_instance_no_public_access":                                                       {"ec2", "rds", "vpc"},
	"rds_instance_storage_encrypted":                                                      {"rds"},
	"s3_account_level_public_access_blocks":                                               {"s3"},
	"s3_bucket_level_public_access_block":                                                 {"s3"},
	"s3_bucket_no_mfa_delete":                                                             {"s3"},
	"s3_bucket_policy_public_write_access":                                                {"s3"},
	"s3_bucket_secure_transport_policy":                                                   {"s3"},
	"secretsmanager_not_publicly_accessible":                                              {"secretsmanager"},
	"securityhub_enabled":                                                                 {"securityhub"},
	"sns_topics_not_publicly_accessible":                                                  {"sns"},
	"sqs_queues_not_publicly_accessible":                                                  {"sqs"},
	"vpc_flow_logs_enabled":                                                               {"vpc"},
	"vpc_peering_routing_tables_with_least_privilege":                                     {"vpc"},
}

// awsServiceActions are the IAM actions asked about before the scan, by the Prowler service module
// that calls them. Each is a call the module makes whenever it has something to read, named in a
// denial Prowler 5.48.0 logged against a read-only role or in Prowler's prowler-additions-policy.
//
// An action IAM does not know simulates as denied, so a wrong name would set aside a service's
// checks for everybody. A service whose calls no such source names is left out, and its denials
// come from the log alone: apigateway, apigatewayv2, awslambda, cloudfront, config, glacier,
// organizations, rds, securityhub, sqs and vpc. So is a call made only in some accounts, such as
// macie2:GetAutomatedDiscoveryConfiguration, made only where Macie is on.
var awsServiceActions = map[string][]string{
	"accessanalyzer": {"access-analyzer:ListAnalyzers"},
	"account":        {"account:GetContactInformation"},
	"cloudtrail":     {"cloudtrail:GetEventSelectors", "cloudtrail:GetInsightSelectors", "cloudtrail:GetTrailStatus"},
	"cloudwatch":     {"cloudwatch:DescribeAlarms"},
	"ec2": {
		"ec2:GetEbsEncryptionByDefault", "ec2:GetInstanceMetadataDefaults",
		"ec2:GetSnapshotBlockPublicAccessState",
	},
	"efs": {
		"elasticfilesystem:DescribeAccessPoints", "elasticfilesystem:DescribeBackupPolicy",
		"elasticfilesystem:DescribeFileSystemPolicy", "elasticfilesystem:DescribeMountTargets",
	},
	"elbv2":       {"elasticloadbalancing:DescribeRules", "elasticloadbalancing:DescribeTags"},
	"eventbridge": {"events:ListEndpoints", "events:ListEventBuses"},
	"iam": {
		"iam:GenerateCredentialReport", "iam:GenerateServiceLastAccessedDetails", "iam:GetPolicyVersion",
		"iam:GetRole", "iam:GetRolePolicy",
	},
	"kms":            {"kms:DescribeKey", "kms:ListAliases"},
	"macie":          {"macie2:GetMacieSession"},
	"s3":             {"s3:GetAccountPublicAccessBlock", "s3:GetBucketLocation", "s3:ListAccessPoints"},
	"secretsmanager": {"secretsmanager:ListSecrets"},
	"sns":            {"sns:GetTopicAttributes"},
}

// awsActions is every action the services call, each once, sorted.
func awsActions() []string {
	var out []string
	for _, service := range slices.Sorted(maps.Keys(awsServiceActions)) {
		out = append(out, awsServiceActions[service]...)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// awsDeniedServices names each service one of the denied actions belongs to, with its first denied
// action.
func awsDeniedServices(denied []string) map[string]string {
	out := map[string]string{}
	for service, actions := range awsServiceActions {
		for _, a := range actions {
			if slices.Contains(denied, a) {
				out[service] = "denied " + a
				break
			}
		}
	}
	return out
}

var (
	// awsModuleRE is the Prowler service module a log line comes from.
	awsModuleRE = regexp.MustCompile(`"module":\s*"([a-z0-9]+)_service"`)
	// awsErrorRE is botocore's account of a failed call: the error code and the operation.
	awsErrorRE = regexp.MustCompile(`An error occurred \(([A-Za-z]+)\) when calling the ([A-Za-z0-9]+) operation`)
	// awsActionRE is the action a denial names: "is not authorized to perform: kms:DescribeKey".
	awsActionRE = regexp.MustCompile(`not authorized to perform: ([A-Za-z0-9-]+):([A-Za-z0-9]+)`)
)

// awsDenialCodes are the error codes AWS services return for a call the caller's policies do not
// allow. AuthorizationError is SNS's, UnauthorizedOperation EC2's.
var awsDenialCodes = map[string]bool{
	"AccessDenied": true, "AccessDeniedException": true, "AuthorizationError": true,
	"UnauthorizedOperation": true,
}

// awsLoggedDenials reads Prowler's log for denied calls, and names each service that logged one,
// with the action, or the operation where the error does not name the action. A throttled call or
// any other failure is not a denial.
//
// The log is one JSON object a line, written from a template that does not escape the message, so
// it is read with patterns rather than decoded.
func awsLoggedDenials(path string) map[string]string {
	out := map[string]string{}
	f, err := os.Open(path) // #nosec G304 -- a file Prowler wrote into a directory this scan made
	if err != nil {
		return out
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
	for sc.Scan() {
		line := sc.Text()
		call := awsErrorRE.FindStringSubmatch(line)
		module := awsModuleRE.FindStringSubmatch(line)
		if call == nil || module == nil || !awsDenialCodes[call[1]] {
			continue
		}
		reason := "denied the " + call[2] + " call"
		if a := awsActionRE.FindStringSubmatch(line); a != nil {
			// IAM's prefixes are case-insensitive, and SNS writes its own in capitals.
			reason = "denied " + strings.ToLower(a[1]) + ":" + a[2]
		}
		if prev, seen := out[module[1]]; !seen || awsBetterReason(reason, prev) {
			out[module[1]] = reason
		}
	}
	return out
}

// awsBetterReason prefers a reason naming the action, which is what somebody grants, and between
// two of a kind the first in order, so the reason is the same whichever call Prowler made first.
func awsBetterReason(a, b string) bool {
	named := func(r string) bool { return !strings.HasPrefix(r, "denied the ") }
	if named(a) != named(b) {
		return named(a)
	}
	return a < b
}
