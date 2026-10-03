package scanners

import (
	"maps"
	"slices"
	"strings"
)

// What each Prowler check reads on Google Cloud, and the permissions each read needs.
//
// Prowler reports no difference between a check it evaluated and one whose reads were denied, so
// the scanner asks Google, before Prowler runs, which of these permissions the credentials hold,
// and calls a check unread when a service it reads is missing one. Taken from Prowler 5.44.0's
// source: the clients each check imports, and the API calls each client makes. A check this does
// not list reads the service its name starts with.

// gcpServiceGate is the permission every service needs before it reads anything: Prowler asks the
// Service Usage API whether the service's API is on, and drops the project from the service when
// it cannot ask.
const gcpServiceGate = "serviceusage.services.get"

// gcpServiceReads are the permissions each Prowler service's reads need, beyond the gate, that
// Google can answer for on the project.
//
// Not every read: bigquery.tables.list and .get are checked on each dataset, and
// storage.buckets.getIamPolicy on each bucket, and testIamPermissions on the project never reports
// them, not even to its owner. Asked here, they would make every service that needs them read as
// denied. Their denials come from Prowler's log instead.
var gcpServiceReads = map[string][]string{
	"accessapproval": {"accessapproval.settings.get"},
	"apikeys":        {"apikeys.keys.list"},
	"bigquery":       {"bigquery.datasets.get"},
	"cloudresourcemanager": {
		"resourcemanager.projects.get", "resourcemanager.projects.getIamPolicy",
	},
	"cloudsql":     {"cloudsql.instances.list"},
	"cloudstorage": {"storage.buckets.list"},
	"compute": {
		"compute.instances.list", "compute.firewalls.list", "compute.networks.list",
		"compute.subnetworks.list", "compute.zones.list", "compute.regions.list",
		"compute.projects.get", "compute.addresses.list", "compute.images.list",
		"compute.snapshots.list", "compute.backendServices.list", "compute.regionBackendServices.list",
		"compute.urlMaps.list", "compute.regionUrlMaps.list", "compute.instanceGroupManagers.list",
	},
	"dataproc":          {"dataproc.clusters.list"},
	"dns":               {"dns.managedZones.list", "dns.policies.list"},
	"essentialcontacts": {"essentialcontacts.contacts.list"},
	"iam": {
		"iam.serviceAccounts.list", "iam.serviceAccountKeys.list",
		"iam.workloadIdentityPools.list", "iam.workloadIdentityPoolProviders.list",
	},
	"kms": {
		"cloudkms.locations.list", "cloudkms.keyRings.list", "cloudkms.cryptoKeys.list",
		"cloudkms.cryptoKeys.getIamPolicy",
	},
	"logging":      {"logging.sinks.list", "logging.logMetrics.list"},
	"monitoring":   {"monitoring.alertPolicies.list", "monitoring.timeSeries.list"},
	"serviceusage": {"serviceusage.services.list"},
}

// gcpCheckReads lists the services a check reads, where that is more than, or other than, the
// service its name starts with. In the order a reader is told about them: the first denied one
// names the row.
var gcpCheckReads = map[string][]string{
	"cloudstorage_bucket_log_retention_policy_lock":                                      {"cloudstorage", "logging"},
	"iam_account_access_approval_enabled":                                                {"accessapproval"},
	"iam_audit_logs_enabled":                                                             {"cloudresourcemanager"},
	"iam_cloud_asset_inventory_enabled":                                                  {"serviceusage"},
	"iam_no_service_roles_at_project_level":                                              {"cloudresourcemanager"},
	"iam_organization_essential_contacts_configured":                                     {"essentialcontacts"},
	"iam_role_kms_enforce_separation_of_duties":                                          {"cloudresourcemanager"},
	"iam_sa_no_administrative_privileges":                                                {"cloudresourcemanager", "iam"},
	"logging_log_metric_filter_and_alert_for_audit_configuration_changes_enabled":        {"logging", "monitoring"},
	"logging_log_metric_filter_and_alert_for_bucket_permission_changes_enabled":          {"logging", "monitoring"},
	"logging_log_metric_filter_and_alert_for_custom_role_changes_enabled":                {"logging", "monitoring"},
	"logging_log_metric_filter_and_alert_for_project_ownership_changes_enabled":          {"logging", "monitoring"},
	"logging_log_metric_filter_and_alert_for_sql_instance_configuration_changes_enabled": {"logging", "monitoring"},
	"logging_log_metric_filter_and_alert_for_vpc_firewall_rule_changes_enabled":          {"logging", "monitoring"},
	"logging_log_metric_filter_and_alert_for_vpc_network_changes_enabled":                {"logging", "monitoring"},
	"logging_log_metric_filter_and_alert_for_vpc_network_route_changes_enabled":          {"logging", "monitoring"},
}

// gcpAPIService maps a Google API's name, as a request URL names it, to the Prowler service that
// calls it, for reading a denial out of Prowler's log.
var gcpAPIService = map[string]string{
	"accessapproval": "accessapproval", "apikeys": "apikeys", "bigquery": "bigquery",
	"cloudkms": "kms", "cloudresourcemanager": "cloudresourcemanager", "compute": "compute",
	"dataproc": "dataproc", "dns": "dns", "essentialcontacts": "essentialcontacts", "iam": "iam",
	"logging": "logging", "monitoring": "monitoring", "serviceusage": "serviceusage",
	"sqladmin": "cloudsql", "storage": "cloudstorage",
}

// checkReads is the services a check reads.
func checkReads(check string) []string {
	if reads, ok := gcpCheckReads[check]; ok {
		return reads
	}
	service, _, _ := strings.Cut(check, "_")
	return []string{service}
}

// gcpPermissions is every permission the services read, the gate first, each once.
func gcpPermissions() []string {
	out := []string{gcpServiceGate}
	seen := map[string]bool{gcpServiceGate: true}
	for _, service := range slices.Sorted(maps.Keys(gcpServiceReads)) {
		for _, p := range gcpServiceReads[service] {
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	return out
}

// deniedServices names each service a permission is missing for, with the first missing one.
func deniedServices(granted []string) map[string]string {
	held := map[string]bool{}
	for _, p := range granted {
		held[p] = true
	}
	out := map[string]string{}
	for service, perms := range gcpServiceReads {
		for _, p := range append([]string{gcpServiceGate}, perms...) {
			if !held[p] {
				out[service] = "denied " + p
				break
			}
		}
	}
	return out
}
