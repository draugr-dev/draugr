package scanners

import (
	"bufio"
	"maps"
	"os"
	"regexp"
	"slices"
	"strings"
)

// What each Prowler check reads on Azure, the actions the scanner asks about before the scan, and
// how a denied read shows in Prowler's log.

// azureDataPlane is the Key Vault data plane, kept apart from the "keyvault" service because a role
// on the subscription does not decide it: a vault's own access policy does, one vault at a time. Only
// the key rotation check reads it, so one locked vault leaves the rest of the service's checks alone.
const azureDataPlane = "keyvault-data"

// azureCheckReads lists the services a check reads, where that is more than the service its name
// starts with, in the order a reader is told about them: the first denied one names the row. From
// Prowler 5.48.0's source: scripts/prowler-check-reads.py over the checks of cis_6.0_azure gives the
// first two, and keyvault_service.py and keyvault_key_rotation_enabled.py the other two, because a
// service's own calls are outside what that script follows.
var azureCheckReads = map[string][]string{
	"entra_user_with_vm_access_has_mfa":                        {"entra", "iam"},
	"keyvault_key_rotation_enabled":                            {"keyvault", azureDataPlane},
	"keyvault_logging_enabled":                                 {"keyvault", "monitor"},
	"monitor_storage_account_with_activity_logs_cmk_encrypted": {"monitor", "storage"},
}

// azureServiceActions are the actions asked about before the scan, by the Prowler service module whose
// calls need them. Each comes from a call in the module's source and is named in Microsoft's published
// list of Azure permissions, whose case Azure does not compare.
//
// An action that is not listed reads as denied, so a wrong name would set aside a service's checks for
// everybody. Left out, with their denials coming from the log alone: keyvault-data, which a vault's
// access policy decides, and defender's auto provisioning settings, whose action the published list
// does not name. entra does not run (azureNotRun).
var azureServiceActions = map[string][]string{
	"appinsights": {"Microsoft.Insights/components/read"},
	"databricks":  {"Microsoft.Databricks/workspaces/read"},
	"defender": {
		"Microsoft.Security/assessments/read", "Microsoft.Security/iotSecuritySolutions/read",
		"Microsoft.Security/pricings/read", "Microsoft.Security/securityContacts/read",
		"Microsoft.Security/settings/read",
	},
	"iam": {"Microsoft.Authorization/roleAssignments/read", "Microsoft.Authorization/roleDefinitions/read"},
	"keyvault": {
		"Microsoft.KeyVault/vaults/keys/read", "Microsoft.KeyVault/vaults/read",
		"Microsoft.KeyVault/vaults/secrets/read",
	},
	"monitor": {"Microsoft.Insights/activityLogAlerts/read", "Microsoft.Insights/diagnosticSettings/read"},
	"network": {
		"Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/read",
		"Microsoft.Network/applicationGateways/read",
		"Microsoft.Network/bastionHosts/read", "Microsoft.Network/networkSecurityGroups/read",
		"Microsoft.Network/networkWatchers/flowLogs/read", "Microsoft.Network/networkWatchers/read",
		"Microsoft.Network/publicIPAddresses/read", "Microsoft.Network/virtualNetworks/read",
	},
	"policy": {"Microsoft.Authorization/policyAssignments/read"},
	"storage": {
		"Microsoft.Storage/storageAccounts/blobServices/read", "Microsoft.Storage/storageAccounts/fileServices/read",
		"Microsoft.Storage/storageAccounts/read",
	},
}

// azureActions is every action the services need, sorted.
func azureActions() []string {
	var out []string
	for _, service := range slices.Sorted(maps.Keys(azureServiceActions)) {
		out = append(out, azureServiceActions[service]...)
	}
	slices.Sort(out)
	return out
}

// azureDeniedServices names each service one of the denied actions belongs to, with its first.
func azureDeniedServices(denied []string) map[string]string {
	out := map[string]string{}
	for service, actions := range azureServiceActions {
		for _, a := range actions {
			if slices.Contains(denied, a) {
				out[service] = "denied " + a
				break
			}
		}
	}
	return out
}

// azureShodanCheck sends each of the subscription's public addresses to Shodan where Prowler has a
// Shodan key, and does nothing where it has none, so it never runs: Draugr does not send a
// subscription's addresses to a third party on the strength of a key in somebody's Prowler
// configuration.
const azureShodanCheck = "network_public_ip_shodan"

// azureNotRun reports whether the scan keeps a check from running. Prowler's App service reads
// function host keys and application settings in its constructor whenever any app_* check runs, and
// those are secrets the scan has no need of.
//
// The entra_* checks are about the tenant's directory rather than the subscription: Prowler's Entra
// service reads every user in the tenant, and each one's MFA registration, whichever subscription the
// scan names. That is a row per person in the organization, from a scan somebody pointed at one
// subscription, so none of them runs, and each is listed as not run.
func azureNotRun(check string) bool {
	return check == azureShodanCheck || strings.HasPrefix(check, "app_") || strings.HasPrefix(check, "entra_")
}

const (
	// azureUnnamedDenial is the reason for a denial whose log line names no action.
	azureUnnamedDenial = "denied a permission Prowler's log does not name"
	// azureDataPlaneDenial is the reason for a denied read of a vault's keys.
	azureDataPlaneDenial = "denied a Key Vault data-plane read"
	// azureNotEvaluated is the reason for a check whose only result is MANUAL. Prowler's Azure checks
	// give that when a read failed, such as the user checks when Microsoft Graph did not return the
	// tenant's users.
	azureNotEvaluated = "Prowler could not evaluate it"
	// azureReadFailed starts the reason for a read that ended with no answer.
	azureReadFailed = "read failed, "
)

var (
	// azureDenialRE finds a refused read in an error Prowler logs whole: the codes Azure Resource Manager
	// returns for one, and the status line Microsoft Graph's errors carry whatever their code.
	azureDenialRE = regexp.MustCompile(`\bAuthorizationFailed\b|\bForbidden[A-Za-z]*\b|` +
		`does not have authorization to perform action|\bCode: 403\b`)
	// azureActionRE is the action a refusal names.
	azureActionRE = regexp.MustCompile(`does not have authorization to perform action '([^']+)'`)
	// azureTransportRE is a read that ended with no answer, as Prowler logs it, Class[line]: the transport
	// errors of httpx, under Microsoft Graph's client, and of azure-core, under Azure Resource Manager's.
	azureTransportRE = regexp.MustCompile(`\b(RemoteProtocolError|LocalProtocolError|ProtocolError|ReadError|` +
		`WriteError|ConnectError|CloseError|ProxyError|ConnectTimeout|ReadTimeout|WriteTimeout|PoolTimeout|` +
		`ServiceRequestError|ServiceResponseError|ServiceRequestTimeoutError|ServiceResponseTimeoutError|` +
		`IncompleteReadError)\[\d+\]`)
	// azureGraphStatusRE is an answer from Microsoft Graph that is no refusal and no result: throttled, or
	// an error on Graph's side.
	azureGraphStatusRE = regexp.MustCompile(`\bCode: (429|5\d\d)\b`)
)

// azureHiddenLogLevel is LOG_LEVEL where it hides the warnings the scan reads. Prowler lets the
// environment override --log-level.
func azureHiddenLogLevel(getenv func(string) string) string {
	switch level := getenv("LOG_LEVEL"); level {
	case "ERROR", "CRITICAL":
		return level
	}
	return ""
}

// azureDataPlaneMessage is how Prowler logs a Key Vault data-plane read that failed: a WARNING, from
// keyvault_service.py, for any HTTP error. The scan logs at WARNING for this line alone.
const azureDataPlaneMessage = "has no access policy configured for keyvault"

// azureLoggedDenials reads Prowler's log for refused reads and reads that ended with no answer, and
// names each service that logged one, with the action where the error names it. A failed read leaves
// a service's checks as much in doubt as a refused one, and the same login can get a different answer
// on the next run.
//
// The log is one JSON object a line, written from a template that does not escape the message, and
// an Azure error runs over several lines, so a line with no module of its own belongs to the record
// before it. A line from outside a service module, such as the provider's own lookup of the tenant's
// domain, leaves no check of a service unread.
func azureLoggedDenials(path string) map[string]string {
	out := map[string]string{}
	f, err := os.Open(path) // #nosec G304 -- a file Prowler wrote into a directory this scan made
	if err != nil {
		return out
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
	module := ""
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "{") {
			module = ""
			if m := serviceModuleRE.FindStringSubmatch(line); m != nil {
				module = m[1]
			}
		}
		if module == "" {
			continue
		}
		if strings.Contains(line, azureDataPlaneMessage) {
			out[azureDataPlane] = azureDataPlaneDenial
			continue
		}
		if reason := azureLineReason(line); reason != "" {
			if prev, seen := out[module]; !seen || azureBetterReason(reason, prev) {
				out[module] = reason
			}
		}
	}
	return out
}

// azureLineReason is what a log line says about a read, or nothing where it says neither of the two.
func azureLineReason(line string) string {
	if azureDenialRE.MatchString(line) {
		if a := azureActionRE.FindStringSubmatch(line); a != nil {
			return "denied " + a[1]
		}
		return azureUnnamedDenial
	}
	if m := azureTransportRE.FindStringSubmatch(line); m != nil {
		return azureReadFailed + m[1]
	}
	if m := azureGraphStatusRE.FindStringSubmatch(line); m != nil {
		return azureReadFailed + "HTTP " + m[1]
	}
	return ""
}

// azureBetterReason prefers a reason naming the action, which is what somebody grants, then any denial
// over a failed read, which may pass on the next run. Between two of a kind it takes the first in
// order, so the reason is the same whichever call Prowler made first.
func azureBetterReason(a, b string) bool {
	if ra, rb := azureReasonRank(a), azureReasonRank(b); ra != rb {
		return ra < rb
	}
	return a < b
}

func azureReasonRank(reason string) int {
	switch {
	case strings.HasPrefix(reason, azureReadFailed):
		return 2
	case reason == azureUnnamedDenial:
		return 1
	}
	return 0
}
