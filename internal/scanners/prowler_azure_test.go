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

	"github.com/draugr-dev/draugr/internal/azureaccess"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// The Azure fixtures are two Prowler 5.48.0 runs of cis_6.0_azure, redacted: prowler.log holds one
// record per shape from a service module, and scan.ocsf.json one finding per check and status, with only
// the fields the scanner reads. rich is a login holding a wildcard grant, whose user read dropped
// mid-run. denied is a login holding no role on the subscription. Finding values elsewhere in this file
// are made up for the test, in the recorded shape.
const azureFixtures = "testdata/prowler-azure"

const shopSubscription = "00000000-0000-0000-0000-000000000000"

var shopAzure = plugin.AccountTarget{Account: "shop", Provider: "azure", ID: shopSubscription}

// azureLogLine is one record of Prowler's log file, in the recorded shape.
func azureLogLine(level, module, message string) string {
	return `{"timestamp": "2026-11-08 00:00:00,000", "filename": "` + module + `.py:1", "level": "` + level +
		`", "module": "` + module + `", "message": "` + message + `"}`
}

// recordedAzureScan replays a recorded run: the framework's checks, its findings and its log.
func recordedAzureScan(t *testing.T, run string) *fakeProwler {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(azureFixtures, run, "scan.ocsf.json")) // #nosec G304 -- a fixture this file names
	if err != nil {
		t.Fatal(err)
	}
	var findings []map[string]any
	if err := json.Unmarshal(data, &findings); err != nil {
		t.Fatal(err)
	}
	log, err := os.ReadFile(filepath.Join(azureFixtures, run, "prowler.log")) // #nosec G304 -- a fixture this file names
	if err != nil {
		t.Fatal(err)
	}
	return &fakeProwler{checks: cisAzureChecks(t), findings: findings, log: string(log)}
}

// newTestAzure is a scanner whose Azure answers are azure's.
func newTestAzure(f *fakeProwler, azure *fakeAzure) prowlerScanner {
	s := newTestProwler(f, &grantAll{})
	s.azure = func(context.Context) (azureaccess.Reader, error) { return azure, nil }
	return s
}

func unreadGroups(r sarif.Report) []string {
	var out []string
	for _, u := range r.Unchecked {
		out = append(out, u.Group+":"+u.Check+":"+u.Reason)
	}
	slices.Sort(out)
	return out
}

// The scan of a subscription: the framework's checks listed from Prowler, the subscription confirmed
// readable, then one Prowler run. The command line is the thing that keeps secrets out of the run:
// the App service and the Shodan check are excluded on every run.
func TestProwlerChecksAnAzureSubscription(t *testing.T) {
	f := &fakeProwler{
		checks: []string{"storage_ensure_minimum_tls_version_12", "iam_subscription_roles_owner_custom_not_created"},
		findings: []map[string]any{
			ocsf("storage_ensure_minimum_tls_version_12", "FAIL", "high", "eastus",
				"/subscriptions/"+shopSubscription+"/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/shop"),
			ocsf("iam_subscription_roles_owner_custom_not_created", "PASS", "medium", "global", "/subscriptions/"+shopSubscription),
		},
	}
	f.findings[0]["unmapped"] = map[string]any{"compliance": map[string][]string{"CIS-6.0": {"10.3.1"}}}
	azure := &fakeAzure{grants: []azureaccess.Permission{{Actions: []string{"*/read"}}}}
	report, err := newTestAzure(f, azure).Scan(context.Background(), shopAzure, nil)
	if err != nil {
		t.Fatal(err)
	}
	if azure.asked != shopSubscription {
		t.Errorf("asked about %q", azure.asked)
	}
	if want := []string{"prowler", "azure", "--list-checks-json", "--compliance", "cis_6.0_azure"}; !slices.Equal(f.argv[0], want) {
		t.Errorf("check list argv = %v, want %v", f.argv[0], want)
	}
	scan := f.argv[1]
	dir := argAfter(scan, "--output-directory")
	want := []string{
		"prowler", "azure", "--az-cli-auth", "--subscription-id", shopSubscription,
		"--excluded-service", "app", "entra", "--excluded-check", "network_public_ip_shodan",
		"--compliance", "cis_6.0_azure",
		"--output-formats", "json-ocsf", "--output-directory", dir, "--output-filename", "scan",
		// WARNING and not ERROR: a denied Key Vault read is logged at WARNING.
		"--log-level", "WARNING", "--log-file", filepath.Join(dir, "prowler.log"), "--only-logs", "--no-color",
		"--ignore-exit-code-3",
	}
	if !slices.Equal(scan, want) {
		t.Errorf("scan argv = %v\nwant %v", scan, want)
	}
	if len(report.Results) != 1 || !strings.HasSuffix(report.Results[0].Location.URI, "/storageAccounts/shop") {
		t.Fatalf("results = %+v, want the storage account at its resource ID", report.Results)
	}
	rule := report.Rules["prowler/storage_ensure_minimum_tls_version_12"]
	if len(rule.Taxa) != 1 || rule.Taxa[0] != (sarif.Taxon{Taxonomy: "CIS Microsoft Azure Foundations Benchmark", ID: "10.3.1", Version: "6.0"}) {
		t.Errorf("taxa = %+v", rule.Taxa)
	}
	got := report.Provenance[0].Describe()
	for _, part := range []string{"benchmark: cis_6.0_azure", "coverage: 2 of 2 checks decided", "scope: whole account",
		"permissions: listed before the scan, then read from Prowler's log"} {
		if !strings.Contains(got, part) {
			t.Errorf("provenance = %q, want %q in it", got, part)
		}
	}
	if len(report.Unchecked) != 0 {
		t.Errorf("unchecked = %+v, want none under Reader", report.Unchecked)
	}
}

// The flag follows the environment, so Prowler is left with the credential the preflight asked with.
func TestProwlerAzureAuthFlagFollowsTheEnvironment(t *testing.T) {
	f := &fakeProwler{checks: []string{"a_b"}, findings: []map[string]any{ocsf("a_b", "PASS", "low", "global", "x")}}
	s := newTestAzure(f, &fakeAzure{grants: []azureaccess.Permission{{Actions: []string{"*/read"}}}})
	env := map[string]string{"AZURE_CLIENT_ID": "a", "AZURE_TENANT_ID": "b", "AZURE_CLIENT_SECRET": "c"}
	s.getenv = func(k string) string { return env[k] }
	if _, err := s.Scan(context.Background(), shopAzure, nil); err != nil {
		t.Fatal(err)
	}
	if got := f.argv[1][2]; got != "--sp-env-auth" {
		t.Errorf("auth flag = %s", got)
	}
}

// The scan stops before Prowler runs where the subscription cannot be reached, as a target not
// reached rather than a report with nothing in it.
func TestProwlerRefusesASubscriptionItCannotRead(t *testing.T) {
	refused := errors.New("subscription " + shopSubscription + " does not exist, or the credentials cannot read it")
	f := &fakeProwler{checks: []string{"a_b"}}
	_, err := newTestAzure(f, &fakeAzure{subErr: refused}).Scan(context.Background(), shopAzure, nil)
	if !errors.Is(err, refused) {
		t.Errorf("err = %v", err)
	}
	if len(f.argv) != 1 {
		t.Errorf("prowler ran %d times, want the check list alone: %v", len(f.argv), f.argv)
	}
	s := newTestAzure(f, &fakeAzure{})
	s.azure = func(context.Context) (azureaccess.Reader, error) { return nil, azureaccess.ErrNoCredentials }
	if _, err := s.Scan(context.Background(), shopAzure, nil); !errors.Is(err, azureaccess.ErrNoCredentials) {
		t.Errorf("no credentials = %v", err)
	}
}

// Credentials holding none of the actions are refused before Prowler runs. The denied recording is what
// such a run gives otherwise: no refusal in the log, and FAILs from the checks that look for something
// absent, which say nothing about the subscription.
func TestProwlerRefusesCredentialsHoldingNoneOfTheActions(t *testing.T) {
	recorded := recordedAzureScan(t, "denied")
	if got := azureLoggedDenials(writeAzureLog(t, recorded.log)); got["monitor"] != "" || got["storage"] != "" {
		t.Fatalf("the recording logs a refusal for an ARM service: %v", got)
	}
	for name, grants := range map[string][]azureaccess.Permission{
		"no role":       nil,
		"no actions":    {{DataActions: []string{"Microsoft.KeyVault/vaults/keys/read"}}},
		"other actions": {{Actions: []string{"Microsoft.Compute/*/read"}}},
	} {
		f := recordedAzureScan(t, "denied")
		_, err := newTestAzure(f, &fakeAzure{grants: grants}).Scan(context.Background(), shopAzure, nil)
		want := "prowler: the credentials hold none of the actions the checks read on subscription " +
			shopSubscription + "; grant Reader"
		if err == nil || err.Error() != want {
			t.Errorf("%s: err = %v", name, err)
		}
		if len(f.argv) != 1 {
			t.Errorf("%s: prowler ran %d times, want the check list alone", name, len(f.argv))
		}
	}
}

// LOG_LEVEL overrides --log-level, and the measured-against line says so where it hides the warnings
// the scan reads. INFO hides none of them.
func TestAnAzureLogLevelHidingWarningsIsSaid(t *testing.T) {
	for level, hides := range map[string]bool{"ERROR": true, "CRITICAL": true, "INFO": false, "": false} {
		f := &fakeProwler{checks: []string{"a_b"}, findings: []map[string]any{ocsf("a_b", "PASS", "low", "global", "x")}}
		s := newTestAzure(f, &fakeAzure{grants: []azureaccess.Permission{{Actions: []string{"*/read"}}}})
		s.getenv = func(k string) string {
			if k == "LOG_LEVEL" {
				return level
			}
			return ""
		}
		report, err := s.Scan(context.Background(), shopAzure, nil)
		if err != nil {
			t.Fatal(err)
		}
		got := report.Provenance[0].Describe()
		if said := strings.Contains(got, "LOG_LEVEL="+level+" hides Prowler's warnings"); said != hides {
			t.Errorf("LOG_LEVEL=%q: provenance = %q", level, got)
		}
	}
}

// writeAzureLog writes a log for azureLoggedDenials to read.
func writeAzureLog(t *testing.T, log string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "prowler.log")
	if err := os.WriteFile(path, []byte(log), 0o600); err != nil { // #nosec G703 -- under the test's own temp directory
		t.Fatal(err)
	}
	return path
}

// The services the recorded logs name, each with the reason the scanner gives. Both logins were refused
// by Graph with Authentication_RequestFromUnsupportedUserRole, accessDenied and AccessDenied, which
// the status line catches whatever the code. FeatureNotSupportedForAccount is a storage account's answer
// about itself, and no denial.
func TestAzureLoggedDenialsReadTheRecordedLogs(t *testing.T) {
	for run, want := range map[string]map[string]string{
		"rich": {
			"entra":         "denied a permission Prowler's log does not name",
			"keyvault-data": "denied a Key Vault data-plane read",
		},
		"denied": {"entra": "denied a permission Prowler's log does not name"},
	} {
		if got := azureLoggedDenials(filepath.Join(azureFixtures, run, "prowler.log")); !maps.Equal(got, want) {
			t.Errorf("%s: denials = %v\nwant %v", run, got, want)
		}
	}
}

// On the recorded run, a check Prowler gave MANUAL is unread with the reason said, one with a result
// keeps its findings marked partly read, and the checks of services nothing happened to stand decided.
func TestProwlerReadsTheRecordedAzureRun(t *testing.T) {
	f := recordedAzureScan(t, "rich")
	azure := &fakeAzure{grants: []azureaccess.Permission{{Actions: []string{"*"}}}}
	report, err := newTestAzure(f, azure).Scan(context.Background(), shopAzure, nil)
	if err != nil {
		t.Fatal(err)
	}
	var rows []string
	for _, u := range report.Unchecked {
		state := "unread"
		if u.PartlyRead {
			state = "partly"
		}
		rows = append(rows, u.Check+":"+state)
	}
	// The recording ran the Entra checks; the scan does not, so their results and rows are not kept.
	want := []string{"keyvault_key_rotation_enabled:partly"}
	if !slices.Equal(rows, want) {
		t.Errorf("rows = %v\nwant %v", rows, want)
	}
	if len(report.Results) == 0 {
		t.Fatal("no results from the recorded run")
	}
	for _, r := range report.Results {
		if r.RuleID == "prowler/entra_non_privileged_user_has_mfa" {
			t.Errorf("a MANUAL check gave a result: %+v", r)
		}
	}
	got := report.Provenance[0].Describe()
	if !strings.Contains(got, "of 88 checks decided") || !strings.Contains(got, "not run: entra_non_privileged_user_has_mfa, entra_policy_guest_users_access_restrictions, entra_privileged_user_has_mfa, entra_security_defaults_enabled, entra_user_with_vm_access_has_mfa, network_public_ip_shodan") {
		t.Errorf("provenance = %q", got)
	}
}

// A MANUAL result with no denial to explain it still raises a row, because Prowler gives one when a
// read failed. A check with a pass or a fail as well is judged on those.
func TestAnAzureCheckProwlerCouldNotEvaluateIsSaid(t *testing.T) {
	f := &fakeProwler{
		checks: []string{"network_a", "network_b", "network_c"},
		findings: []map[string]any{
			ocsf("network_a", "MANUAL", "high", "global", "x"),
			ocsf("network_b", "MANUAL", "high", "global", "y"),
			ocsf("network_b", "PASS", "high", "global", "y"),
			ocsf("network_c", "PASS", "high", "global", "z"),
		},
	}
	report, err := newTestAzure(f, &fakeAzure{grants: []azureaccess.Permission{{Actions: []string{"*/read"}}}}).Scan(context.Background(), shopAzure, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"network:network_a:Prowler could not evaluate it"}
	if rows := unreadGroups(report); !slices.Equal(rows, want) {
		t.Errorf("rows = %v, want %v", rows, want)
	}
	if got := report.Provenance[0].Describe(); !strings.Contains(got, "coverage: 2 of 3 checks decided") {
		t.Errorf("provenance = %q", got)
	}
}

// A preflight Azure refuses or fails is no error, and the measured-against line says which.
func TestAnAzurePreflightNotMadeIsSaid(t *testing.T) {
	for want, grantsErr := range map[string]error{
		"permissions: read from Prowler's log; Azure refused the preflight": azureaccess.ErrRefused,
		"permissions: read from Prowler's log; the preflight failed":        errors.New("502"),
	} {
		f := &fakeProwler{checks: []string{"a_b"}, findings: []map[string]any{ocsf("a_b", "PASS", "low", "global", "x")}}
		report, err := newTestAzure(f, &fakeAzure{grantsErr: grantsErr}).Scan(context.Background(), shopAzure, nil)
		if err != nil {
			t.Fatal(err)
		}
		if got := report.Provenance[0].Describe(); !strings.Contains(got, want) {
			t.Errorf("provenance = %q, want %q in it", got, want)
		}
	}
}

// A check with no result whose service was denied is unread; one with a result keeps its findings and
// is partly read; neither counts as decided. The rest of the framework is judged as usual, and a
// MANUAL result, which Prowler's Entra checks give when they cannot evaluate, is not a verdict.
func TestProwlerJudgesAnAzureDenialPerCheck(t *testing.T) {
	f := &fakeProwler{
		checks: []string{
			"defender_ensure_mcas_is_enabled", "network_ssh_internet_access_restricted", "network_watcher_enabled",
			"storage_ensure_minimum_tls_version_12", "storage_key_rotation_90_days",
		},
		findings: []map[string]any{
			ocsf("network_ssh_internet_access_restricted", "FAIL", "high", "eastus", "/subscriptions/"+shopSubscription+"/nsg"),
			ocsf("defender_ensure_mcas_is_enabled", "MANUAL", "high", "global", "/subscriptions/"+shopSubscription),
			ocsf("storage_ensure_minimum_tls_version_12", "PASS", "high", "eastus", "/subscriptions/"+shopSubscription+"/sa"),
		},
	}
	azure := &fakeAzure{grants: []azureaccess.Permission{
		{Actions: []string{"*/read"}, NotActions: []string{"Microsoft.Network/networkWatchers/read", "Microsoft.Storage/*"}},
	}}
	report, err := newTestAzure(f, azure).Scan(context.Background(), shopAzure, nil)
	if err != nil {
		t.Fatal(err)
	}
	var rows []string
	for _, u := range report.Unchecked {
		state := "unread"
		if u.PartlyRead {
			state = "partly"
		}
		rows = append(rows, u.Check+":"+state+":"+u.Reason)
	}
	want := []string{
		"defender_ensure_mcas_is_enabled:unread:Prowler could not evaluate it",
		"network_ssh_internet_access_restricted:partly:denied Microsoft.Network/networkWatchers/read",
		"network_watcher_enabled:unread:denied Microsoft.Network/networkWatchers/read",
		"storage_ensure_minimum_tls_version_12:partly:denied Microsoft.Storage/storageAccounts/blobServices/read",
		"storage_key_rotation_90_days:unread:denied Microsoft.Storage/storageAccounts/blobServices/read",
	}
	if !slices.Equal(rows, want) {
		t.Errorf("rows = %v\nwant %v", rows, want)
	}
	if len(report.Results) != 1 || report.Results[0].RuleID != "prowler/network_ssh_internet_access_restricted" {
		t.Errorf("results = %+v, want the partly read FAIL kept", report.Results)
	}
	if len(report.Decided) != 0 {
		t.Errorf("decided = %+v, want none: the MANUAL is no verdict and the rest were set aside", report.Decided)
	}
	if got := report.Provenance[0].Describe(); !strings.Contains(got, "coverage: 0 of 5 checks decided") {
		t.Errorf("provenance = %q", got)
	}
}

// The checks the scan keeps from running are named in the measured-against line and raise no row, so
// a run under failOnCaveats does not fail for something nobody can grant. An override selecting
// app_* checks reports them the same way, with no result.
func TestProwlerNamesTheAzureChecksItDoesNotRun(t *testing.T) {
	f := &fakeProwler{
		checks: []string{"app_ftp_deployment_disabled", "appinsights_ensure_is_configured", "network_public_ip_shodan", "network_watcher_enabled"},
		findings: []map[string]any{
			ocsf("appinsights_ensure_is_configured", "PASS", "low", "global", "x"),
			ocsf("network_watcher_enabled", "PASS", "low", "eastus", "y"),
			// Prowler is told not to run this one; a result anyway is not kept.
			ocsf("network_public_ip_shodan", "FAIL", "high", "eastus", "z"),
		},
	}
	azure := &fakeAzure{grants: []azureaccess.Permission{{Actions: []string{"*/read"}, NotActions: []string{"Microsoft.Network/publicIPAddresses/read"}}}}
	report, err := newTestAzure(f, azure).Scan(context.Background(), shopAzure, plugin.Config{"compliance": "cis_2.0_azure"})
	if err != nil {
		t.Fatal(err)
	}
	got := report.Provenance[0].Describe()
	for _, part := range []string{"coverage: 1 of 4 checks decided", "not run: app_ftp_deployment_disabled, network_public_ip_shodan"} {
		if !strings.Contains(got, part) {
			t.Errorf("provenance = %q, want %q in it", got, part)
		}
	}
	if len(report.Results) != 0 {
		t.Errorf("results = %+v", report.Results)
	}
	want := []string{"network:network_watcher_enabled:denied Microsoft.Network/publicIPAddresses/read"}
	if rows := unreadGroups(report); !slices.Equal(rows, want) {
		t.Errorf("rows = %v, want %v: no row for a check that does not run", rows, want)
	}
	if scan := f.argv[1]; argAfter(scan, "--excluded-service") != "app" || argAfter(scan, "app") != "entra" || argAfter(scan, "--excluded-check") != "network_public_ip_shodan" {
		t.Errorf("an override dropped the exclusions: %v", scan)
	}
}

// A Key Vault read refused at the vault is a WARNING, and a denial of the data plane alone: the key
// rotation check is partly read, and the rest of the service's checks stand. The message is
// keyvault_service.py's.
func TestProwlerReadsADeniedKeyVaultWarning(t *testing.T) {
	f := &fakeProwler{
		checks: []string{"keyvault_key_rotation_enabled", "keyvault_recoverable"},
		findings: []map[string]any{
			ocsf("keyvault_key_rotation_enabled", "FAIL", "high", "eastus", "/subscriptions/"+shopSubscription+"/k"),
			ocsf("keyvault_recoverable", "PASS", "high", "eastus", "/subscriptions/"+shopSubscription+"/v"),
		},
		log: azureLogLine("WARNING", "keyvault_service", "Subscription ID: "+shopSubscription+" -- has no access policy configured for keyvault shop") + "\n",
	}
	report, err := newTestAzure(f, &fakeAzure{grants: []azureaccess.Permission{{Actions: []string{"*/read"}}}}).Scan(context.Background(), shopAzure, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Unchecked) != 1 {
		t.Fatalf("unchecked = %+v", report.Unchecked)
	}
	u := report.Unchecked[0]
	if u.Check != "keyvault_key_rotation_enabled" || u.Group != "keyvault-data" || !u.PartlyRead || u.Reason != "denied a Key Vault data-plane read" {
		t.Errorf("row = %+v", u)
	}
	if len(report.Decided) != 1 || report.Decided[0].ID != "keyvault_recoverable" {
		t.Errorf("decided = %+v", report.Decided)
	}
}

// azureARMDenial is a refused Azure Resource Manager read. Neither recording holds one, because a login
// with a wildcard is never refused and one with no role logs nothing. The message is the wording Microsoft
// publishes in its Azure RBAC troubleshooting guide, and the wrapper the one the recorded
// FeatureNotSupportedForAccount line shows for an HttpResponseError.
func azureARMDenial(action string) []string {
	message := "The client 'user@tenant.onmicrosoft.com' with object id '" + shopSubscription +
		"' does not have authorization to perform action '" + action + "' over scope '/subscriptions/" +
		shopSubscription + "' or the scope is invalid."
	return []string{
		azureLogLine("ERROR", "network_service", "Subscription ID: "+shopSubscription+" -- HttpResponseError[1]: (AuthorizationFailed) "+message),
		"Code: AuthorizationFailed",
		"Message: " + message,
	}
}

// A refusal runs over several log lines, so a line with no module belongs to the record above it, and
// the first action in order names the reason, whichever call came first. A failure that is no refusal
// and no failed read, and a refusal outside a service module, leave no service in doubt.
func TestAzureLoggedDenials(t *testing.T) {
	lines := append(azureARMDenial("Microsoft.Network/virtualNetworks/read"), azureARMDenial("Microsoft.Network/bastionHosts/read")...)
	lines = append(lines,
		azureLogLine("ERROR", "monitor_service", "Subscription ID: s -- HttpResponseError[1]: (Forbidden) no action named"),
		azureLogLine("ERROR", "monitor_service", "Subscription ID: s -- HttpResponseError[1]: does not have authorization to perform action 'Microsoft.Insights/diagnosticSettings/read'"),
		azureLogLine("ERROR", "monitor_service", "Subscription ID: s -- HttpResponseError[1]: (Forbidden) again no action named"),
		azureLogLine("ERROR", "defender_service", "Subscription ID: s -- ResourceNotFoundError[1]: Subscription Not Registered"),
		azureLogLine("ERROR", "azure_provider", "ODataError[1]: APIError"),
		"Code: 403",
		azureLogLine("WARNING", "keyvault_service", "KeyVault v in s -- has no vault URI, skipping key rotation policies"),
		azureLogLine("WARNING", "keyvault_service", "Subscription ID: s -- has no access policy configured for keyvault v"),
		azureLogLine("WARNING", "storage_service", "Subscription ID: s -- HttpResponseError[133]: (FeatureNotSupportedForAccount) Blob is not supported for the account."),
		"Code: FeatureNotSupportedForAccount",
	)
	want := map[string]string{
		"network":       "denied Microsoft.Network/bastionHosts/read",
		"monitor":       "denied Microsoft.Insights/diagnosticSettings/read",
		"keyvault-data": "denied a Key Vault data-plane read",
	}
	if got := azureLoggedDenials(writeAzureLog(t, strings.Join(lines, "\n")+"\n")); !maps.Equal(got, want) {
		t.Errorf("denials = %v\nwant %v", got, want)
	}
	if got := azureLoggedDenials(filepath.Join(t.TempDir(), "missing.log")); len(got) != 0 {
		t.Errorf("a missing log = %v", got)
	}
}

// A read that ended with no answer leaves its service in doubt as a refusal does, and a refusal of the
// same service names the reason, since a grant fixes it and a retry may not. The first line is the
// recorded dropped connection; the class names are httpx's and azure-core's.
func TestAzureFailedReadsLeaveTheServiceInDoubt(t *testing.T) {
	dropped := azureLogLine("ERROR", "entra_service", "tenant.onmicrosoft.com -- RemoteProtocolError[188]: <ConnectionTerminated error_code:0, last_stream_id:2147483647, additional_data:None>")
	got := azureLoggedDenials(writeAzureLog(t, strings.Join([]string{
		dropped,
		azureLogLine("ERROR", "storage_service", "Subscription ID: s -- ServiceRequestError[1]: connection reset"),
		azureLogLine("ERROR", "network_service", "Subscription ID: s -- ReadTimeout[1]: timed out"),
		azureLogLine("ERROR", "network_service", "Subscription ID: s -- ConnectError[1]: unreachable"),
		azureLogLine("ERROR", "monitor_service", "ODataError[1]: "),
		"        APIError",
		"        Code: 503",
		azureLogLine("ERROR", "iam_service", "ODataError[1]: "),
		"        Code: 429",
	}, "\n")+"\n"))
	want := map[string]string{
		"entra":   "read failed, RemoteProtocolError",
		"storage": "read failed, ServiceRequestError",
		"network": "read failed, ConnectError",
		"monitor": "read failed, HTTP 503",
		"iam":     "read failed, HTTP 429",
	}
	if !maps.Equal(got, want) {
		t.Errorf("failed reads = %v\nwant %v", got, want)
	}
	got = azureLoggedDenials(writeAzureLog(t, strings.Join(append([]string{dropped},
		azureLogLine("ERROR", "entra_service", "ODataError[1]: "), "        Code: 403"), "\n")+"\n"))
	if got["entra"] != azureUnnamedDenial {
		t.Errorf("a denial beside a failed read = %v", got)
	}
}

// Each action asked about belongs to a service some check reads, sorted and once, and is one action
// rather than a pattern: an action Azure's list does not hold reads as denied for everybody.
func TestAzureActionsBelongToServicesTheChecksRead(t *testing.T) {
	read := map[string]bool{}
	for _, check := range cisAzureChecks(t) {
		for _, s := range prowlerClouds["azure"].checkReads(check) {
			read[s] = true
		}
	}
	for service, actions := range azureServiceActions {
		if !read[service] {
			t.Errorf("%s is asked about and no check reads it", service)
		}
		if !slices.IsSorted(actions) || len(slices.Compact(slices.Clone(actions))) != len(actions) {
			t.Errorf("%s: %v, want sorted and each once", service, actions)
		}
		for _, a := range actions {
			if !strings.HasPrefix(a, "Microsoft.") || strings.ContainsAny(a, "*?") {
				t.Errorf("%s: %q is not one action", service, a)
			}
		}
	}
	if got := azureDeniedServices([]string{"Microsoft.Network/virtualNetworks/read", "Microsoft.Network/bastionHosts/read"}); got["network"] != "denied Microsoft.Network/bastionHosts/read" || len(got) != 1 {
		t.Errorf("denied services = %v", got)
	}
	if len(slices.Compact(azureActions())) != len(azureActions()) {
		t.Errorf("an action is asked about twice: %v", azureActions())
	}
}

// cisAzureChecks is the check list of cis_6.0_azure in Prowler 5.48.0, from
// `prowler azure --list-checks-json`. It holds no app_* check and one Shodan check. It is a file
// because one of Prowler's check names carries a typo the spelling gates would refuse in Go source.
func cisAzureChecks(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "prowler-azure", "cis_6.0_azure.checks"))
	if err != nil {
		t.Fatal(err)
	}
	return strings.Fields(string(data))
}

// The default framework runs no App service check. The scan keeps from running its five Entra checks,
// which read the whole tenant's directory, and the one that would send data to a third party, so its
// coverage reads at most six short of the list.
func TestTheDefaultAzureFrameworkLeavesTheEntraChecksAndShodanNotRun(t *testing.T) {
	checks := cisAzureChecks(t)
	var notRun []string
	for _, check := range checks {
		if azureNotRun(check) {
			notRun = append(notRun, check)
		}
	}
	if !slices.Equal(notRun, []string{
		"entra_non_privileged_user_has_mfa", "entra_policy_guest_users_access_restrictions", "entra_privileged_user_has_mfa",
		"entra_security_defaults_enabled", "entra_user_with_vm_access_has_mfa", "network_public_ip_shodan",
	}) {
		t.Errorf("not run = %v", notRun)
	}
	// Every listed exception belongs to the framework, so none is left over from another release.
	for check := range azureCheckReads {
		if !slices.Contains(checks, check) {
			t.Errorf("%s has its reads listed and is not in the framework", check)
		}
	}
	azure := prowlerClouds["azure"]
	if got := azure.checkReads("keyvault_logging_enabled"); !slices.Equal(got, []string{"keyvault", "monitor"}) {
		t.Errorf("a listed check = %v", got)
	}
	if got := azure.checkReads("storage_geo_redundant_enabled"); !slices.Equal(got, []string{"storage"}) {
		t.Errorf("an unlisted check = %v", got)
	}
}

// An Azure resource ID locates a finding, whatever Prowler calls the resource, and the subscription's
// own ID is the account.
func TestProwlerLocatesAnAzureFinding(t *testing.T) {
	finding := func(uid, name string) ocsfFinding {
		var f ocsfFinding
		f.Resources = append(f.Resources, struct {
			UID    string `json:"uid"`
			Name   string `json:"name"`
			Region string `json:"region"`
		}{UID: uid, Name: name})
		return f
	}
	nsg := "/subscriptions/" + shopSubscription + "/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/web"
	for _, c := range []struct {
		f    ocsfFinding
		want string
	}{
		{finding(nsg, "web"), nsg},
		{finding("/subscriptions/"+shopSubscription, "Shop"), "azure/" + shopSubscription},
		{finding("/SUBSCRIPTIONS/"+shopSubscription, "Shop"), "azure/" + shopSubscription},
		{ocsfFinding{}, "azure/" + shopSubscription},
	} {
		if got := prowlerLocation(shopAzure, c.f); got != c.want {
			t.Errorf("prowlerLocation(%+v) = %q, want %q", c.f.Resources, got, c.want)
		}
	}
}

// A component claiming regions gets the findings in them; a finding with no region, or Prowler's
// "global", goes to the component declaring the whole subscription. No flag narrows the scan.
func TestProwlerNarrowsAzureFindingsToTheClaimedRegions(t *testing.T) {
	f := &fakeProwler{
		checks: []string{"network_ssh_internet_access_restricted", "iam_role_user_access_admin_restricted", "defender_ensure_defender_for_server_is_on"},
		findings: []map[string]any{
			ocsf("network_ssh_internet_access_restricted", "FAIL", "high", "eastus", "/subscriptions/"+shopSubscription+"/a"),
			ocsf("network_ssh_internet_access_restricted", "FAIL", "high", "westeurope", "/subscriptions/"+shopSubscription+"/b"),
			ocsf("iam_role_user_access_admin_restricted", "FAIL", "high", "global", "/subscriptions/"+shopSubscription+"/c"),
			ocsf("defender_ensure_defender_for_server_is_on", "FAIL", "high", "", "/subscriptions/"+shopSubscription),
		},
	}
	narrowed := shopAzure
	narrowed.Regions = []string{"EASTUS"}
	report, err := newTestAzure(f, &fakeAzure{grants: []azureaccess.Permission{{Actions: []string{"*/read"}}}}).Scan(context.Background(), narrowed, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Results) != 1 || !strings.HasSuffix(report.Results[0].Location.URI, "/a") {
		t.Errorf("results = %+v, want the eastus resource alone", report.Results)
	}
	if slices.Contains(f.argv[1], "--region") || slices.Contains(f.argv[1], "--azure-region") {
		t.Errorf("argv = %v", f.argv[1])
	}
	if got := report.Provenance[0].Describe(); !strings.Contains(got, "scope: 1 region EASTUS") {
		t.Errorf("provenance = %q", got)
	}
	whole, err := newTestAzure(f, &fakeAzure{grants: []azureaccess.Permission{{Actions: []string{"*/read"}}}}).Scan(context.Background(), shopAzure, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(whole.Results) != len(f.findings) {
		t.Errorf("whole subscription = %d results, want %d", len(whole.Results), len(f.findings))
	}
}
