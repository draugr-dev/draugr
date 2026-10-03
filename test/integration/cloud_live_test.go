//go:build integration

package integration

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The cloud control against a real Google Cloud project: the fixture draugr-ops keeps,
// misconfigured on purpose and holding nothing.
//
// The unit tests drive a fake Prowler that writes what the scanner expects to read. What only a real
// project proves is that Prowler still writes it: the OCSF a Google Cloud finding carries, the
// region values, the log lines for a denial, and that every permission the preflight asks Google
// about is one Google accepts. Any of those moving turns the control quietly wrong, and none of
// them would change a unit test.
const (
	// cloudLiveProjectEnv names the fixture project. Unset, the test is skipped.
	cloudLiveProjectEnv = "DRAUGR_CLOUD_LIVE_PROJECT"
	// cloudLiveExpectEnv says which identity the job signed in as: "full", holding what Prowler
	// documents, or "narrow", which can see the project and read none of its services.
	cloudLiveExpectEnv = "DRAUGR_CLOUD_LIVE_EXPECT"
)

func TestLiveCloudAccount(t *testing.T) {
	project := os.Getenv(cloudLiveProjectEnv)
	if project == "" {
		t.Skipf("set %s to the fixture project, and %s to full or narrow, to scan a real Google Cloud project",
			cloudLiveProjectEnv, cloudLiveExpectEnv)
	}
	expect := os.Getenv(cloudLiveExpectEnv)
	requireTool(t, "prowler", "the cloud control's scanner")

	dir := t.TempDir()
	descriptor := filepath.Join(dir, "draugr.saga.yaml")
	body := "project: cloud-fixture\nrelease: {version: \"1\"}\nconfig:\n  controls:\n    cloud: {enabled: true}\n" +
		"accounts:\n  fixture: {provider: gcp, project: " + project + "}\n" +
		"components:\n  - name: platform\n    cloud: [{account: fixture}]\n" +
		"  - name: network\n    cloud: [{account: fixture, regions: [us-central1]}]\n"
	if err := os.WriteFile(descriptor, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out")
	// #nosec G204 -- the binary under test, from $DRAUGR_BIN or LookPath, with arguments this test wrote
	cmd := exec.Command(draugrBin(t), "scan", descriptor, "--output", out, "--allow-scan-errors", "--log-level", "warn")
	cmd.Dir = dir
	if console, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("draugr scan: %v\n%s", err, console)
	}
	data, err := os.ReadFile(filepath.Join(out, "report.json")) // #nosec G304 -- a file this test's scan wrote
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Controls []struct {
			Name       string   `json:"name"`
			ScanErrors []string `json:"scanErrors"`
		} `json:"controls"`
		Targets []struct {
			Kind, Target, Status, Detail string
		} `json:"targets"`
		UnreadChecks []struct {
			Component string   `json:"component"`
			Service   string   `json:"service"`
			Checks    []string `json:"checks"`
			Reason    string   `json:"reason"`
		} `json:"unreadChecks"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	// Each finding with its component, which the SARIF carries and report.json's summary does not.
	sarifData, err := os.ReadFile(filepath.Join(out, "results.sarif")) // #nosec G304 -- a file this test's scan wrote
	if err != nil {
		t.Fatal(err)
	}
	var log struct {
		Runs []struct {
			Results []struct {
				RuleID     string `json:"ruleId"`
				Properties struct {
					Component string `json:"component"`
				} `json:"properties"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(sarifData, &log); err != nil {
		t.Fatal(err)
	}
	for _, c := range doc.Controls {
		if c.Name == "cloud" && len(c.ScanErrors) > 0 {
			t.Fatalf("the cloud control did not run cleanly: %v", c.ScanErrors)
		}
	}
	for _, target := range doc.Targets {
		if target.Kind == "account" && target.Status != "reached" {
			t.Fatalf("the fixture was not reached: %s %s", target.Status, target.Detail)
		}
	}

	unread := map[string]bool{}
	for _, u := range doc.UnreadChecks {
		unread[u.Service] = true
		if !strings.HasPrefix(u.Reason, "denied ") {
			t.Errorf("%s's reason names no permission: %q", u.Service, u.Reason)
		}
	}
	switch expect {
	case "narrow":
		// It can see the project and read none of its services.
		if !unread["compute"] {
			t.Errorf("a scan that cannot read compute left it unlisted: %+v", doc.UnreadChecks)
		}
	default:
		// Everything Prowler documents is held, so nothing is unread, and the fixture's open firewall
		// is found, by the component that declares the network's region.
		if len(doc.UnreadChecks) > 0 {
			t.Errorf("a full scan left checks unread: %+v", doc.UnreadChecks)
		}
		var found []string
		for _, run := range log.Runs {
			for _, r := range run.Results {
				found = append(found, r.Properties.Component+" "+r.RuleID)
			}
		}
		for _, want := range []string{
			"network prowler/compute_firewall_ssh_access_from_the_internet_allowed",
			"network prowler/compute_firewall_rdp_access_from_the_internet_allowed",
		} {
			if !slices.Contains(found, want) {
				t.Errorf("missing %q among %v", want, found)
			}
		}
	}
}
