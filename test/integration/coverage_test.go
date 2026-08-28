//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"k8s.io/client-go/tools/clientcmd"
)

// scanTo runs the built binary against a descriptor and returns the console output and the SARIF
// path. A non-zero exit is expected wherever findings trip the gate.
func scanTo(t *testing.T, dir, saga string) (string, string) {
	t.Helper()
	out := t.TempDir()
	// #nosec G204 -- the binary under test, against a descriptor this test wrote into t.TempDir().
	cmd := exec.Command(draugrBin(t), "scan", saga, "--output", out, "--log-level", "warn")
	cmd.Dir = dir
	combined, err := cmd.CombinedOutput()
	t.Logf("draugr scan %s exit=%v\n%s", saga, err, combined)
	return string(combined), filepath.Join(out, "results.sarif")
}

// toolsInSARIF returns the set of scanners that produced a finding, read from the report rather
// than the console — the console shows a shortlist, and a scanner with nothing to say about a
// fixture is not the same as one that never ran.
func toolsInSARIF(t *testing.T, path string) map[string]int {
	t.Helper()
	body, err := os.ReadFile(path) // #nosec G304 -- a path the scan just wrote into t.TempDir()
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var doc struct {
		Runs []struct {
			Results []struct {
				Properties struct {
					Tool string `json:"tool"`
				} `json:"properties"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("parse SARIF: %v", err)
	}
	seen := map[string]int{}
	for _, run := range doc.Runs {
		for _, r := range run.Results {
			seen[r.Properties.Tool]++
		}
	}
	return seen
}

// TestGrypeRunsBesideTrivy covers the scanner shipped as an opt-in second opinion, which nothing
// exercised: enabling it has to actually add a scanner rather than being accepted and ignored.
//
// It asserts that both tools produced findings, not how many or which. Counts drift with every
// database refresh, and a test that pinned them would fail for reasons that are not about Draugr.
func TestGrypeRunsBesideTrivy(t *testing.T) {
	requireTool(t, "trivy", "this test is the default scanner and the opt-in one running together")
	requireTool(t, "grype", "grype is the opt-in scanner under test")
	requireTool(t, "git", "the scan checks the repository out before scanning it")

	repo := newVulnRepo(t)
	dir := t.TempDir()
	writeFile(t, dir, "draugr.saga.yaml", fmt.Sprintf(`release: { name: grype-integration, version: "1.0" }
config:
  controllers:
    sca:
      enabled: true
      grypeFs: { enabled: true }
components:
  - name: app
    exposure:
      value: internal
    criticality:
      value: supporting
    repositories:
      - url: %s
`, repo))

	_, sarifPath := scanTo(t, dir, "draugr.saga.yaml")
	tools := toolsInSARIF(t, sarifPath)
	// The report names the tool rather than the scanner — "trivy", not "trivy-fs" — because that
	// is what a reader recognizes. Only sca is enabled here, so each can only be its repository
	// scanner.
	for _, want := range []string{"trivy", "grype"} {
		if tools[want] == 0 {
			t.Errorf("%s produced no findings, so enabling it did nothing: %v", want, tools)
		}
	}
}

// TestLicensesControlRunsOverARepository covers the licenses control, which shipped with no
// integration coverage. The fixture declares dependencies with known licenses.
func TestLicensesControlRunsOverARepository(t *testing.T) {
	requireTool(t, "trivy", "trivy-license is the scanner under test")
	requireTool(t, "git", "the scan checks the repository out before scanning it")

	repo := newVulnRepo(t)
	dir := t.TempDir()
	writeFile(t, dir, "draugr.saga.yaml", fmt.Sprintf(`release: { name: licenses-integration, version: "1.0" }
config:
  controllers:
    licenses: { enabled: true }
components:
  - name: app
    exposure:
      value: internal
    criticality:
      value: supporting
    repositories:
      - url: %s
`, repo))

	console, _ := scanTo(t, dir, "draugr.saga.yaml")
	// The control has to appear in the report. Whether this fixture's licenses are worth
	// reporting is the scanner's judgement; that the control ran is Draugr's.
	if !strings.Contains(console, "licenses") {
		t.Errorf("the licenses control is absent from the report, so it did not run:\n%s", console)
	}
	if strings.Contains(console, "licenses  ERROR") {
		t.Errorf("the licenses control could not run:\n%s", console)
	}
}

// TestInfrastructureControlAuditsTheCluster covers the infrastructure control against the kind
// cluster the workflow already stands up. Its default scanner is native, so this needs no binary —
// only a reachable cluster, which is the one thing this job has and unit tests cannot fake.
func TestInfrastructureControlAuditsTheCluster(t *testing.T) {
	// Asking the cluster rather than assuming one: this file's other tests run without it.
	clientset(t)

	// `ref` selects a kubeconfig context by name, and the name depends on what created the
	// cluster — kind calls it "kind-<cluster>" — so hard-coding one would pass on the machine it
	// was written on and fail everywhere else.
	dir := t.TempDir()
	writeFile(t, dir, "draugr.saga.yaml", fmt.Sprintf(`release: { name: infra-integration, version: "1.0" }
config:
  controllers:
    infrastructure: { enabled: true }
components:
  - name: cluster
    exposure:
      value: internal
    criticality:
      value: critical
    infrastructure:
      - kind: kubernetes
        ref: %s
`, currentKubeContext(t)))

	console, _ := scanTo(t, dir, "draugr.saga.yaml")
	if !strings.Contains(console, "infrastructure") {
		t.Errorf("the infrastructure control is absent from the report:\n%s", console)
	}
	if strings.Contains(console, "infrastructure  ERROR") {
		t.Errorf("the infrastructure control could not run against a real cluster:\n%s", console)
	}
}

// TestDiffGatesOnNewFindingsOnly covers the command teams actually put in a pull-request gate, and
// which had no end-to-end coverage at all.
//
// The property that matters is the one the command exists for: an unchanged repository introduces
// nothing, so the gate passes even though the findings are still there. Inheriting a backlog must
// not block every change.
func TestDiffGatesOnNewFindingsOnly(t *testing.T) {
	requireTool(t, "gitleaks", "the diff needs a scanner that reliably produces findings")
	requireTool(t, "git", "the scan checks the repository out before scanning it")

	repo := newVulnRepo(t)
	base := t.TempDir()
	head := t.TempDir()
	for _, out := range []string{base, head} {
		// #nosec G204 -- the binary under test, against a fixture repository in t.TempDir().
		cmd := exec.Command(draugrBin(t), "scan", repo, "--output", out, "--log-level", "warn")
		combined, err := cmd.CombinedOutput()
		t.Logf("scan exit=%v\n%s", err, combined)
	}

	baseSarif := filepath.Join(base, "results.sarif")
	headSarif := filepath.Join(head, "results.sarif")
	// #nosec G204 -- both paths are t.TempDir() outputs written above.
	diff := exec.Command(draugrBin(t), "diff", baseSarif, headSarif, "--fail-on-new", "error")
	out, err := diff.CombinedOutput()
	t.Logf("draugr diff exit=%v\n%s", err, out)

	if err != nil {
		t.Errorf("two scans of one unchanged repository introduced nothing, so the gate should "+
			"pass — inheriting a backlog must not block every change:\n%s", out)
	}
	if !strings.Contains(string(out), "new") && !strings.Contains(string(out), "New") {
		t.Errorf("the diff never reported what it compared:\n%s", out)
	}
}

// currentKubeContext is the context the ambient kubeconfig is pointed at.
func currentKubeContext(t *testing.T) string {
	t.Helper()
	raw, err := clientcmd.NewDefaultClientConfigLoadingRules().Load()
	if err != nil {
		t.Fatalf("read kubeconfig: %v", err)
	}
	if raw.CurrentContext == "" {
		t.Fatal("the kubeconfig names no current context, so there is no cluster to audit")
	}
	return raw.CurrentContext
}
