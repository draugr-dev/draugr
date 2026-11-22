//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/draugr-dev/draugr/internal/tools"
)

// requireKICSImage skips, or in a strict job fails, where Docker or the pinned KICS image is
// missing, the way requireTool decides about a binary.
func requireKICSImage(t *testing.T) {
	t.Helper()
	requireTool(t, "docker", "the kics scanner runs KICS from its image")
	// #nosec G204 -- a fixed binary and the image reference this build pins.
	if err := exec.Command("docker", "image", "inspect", "--format", "{{.Id}}", tools.KICSImage).Run(); err == nil {
		return
	}
	if os.Getenv(strictEnv) != "" {
		t.Fatalf("the KICS image %s is not on this machine, and %s is set. The job pulls it, so this "+
			"is the provisioning being wrong rather than the test being unrunnable", tools.KICSImage, strictEnv)
	}
	t.Skipf("the KICS image is not on this machine: run `docker pull %s` to run this test; set %s to "+
		"make a missing image a failure instead", tools.KICSImage, strictEnv)
}

// TestKICSRunsBesideTrivyWithTheNetworkCut runs the real image, with the network cut as every scan
// runs it, over two repositories of one component that each hold a privileged container, and expects
// a complete report: both scanners ran, KICS found what it finds offline, and in each repository the
// privileged setting both tools flag is counted once.
func TestKICSRunsBesideTrivyWithTheNetworkCut(t *testing.T) {
	requireKICSImage(t)
	requireTool(t, "trivy", "trivy-config is the default iac scanner KICS runs beside")
	requireTool(t, "git", "the scan checks the repositories out before scanning them")

	manifest := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: shop
spec:
  selector:
    matchLabels:
      app: web
  template:
    metadata:
      labels:
        app: web
    spec:
      containers:
        - name: web
          image: nginx:1.27.3
          securityContext:
            privileged: true
`
	repos := []string{
		newRepo(t, map[string]string{"web.yaml": manifest}),
		newRepo(t, map[string]string{"web.yaml": manifest}),
	}
	dir := t.TempDir()
	writeFile(t, dir, "draugr.saga.yaml", fmt.Sprintf(`project: kics-integration
release: { version: "1.0" }
config:
  gate: { failOn: critical }
  controls:
    iac:
      enabled: true
      kics: { enabled: true }
components:
  - name: platform
    exposure: internal
    criticality: supporting
    repositories:
      - url: %s
      - url: %s
`, repos[0], repos[1]))

	out := scanTo(t, dir, "draugr.saga.yaml")
	requireControlRan(t, out, "iac", "kics")
	requireControlRan(t, out, "iac", "trivy-config")

	body, err := os.ReadFile(filepath.Join(out, "results.sarif")) // #nosec G304 -- written by the scan into t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Runs []struct {
			Results []struct {
				RuleID     string `json:"ruleId"`
				Properties struct {
					Tool        string `json:"tool"`
					Repository  string `json:"repository"`
					Correlation *struct {
						CountedUnder string `json:"countedUnder"`
						AlsoFoundBy  []struct {
							RuleID string `json:"ruleId"`
						} `json:"alsoFoundBy"`
					} `json:"correlation"`
				} `json:"properties"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	kics, joined := 0, map[string]int{}
	for _, run := range doc.Runs {
		for _, r := range run.Results {
			if r.Properties.Tool == "KICS" {
				kics++
			}
			// Both rate it high, and Trivy's copy carries a score, so Trivy's is the one counted.
			c := r.Properties.Correlation
			if r.RuleID == "KSV-0017" && c != nil && c.CountedUnder == "" &&
				len(c.AlsoFoundBy) == 1 && c.AlsoFoundBy[0].RuleID == "dd29336b-fe57-445b-a26e-e6aa867ae609" {
				joined[r.Properties.Repository]++
			}
			if r.RuleID == "dd29336b-fe57-445b-a26e-e6aa867ae609" && (c == nil || c.CountedUnder != "Trivy") {
				t.Errorf("KICS's privileged finding in %s is not counted under Trivy's copy: %+v", r.Properties.Repository, c)
			}
		}
	}
	if kics == 0 {
		t.Error("KICS produced no findings with the network cut")
	}
	if len(joined) != 2 {
		t.Errorf("the privileged container was counted once in %d repositories, want both: %v", len(joined), joined)
	}
}
