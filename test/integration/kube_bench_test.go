//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/draugr-dev/draugr/internal/tools"
)

// kubeBenchFallbackBenchmark is the benchmark kube-bench applies when it cannot tell which
// Kubernetes version it is auditing. It assumes 1.18 and maps that to a benchmark written for 1.16,
// so a vanilla cluster reported against it was audited against the wrong standard.
const kubeBenchFallbackBenchmark = "cis-1.6"

// kubeBenchRulePrefix namespaces both kube-bench scanners' rule ids. The rest of the id is the CIS
// check number, the same value the run's decided list carries.
const kubeBenchRulePrefix = "kube-bench/cis/"

// The CIS sections each scanner asks kube-bench for. A finding outside them means the targets
// Draugr passed were not the targets kube-bench ran.
var (
	policiesSection = regexp.MustCompile(`^kube-bench/cis/5(\.\d+)+$`)
	nodeSections    = regexp.MustCompile(`^kube-bench/cis/[1-4](\.\d+)+$`)
)

// TestKubeBenchAuditsTheClusterPolicies runs the kube-bench scanner, the binary
// `draugr tools install` pins, against the kind cluster. Unit tests feed the parser recorded JSON,
// so a kube-bench release that changes its flags, its output or where it reads its benchmark
// definitions passes every one of them. This is the test a bump of the pin has to pass.
func TestKubeBenchAuditsTheClusterPolicies(t *testing.T) {
	requireTool(t, "kube-bench", "kube-bench is the scanner under test")
	requireTool(t, "kubectl", "every section 5 check kube-bench runs shells out to kubectl")
	// A missing kubeconfig fails the test here, with a message that says so.
	clientset(t)

	dir := t.TempDir()
	writeFile(t, dir, "draugr.saga.yaml", fmt.Sprintf(`project: kube-bench-integration
release: { version: "1.0" }
config:
  controls:
    kubernetes:
      enabled: true
      # Off, so every finding and every decided check in the report is kube-bench's.
      draugrK8sPolicies: { enabled: false }
      kubeBench: { enabled: true }
clusters:
  kind:
    context: %s
components:
  - name: cluster
    exposure: internal
    criticality: critical
    kubernetes:
      - cluster: kind
`, currentKubeContext(t)))

	out := scanTo(t, dir, "draugr.saga.yaml")
	requireControlRan(t, out, "kubernetes", "kube-bench")

	// Another kube-bench earlier on PATH would make this a test of that binary rather than of the
	// pin, and a bump would then change nothing the test runs.
	want := "kube-bench@" + tools.PinnedVersion("kube-bench")
	if got := scannerVersion(t, out, "kube-bench"); got != want {
		t.Errorf("the scan ran kube-bench %q, want the pinned %q", got, want)
	}
	requireKubeBenchAudited(t, out, "kube-bench", policiesSection)
}

// TestKubeBenchJobAuditsTheNodes runs the kube-bench-job scanner, which starts the digest-pinned
// image as a Job, against the kind cluster's node. A fake clientset cannot schedule a pod, mount a
// host path or stream its logs, so only a real cluster shows the image's kube-bench reading a node
// and its output reaching the parser. This is the test a bump of the image digest has to pass.
func TestKubeBenchJobAuditsTheNodes(t *testing.T) {
	cs := clientset(t)

	dir := t.TempDir()
	writeFile(t, dir, "draugr.saga.yaml", fmt.Sprintf(`project: kube-bench-job-integration
release: { version: "1.0" }
config:
  # The Job is a privileged pod Draugr creates in the cluster, and the scan refuses to create it
  # until both effects are accepted.
  allowEffects: [mutate, privilege]
  controls:
    kubernetes:
      enabled: true
      # Off, so every finding and every decided check in the report is the Job's.
      draugrK8sPolicies: { enabled: false }
      kubeBenchJob: { enabled: true }
clusters:
  kind:
    context: %s
components:
  - name: cluster
    exposure: internal
    criticality: critical
    kubernetes:
      - cluster: kind
`, currentKubeContext(t)))

	out := scanTo(t, dir, "draugr.saga.yaml")
	requireControlRan(t, out, "kubernetes", "kube-bench-job")
	requireKubeBenchAudited(t, out, "kube-bench-job", nodeSections)
	requireNoJobLeftBehind(t, cs)
}

// requireKubeBenchAudited fails unless the tool's part of results.sarif has the shape a real
// kube-bench run against the cluster produces. None of the assertions names a check or a count,
// so a kind release or a benchmark revision that renumbers checks or changes which ones fail
// leaves them standing:
//
//   - Findings, all in the sections the scanner asked for. Most CIS checks are manual, and
//     kube-bench reports every manual check as WARN, so a run that produced none did not run the
//     benchmark.
//   - A cis-* benchmark other than kube-bench's fallback. kind is vanilla Kubernetes, and the
//     fallback means kube-bench never learned the cluster's version.
//   - At least one check decided with no finding, a PASS. kube-bench that cannot reach what it
//     inspects, the cluster through kubectl or the node's files through its mounts, still reports
//     its checks, as FAIL or WARN, so a PASS is the evidence that it reached them.
func requireKubeBenchAudited(t *testing.T, outDir, tool string, section *regexp.Regexp) {
	t.Helper()
	ev := kubeBenchEvidenceIn(t, outDir, tool)

	if len(ev.ruleIDs) == 0 {
		t.Errorf("%s reported no findings, and kube-bench reports every manual check as one, so it "+
			"did not run the benchmark", tool)
	}
	for _, id := range ev.ruleIDs {
		if !section.MatchString(id) {
			t.Errorf("%s reported %s, outside the sections it asks kube-bench for (%s)", tool, id, section)
		}
	}
	if !strings.HasPrefix(ev.benchmark, "cis-") || ev.benchmark == kubeBenchFallbackBenchmark {
		t.Errorf("%s audited the vanilla kind cluster against benchmark %q, want a cis-* benchmark "+
			"other than kube-bench's fallback %s", tool, ev.benchmark, kubeBenchFallbackBenchmark)
	}
	if len(ev.passed) == 0 {
		t.Errorf("%s passed no check, so kube-bench never reached what it inspects; findings: %v",
			tool, ev.ruleIDs)
	}
	t.Logf("%s: benchmark %s, %d findings, %d checks passed", tool, ev.benchmark, len(ev.ruleIDs), len(ev.passed))
}

// kubeBenchEvidence is one kube-bench scanner's part of results.sarif.
type kubeBenchEvidence struct {
	// ruleIDs are its findings, one per FAIL or WARN.
	ruleIDs []string
	// benchmark is the benchmark kube-bench reported having applied.
	benchmark string
	// passed are the CIS checks decided with no finding.
	passed []string
}

// kubeBenchEvidenceIn reads a tool's findings, benchmark and passed checks from results.sarif.
//
// The decided list carries no scanner name, so it is read as the tool's own. That holds because
// each test here turns every other scanner of the control off.
func kubeBenchEvidenceIn(t *testing.T, outDir, tool string) kubeBenchEvidence {
	t.Helper()
	path := filepath.Join(outDir, "results.sarif")
	body, err := os.ReadFile(path) // #nosec G304 -- a file the scan just wrote into t.TempDir()
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var doc struct {
		Runs []struct {
			Properties struct {
				Provenance []struct {
					Tool   string            `json:"tool"`
					Fields map[string]string `json:"fields"`
				} `json:"draugr/provenance"`
				Decided []struct {
					Taxonomy string `json:"taxonomy"`
					ID       string `json:"id"`
				} `json:"decided"`
			} `json:"properties"`
			Results []struct {
				RuleID     string `json:"ruleId"`
				Properties struct {
					Tool string `json:"tool"`
				} `json:"properties"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("parse SARIF: %v", err)
	}

	var ev kubeBenchEvidence
	reported := map[string]bool{}
	for _, run := range doc.Runs {
		for _, r := range run.Results {
			if r.Properties.Tool != tool {
				continue
			}
			ev.ruleIDs = append(ev.ruleIDs, r.RuleID)
			reported[strings.TrimPrefix(r.RuleID, kubeBenchRulePrefix)] = true
		}
		for _, p := range run.Properties.Provenance {
			if p.Tool == tool && p.Fields["benchmark"] != "" {
				ev.benchmark = p.Fields["benchmark"]
			}
		}
	}
	for _, run := range doc.Runs {
		for _, d := range run.Properties.Decided {
			if d.Taxonomy == "CIS-Kubernetes" && !reported[d.ID] {
				ev.passed = append(ev.passed, d.ID)
			}
		}
	}
	return ev
}

// scannerVersion is the version report.json records for a scanner that ran, "" when it records
// none.
func scannerVersion(t *testing.T, outDir, scanner string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(outDir, "report.json")) // #nosec G304 -- a file the scan just wrote into t.TempDir()
	if err != nil {
		t.Fatalf("read report.json: %v", err)
	}
	var doc struct {
		Scanners []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"scanners"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("parse report.json: %v", err)
	}
	for _, s := range doc.Scanners {
		if s.Name == scanner {
			return s.Version
		}
	}
	return ""
}

// requireNoJobLeftBehind fails if a Job the scanner created is still in the cluster. The scanner
// deletes it on every path, and a privileged Job left in somebody's cluster is the worst thing it
// could leave there. The fake clientset the unit tests use deletes whatever it is asked to, so
// only a real API server shows the deletion taking effect.
func requireNoJobLeftBehind(t *testing.T, cs kubernetes.Interface) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// The label the scanner puts on its Job, read across namespaces so a Job created somewhere
	// other than the default namespace still counts.
	opts := metav1.ListOptions{LabelSelector: "app.kubernetes.io/managed-by=draugr"}
	var left []string
	for ctx.Err() == nil {
		jobs, err := cs.BatchV1().Jobs("").List(ctx, opts)
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			t.Fatalf("list Jobs: %v", err)
		}
		left = left[:0]
		for _, j := range jobs.Items {
			left = append(left, j.Namespace+"/"+j.Name)
		}
		if len(left) == 0 {
			return
		}
		select {
		case <-ctx.Done():
		case <-time.After(time.Second):
		}
	}
	t.Errorf("the scan finished and its Job is still in the cluster after 30s: %v", left)
}
