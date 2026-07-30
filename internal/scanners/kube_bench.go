package scanners

import (
	"encoding/json"
	"fmt"
	"strings"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/tooladapter"
)

// kubeBenchScannerName identifies the scanner behind the "infrastructure" control.
const kubeBenchScannerName = "kube-bench"

// NewKubeBench returns a Scanner that audits a Kubernetes cluster against the CIS Kubernetes
// Benchmark. It serves the "infrastructure" control.
//
// kube-bench emits its own JSON rather than SARIF, so the conversion is ours — the second such
// scanner, after trivy-license.
func NewKubeBench() plugin.Scanner {
	return tooladapter.New(tooladapter.Config{
		Name:        kubeBenchScannerName,
		Binary:      "kube-bench",
		Controls:    []string{"infrastructure"},
		TargetKinds: []plugin.TargetKind{plugin.TargetInfra},
		Argv:        kubeBenchArgv,
		Run:         execArgv,
		Parse:       parseKubeBench,
	})
}

// Config keys. Both are optional; the defaults are the safe reading.
const (
	// targetsKey selects which CIS sections to run, comma-separated.
	targetsKey = "targets"
	// benchmarkKey pins the benchmark config directly (e.g. "cis-1.9", "gke-1.6.0",
	// "rke2-cis-1.7"). Use it for a platform whose benchmark is not derived from the Kubernetes
	// version; otherwise let the version decide.
	benchmarkKey = "benchmark"
	// versionKey pins the Kubernetes version kube-bench maps to a benchmark (e.g. "1.34").
	// Unset means Draugr asks the cluster — see clusterVersion.
	versionKey = "version"
	// configDirKey points at kube-bench's own `cfg/` tree of benchmark definitions. kube-bench
	// looks in /etc/kube-bench/cfg by default, which is right when it was installed from a
	// package and wrong when someone put the binary on PATH and left the cfg beside it — a
	// common enough case that failing with kube-bench's own "config file is missing
	// 'version_mapping' section" needs an answer the user can act on.
	configDirKey = "configDir"
)

// defaultKubeBenchTargets is the CIS section Draugr runs, and the choice is the whole design of
// this scanner.
//
// kube-bench audits **the machine it runs on**. Sections 1–4 (master, node, etcd, controlplane)
// read node-local files — API server manifests, kubelet config, etcd data-dir permissions — so
// they mean something only on a cluster node. Draugr runs from a laptop or a CI runner, where
// those checks do not error: they find the files missing and return confident failures about a
// cluster nobody inspected.
//
// Section 5, "policies", is the section that travels. Every check shells out to kubectl — RBAC
// bindings, service account tokens, Pod Security Standards, network policies, secrets usage — so
// it audits whatever cluster the ambient kubeconfig points at, read-only, and means the same
// thing from anywhere. 35 of the 130 checks in cis-1.9, and the 35 that describe how the cluster
// is configured for the workloads on it rather than how its nodes were installed.
//
// The rest of the benchmark needs kube-bench running inside the cluster as a Job, which is a
// different tool contract: Draugr would be creating something in the system it is scanning.
// Deliberately out of scope here.
const defaultKubeBenchTargets = "policies"

// kubeBenchArgv builds the command line, and its main job is making sure kube-bench audits
// against the right benchmark.
//
// kube-bench maps a Kubernetes version to a CIS benchmark, and detects that version by reading
// the kubelet on the node it runs on. Off a node it cannot, and it does not say so: it falls
// back to a default of 1.18 and audits against cis-1.6 — a benchmark for Kubernetes 1.16. On a
// 1.34 cluster that silently reports 24 findings where the right benchmark reports 29, and every
// one of the differences is a check the older benchmark had never heard of.
//
// A compliance report against the wrong standard is worse than no report, so Draugr supplies the
// version rather than letting the tool guess. It asks the cluster, and passes --version so
// kube-bench applies its own mapping — which stays correct as kube-bench adds benchmarks,
// whereas a table copied into Draugr would not.
func kubeBenchArgv(_ plugin.Target, cfg plugin.Config) ([]string, error) {
	targets := stringSetting(cfg, targetsKey, defaultKubeBenchTargets)
	argv := []string{"kube-bench", "run", "--json", "--targets", targets}

	switch benchmark := stringSetting(cfg, benchmarkKey, ""); {
	case benchmark != "":
		// An explicit benchmark names a config directly, including the platform ones
		// (gke-*, rke2-*, eks-*) that no Kubernetes version maps to.
		argv = append(argv, "--benchmark", benchmark)
	default:
		version := stringSetting(cfg, versionKey, "")
		if version == "" {
			detected, err := clusterVersion()
			if err != nil {
				return nil, fmt.Errorf(
					"kube-bench: cannot determine the cluster's Kubernetes version, and kube-bench "+
						"would silently audit against a stale benchmark instead of saying so: %w. "+
						"Set controllers.infrastructure.version (e.g. \"1.34\") or .benchmark "+
						"(e.g. \"cis-1.12\")", err)
			}
			version = detected
		}
		argv = append(argv, "--version", version)
	}

	if dir := stringSetting(cfg, configDirKey, ""); dir != "" {
		argv = append(argv, "--config-dir", dir)
	}
	return argv, nil
}

// clusterVersion reports the cluster's Kubernetes version as major.minor. Injectable for tests.
var clusterVersion = detectClusterVersion

// detectClusterVersion asks the cluster named by the ambient kubeconfig, the same way the
// k8s-images surveyor reaches one.
func detectClusterVersion() (string, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	restCfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{}).ClientConfig()
	if err != nil {
		return "", fmt.Errorf("kubeconfig: %w", err)
	}
	client, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return "", err
	}
	info, err := client.Discovery().ServerVersion()
	if err != nil {
		return "", err
	}
	// Major/Minor come back as "1" and "34", sometimes with a "+" on managed clusters.
	minor := strings.TrimRight(info.Minor, "+")
	if info.Major == "" || minor == "" {
		return "", fmt.Errorf("server reported an unusable version %q", info.GitVersion)
	}
	return info.Major + "." + minor, nil
}

// stringSetting reads a string from a plugin.Config, falling back to a default.
func stringSetting(cfg plugin.Config, key, fallback string) string {
	if cfg == nil {
		return fallback
	}
	if v, ok := cfg[key].(string); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return fallback
}

// kubeBenchDoc is the slice of kube-bench's JSON this scanner reads.
type kubeBenchDoc struct {
	Controls []struct {
		ID       string `json:"id"`
		Text     string `json:"text"`
		NodeType string `json:"node_type"`
		Version  string `json:"version"`
		Tests    []struct {
			Section string             `json:"section"`
			Desc    string             `json:"desc"`
			Results []kubeBenchFinding `json:"results"`
		} `json:"tests"`
	} `json:"Controls"`
}

type kubeBenchFinding struct {
	TestNumber string `json:"test_number"`
	TestDesc   string `json:"test_desc"`
	Status     string `json:"status"`
	Scored     bool   `json:"scored"`
	Remedy     string `json:"remediation"`
}

// The message is the check description and nothing else.
//
// kube-bench also reports expected_result and actual_value, and neither survives contact with a
// reader. expected_result is the tool's internal assertion — "'is_compliant' is equal to 'true'"
// — which describes kube-bench's own test rather than the cluster. actual_value is the raw
// stdout of the check script: multi-line, and on some checks it carries shell errors from
// kube-bench's own logic. Appending either produces the field-dump problem the Trivy scanners
// were fixed for.
//
// The remediation kube-bench supplies is genuinely useful, and travels on the rule where a
// viewer shows it beside the finding. Everything the tool printed is available at
// --log-level trace.

// parseKubeBench converts kube-bench's JSON into a report.
//
// Only FAIL and WARN become findings. PASS and INFO are the benchmark confirming what it
// checked, and a report listing three hundred passing checks buries the dozen that failed —
// the same reasoning that keeps permissive licences out of the licences control.
func parseKubeBench(out []byte, target plugin.Target, _ plugin.Config) (sarif.Report, error) {
	var doc kubeBenchDoc
	if err := json.Unmarshal(out, &doc); err != nil {
		return sarif.Report{}, fmt.Errorf("decode kube-bench json: %w", err)
	}
	location := "cluster"
	if t, ok := target.(plugin.InfraTarget); ok && t.Identity() != "" {
		location = t.Identity()
	}

	report := sarif.Report{Tool: kubeBenchScannerName, Rules: map[string]sarif.Rule{}}
	for _, ctl := range doc.Controls {
		for _, test := range ctl.Tests {
			for _, res := range test.Results {
				level, ok := kubeBenchLevel(res.Status, res.Scored)
				if !ok {
					continue
				}
				ruleID := "cis/" + res.TestNumber
				report.Results = append(report.Results, sarif.Result{
					Tool:     kubeBenchScannerName,
					RuleID:   ruleID,
					Level:    level,
					Message:  res.TestDesc,
					Location: sarif.Location{URI: location},
				})
				report.Rules[ruleID] = sarif.Rule{
					Name:             ctl.Text,
					ShortDescription: res.TestDesc,
					FullDescription:  strings.TrimSpace(res.Remedy),
					HelpURI:          "https://www.cisecurity.org/benchmark/kubernetes",
				}
			}
		}
	}
	return report, nil
}

// kubeBenchLevel maps a check's status to a SARIF level.
//
// A scored FAIL is an error: the benchmark says the cluster is out of compliance and counts it.
// An unscored FAIL and a WARN are both warnings — WARN in CIS terms means "manual check
// required", which is a prompt for a human rather than a defect, and reporting it as an error
// would make a clean cluster impossible.
func kubeBenchLevel(status string, scored bool) (sarif.Level, bool) {
	switch strings.ToUpper(status) {
	case "FAIL":
		if scored {
			return sarif.LevelError, true
		}
		return sarif.LevelWarning, true
	case "WARN":
		return sarif.LevelWarning, true
	default: // PASS, INFO
		return "", false
	}
}
