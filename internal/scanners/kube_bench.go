package scanners

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/draugr-dev/draugr/internal/toolexec"

	"github.com/draugr-dev/draugr/internal/tools"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// kubeBenchScannerName identifies the scanner behind the "infrastructure" control.
const kubeBenchScannerName = "kube-bench"

// kubeBenchScanner audits a Kubernetes cluster against the CIS Kubernetes Benchmark.
//
// Written directly rather than through tooladapter, which covers a tool that takes an argv and
// answers in SARIF. kube-bench needs three things beyond that: its own argv, its own JSON
// conversion, and a per-scan environment with a lifecycle — a kubeconfig written to disk so the
// kubectl it invokes talks to the cluster the Saga named, then removed. The third is what tips
// it; a hook returning a value plus a cleanup function is worse than a Scan method.
type kubeBenchScanner struct {
	info plugin.ScannerInfo
	run  func(ctx context.Context, argv, env []string) ([]byte, error)
}

// NewKubeBench returns a Scanner for the "infrastructure" control.
func NewKubeBench() plugin.Scanner {
	return kubeBenchScanner{
		info: plugin.ScannerInfo{
			Name:   kubeBenchScannerName,
			Origin: "aquasecurity",
			Binary: "kube-bench",
			// Its CIS policy checks are shell scripts that invoke kubectl; without it the tool
			// runs and reports every check as failed.
			AlsoRequires: []string{"kubectl"},
			Controls:     []string{"infrastructure"},
			TargetKinds:  []plugin.TargetKind{plugin.TargetInfra},
		},
		run: func(ctx context.Context, argv, env []string) ([]byte, error) {
			return toolexec.RunWithEnv(ctx, "", argv, env)
		},
	}
}

// Info describes the scanner.
func (s kubeBenchScanner) Info() plugin.ScannerInfo { return s.info }

// CacheVersion reports kube-bench's version and the benchmark set it was provisioned with
// (implements plugin.CacheVersioner).
//
// Both matter: the binary decides how a check is run, and the cfg/ tree decides which checks
// exist. A benchmark update adds controls to an unchanged cluster, and a cached pass from before
// it would answer a narrower question than the one being asked.
func (s kubeBenchScanner) CacheVersion(ctx context.Context) string {
	if v := sharedKubeBenchVersion.version(ctx); v != "" {
		return "kube-bench@" + v
	}
	return ""
}

// Scan audits the cluster the target names and converts kube-bench's JSON to SARIF.
func (s kubeBenchScanner) Scan(ctx context.Context, target plugin.Target, cfg plugin.Config) (sarif.Report, error) {
	infra, ok := target.(plugin.InfraTarget)
	if !ok {
		return sarif.Report{}, fmt.Errorf("kube-bench: unsupported target %T (want infrastructure)", target)
	}
	if err := refuseNamespaceScope(kubeBenchScannerName, infra.Namespaces); err != nil {
		return sarif.Report{}, err
	}
	// Resolve the cluster before anything talks to it. A context that does not exist is a typo
	// or a missing kubeconfig entry, and saying so beats the version lookup failing first and
	// blaming the wrong thing.
	//
	// kube-bench shells out to kubectl for every policies check, and kubectl reads its cluster
	// from the environment. Without this the scan audits whatever context the machine has
	// selected while labelling the findings with the one the Saga declared — a report naming one
	// cluster and describing another.
	env, cleanup, err := kubeContextEnv(kubeContext(target, cfg))
	if err != nil {
		return sarif.Report{}, err
	}
	defer cleanup()

	plan, err := kubeBenchArgv(target, cfg)
	if err != nil {
		return sarif.Report{}, err
	}

	out, err := s.run(ctx, plan.argv, env)
	if err != nil {
		return sarif.Report{}, fmt.Errorf("run %s: %w", kubeBenchScannerName, err)
	}
	doc, err := decodeKubeBench(out)
	if err != nil {
		return sarif.Report{}, err
	}
	if err := verifyBenchmark(doc, plan.platform); err != nil {
		return sarif.Report{}, err
	}
	return reportFromKubeBench(doc, kubeBenchScannerName, clusterLabel(kubeContext(target, cfg))), nil
}

// kubeContextEnv writes a kubeconfig whose current context is the one being audited, and returns
// the environment pointing kubectl at it.
//
// A copy rather than `kubectl config use-context`, which would change the operator's own default
// as a side effect of running a scan. An empty context means the ambient config is already right,
// so nothing is written.
func kubeContextEnv(kubeCtx string) (env []string, cleanup func(), err error) {
	noop := func() {}
	if kubeCtx == "" {
		return nil, noop, nil
	}
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	raw, err := rules.Load()
	if err != nil {
		return nil, noop, fmt.Errorf("kube-bench: read kubeconfig: %w", err)
	}
	if _, ok := raw.Contexts[kubeCtx]; !ok {
		return nil, noop, fmt.Errorf(
			"kube-bench: no kubeconfig context named %q — the component's infrastructure `ref` "+
				"selects the cluster to audit, so it has to match a context (or set "+
				"controllers.infrastructure.context)", kubeCtx)
	}
	raw.CurrentContext = kubeCtx

	f, err := os.CreateTemp("", "draugr-kubeconfig-*.yaml")
	if err != nil {
		return nil, noop, err
	}
	path := f.Name()
	_ = f.Close()
	cleanup = func() { _ = os.Remove(path) }
	if err := clientcmd.WriteToFile(*raw, path); err != nil {
		cleanup()
		return nil, noop, fmt.Errorf("kube-bench: write kubeconfig: %w", err)
	}
	return []string{"KUBECONFIG=" + path}, cleanup, nil
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
	// Unset means Draugr asks the cluster — see detectClusterFacts.
	versionKey = "version"
	// contextKey names the kubeconfig context to audit. Unset means the component's
	// infrastructure `ref`, and only then the kubeconfig's current context.
	contextKey = "context"
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
//
// That holds for a vanilla distribution and breaks for a managed one, because of how kube-bench
// chooses (cmd/common.go, getBenchmarkVersion):
//
//	if isEmpty(benchmarkVersion) && isEmpty(kubeVersion) && !isEmpty(platform.Name) {
//	    benchmarkVersion = getPlatformBenchmarkVersion(platform)
//	}
//
// The platform benchmarks — eks-*, gke-*, aks-*, ack-*, and the k3s/RKE ones — are reachable
// only when *neither* flag is set. Supplying --version to avoid one wrong answer therefore
// guarantees a different one: every managed cluster falls through to generic cis-*.
//
// The provider benchmarks are not subsets of it. They drop the control-plane checks that are not
// the customer's to make, and add provider-specific ones the generic benchmark has never heard
// of, so the mismatch both fails a cluster for what it cannot fix and skips what it can.
//
// So the flag is supplied only where it helps: a vanilla cluster gets --version, a recognized
// platform gets neither flag and kube-bench's own mapping. What makes that safe is not trusting
// it — verifyBenchmark checks the benchmark the tool reports having used.
func kubeBenchArgv(target plugin.Target, cfg plugin.Config) (kubeBenchPlan, error) {
	targets := stringSetting(cfg, targetsKey, defaultKubeBenchTargets)
	kubeCtx := kubeContext(target, cfg)
	plan := kubeBenchPlan{argv: []string{"kube-bench", "run", "--json", "--targets", targets}}
	argv := plan.argv

	switch benchmark := stringSetting(cfg, benchmarkKey, ""); {
	case benchmark != "":
		// An explicit benchmark names a config directly, including the platform ones
		// (gke-*, rke2-*, eks-*) that no Kubernetes version maps to.
		argv = append(argv, "--benchmark", benchmark)
	default:
		if version := stringSetting(cfg, versionKey, ""); version != "" {
			argv = append(argv, "--version", version)
			break
		}
		facts, err := detectCluster(kubeCtx)
		if err != nil {
			return kubeBenchPlan{}, fmt.Errorf(
				"kube-bench: cannot determine the cluster's Kubernetes version, and kube-bench "+
					"would silently audit against a stale benchmark instead of saying so: %w. "+
					"Set controllers.infrastructure.version (e.g. \"1.34\") or .benchmark "+
					"(e.g. \"cis-1.12\")", err)
		}
		if facts.Platform != "" {
			// Deliberately neither flag: this is the only way kube-bench will select the
			// platform's own benchmark.
			plan.platform = facts.Platform
			break
		}
		argv = append(argv, "--version", facts.Version)
	}

	switch dir := stringSetting(cfg, configDirKey, ""); {
	case dir != "":
		argv = append(argv, "--config-dir", dir)
	default:
		// Point at the tree `draugr tools install` fetched, when there is one. Without this the
		// install is useless: kube-bench searches /etc/kube-bench/cfg and its own directory, and
		// finds nothing we put under ~/.draugr.
		//
		// Only when the descriptor said nothing, and only when the directory exists — a system
		// install with its own cfg keeps working exactly as before, and an explicit setting
		// always wins.
		if provisioned := provisionedKubeBenchCfg(); provisioned != "" {
			argv = append(argv, "--config-dir", provisioned)
		}
	}
	plan.argv = argv
	return plan, nil
}

// provisionedKubeBenchCfg returns the cfg directory `draugr tools install` wrote, or "" if there
// is none. A var so a test can answer without arranging a home directory.
var provisionedKubeBenchCfg = func() string {
	dir := tools.DataDirFor("kube-bench")
	if dir == "" {
		return ""
	}
	if _, err := os.Stat(filepath.Join(dir, "config.yaml")); err != nil {
		return ""
	}
	return dir
}

// kubeBenchCISRulePrefix namespaces this scanner's CIS rule ids, so they cannot be confused with
// draugr-k8s-policies' findings about the very same checks.
const kubeBenchCISRulePrefix = "kube-bench/cis/"

// kubeBenchPlan is how the scan will run, and what it therefore expects back.
//
// platform carries the distribution Draugr detected, and is empty whenever the benchmark was
// pinned by configuration or the cluster is vanilla — in both of those cases the benchmark is
// already determined and there is nothing for the output check to disagree with.
type kubeBenchPlan struct {
	argv     []string
	platform string
}

// currentKubeContext reports the kubeconfig's current context. Injectable for tests.
var currentKubeContext = detectCurrentKubeContext

func detectCurrentKubeContext() string {
	raw, err := clientcmd.NewDefaultClientConfigLoadingRules().Load()
	if err != nil {
		return ""
	}
	return raw.CurrentContext
}

// clusterLabel names the cluster a finding is about.
//
// Normally that is the context being audited. When the Saga declares infrastructure without a
// `ref` — which the schema allows — Draugr falls back to the ambient context, and the label has
// to follow: a report reading `kubernetes/` says nothing about what was examined, and "which
// cluster is this about" is the first question asked of a compliance artifact. So the ambient
// context is resolved and named, rather than left blank.
func clusterLabel(kubeCtx string) string {
	if kubeCtx == "" {
		kubeCtx = currentKubeContext()
	}
	if kubeCtx == "" {
		return "kubernetes"
	}
	return "kubernetes/" + kubeCtx
}

// kubeContext decides which cluster this scan is about.
//
// The Saga's `ref` names the concrete instance, so it is the natural answer — and it has to be
// used, not merely displayed. Findings are labelled with it; if the scan actually audited
// whatever context the machine happened to have selected, the report would name one cluster and
// describe another. Mislabelled evidence is worse than none.
//
// An explicit `context` setting wins, for the case where the kubeconfig's name for a cluster is
// not the name the organisation uses for it.
func kubeContext(target plugin.Target, cfg plugin.Config) string {
	if ctx := stringSetting(cfg, contextKey, ""); ctx != "" {
		return ctx
	}
	if t, ok := target.(plugin.InfraTarget); ok {
		return t.Ref
	}
	return ""
}

// clusterFacts is what a cluster reports about itself that decides which benchmark applies.
type clusterFacts struct {
	// Version is the Kubernetes version as major.minor, e.g. "1.34".
	Version string
	// Platform names the managed distribution — "eks", "gke" — or is empty for a vanilla one.
	Platform string
}

// detectCluster reads the facts that decide the benchmark. Injectable for tests.
var detectCluster = detectClusterFacts

// clientForContext builds a Kubernetes client for a named context, the same way the k8s-images
// surveyor reaches one. An empty context means the kubeconfig's current one.
func clientForContext(kubeCtx string) (kubernetes.Interface, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	overrides := &clientcmd.ConfigOverrides{CurrentContext: kubeCtx}
	restCfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("kubeconfig: %w", err)
	}
	return kubernetes.NewForConfig(restCfg)
}

// detectClusterFacts asks the named context's cluster what decides its benchmark.
func detectClusterFacts(kubeCtx string) (clusterFacts, error) {
	client, err := clientForContext(kubeCtx)
	if err != nil {
		return clusterFacts{}, err
	}
	info, err := client.Discovery().ServerVersion()
	if err != nil {
		return clusterFacts{}, err
	}
	version, err := majorMinor(info.Major, info.Minor, info.GitVersion)
	if err != nil {
		return clusterFacts{}, err
	}
	platform := platformFrom(info.GitVersion)
	if platform == "" {
		platform = platformFromNodes(context.Background(), client)
	}
	return clusterFacts{Version: version, Platform: platform}, nil
}

// platformFromNodes identifies a distribution that does not stamp itself into the version string.
//
// AKS is the case this exists for. GKE and EKS both report a version like v1.29.7-gke.1104000,
// so a regex is enough; a real AKS cluster reports a bare v1.34.2 and is indistinguishable from
// kubeadm by version alone. kube-bench knows this and looks at a node instead — but only along
// its in-cluster path, because that is where it happens to build a client. The check itself is an
// ordinary List, so there is no reason it cannot run from a laptop.
//
// Without it, AKS is audited against the generic benchmark and nothing says so: no platform means
// no expectation, so verifyBenchmark has nothing to disagree with. Silence, again, is the failure.
//
// One node is enough, and one is all that is fetched — a cluster with two hundred nodes should
// not pay for two hundred objects to answer a yes/no question.
func platformFromNodes(ctx context.Context, client kubernetes.Interface) string {
	nodes, err := client.CoreV1().Nodes().List(ctx, metav1.ListOptions{Limit: 1})
	if err != nil || len(nodes.Items) == 0 {
		// Not fatal. Reading nodes may be denied on a shared cluster, and a missed platform
		// leaves the version-string path to decide exactly as it did before.
		return ""
	}
	// The label AKS puts on its own nodes, and deliberately not the azure:// provider ID that
	// kube-bench also accepts.
	//
	// A provider ID says which cloud the VM is on, not who runs the control plane. RKE2, RKE and
	// kubeadm all set it when the Azure cloud provider is configured, so accepting it would call
	// a self-managed cluster AKS and audit it against a benchmark written for a control plane
	// nobody can see — dropping the very checks a self-managed cluster most needs.
	//
	// kube-bench can afford the looser signal because it only reaches this check from inside the
	// cluster, having already tested for RKE. Reading a node from outside gives no such context,
	// so the signal has to carry the distinction on its own.
	//
	// Erring this way is also the cheaper mistake. A missed AKS cluster falls back to the version
	// string and behaves as it did before; a self-managed cluster wrongly called AKS gets a scan
	// that fails with an error about the wrong thing.
	if _, ok := nodes.Items[0].Labels["kubernetes.azure.com/cluster"]; ok {
		return "aks"
	}
	return ""
}

// gitVersionPlatformRE is kube-bench's own expression (cmd/util.go, getPlatformInfoFromVersion),
// copied rather than approximated: the aim is to reach the same conclusion the tool would, so a
// looser pattern that finds a platform kube-bench will not is worse than no pattern.
var gitVersionPlatformRE = regexp.MustCompile(`v(\d+\.\d+)\.\d+[-+](\w+)(?:[.\-+]*)\w+`)

// platformBenchmarkPrefix maps a distribution to the benchmark family kube-bench selects for it.
// The keys are the platform names kube-bench's own parser yields; the values are read from the
// directory names in its cfg/ tree, because that is what it reports having used.
//
// OpenShift is absent deliberately: kube-bench identifies it by running `oc`, not from the
// version string, so Draugr cannot reach the same conclusion here. AKS and RKE are listed
// because their version strings carry the token when they carry it at all — kube-bench's extra
// in-cluster detection for those two is a fallback for the clusters that do not, and one this
// scanner has no way to reproduce from outside.
var platformBenchmarkPrefix = map[string]string{
	"eks":     "eks-",
	"gke":     "gke-",
	"aks":     "aks-",
	"k3s":     "k3s-cis-",
	"rancher": "rke-cis-",
	"rke2r":   "rke2-cis-",
	"aliyun":  "ack-",
	"vmware":  "tkgi-",
}

// platformFrom names the managed distribution a GitVersion belongs to, or "" for a vanilla one.
//
// A build suffix is not automatically a platform: v1.31.0-rc.1 parses just as cleanly as
// v1.30.4-eks-a737599. Only suffixes kube-bench maps to a benchmark count, so a release
// candidate stays vanilla instead of sending the scan looking for an "rc" benchmark.
func platformFrom(gitVersion string) string {
	subs := gitVersionPlatformRE.FindStringSubmatch(gitVersion)
	if len(subs) < 3 {
		return ""
	}
	if _, ok := platformBenchmarkPrefix[subs[2]]; !ok {
		return ""
	}
	return subs[2]
}

// verifyBenchmark checks that kube-bench audited against the benchmark the cluster called for.
//
// Draugr selects the benchmark by withholding flags — the only way to reach a platform config —
// which means the choice is made inside a tool that has its own detection and its own fallback.
// When that detection fails, kube-bench does not stop: it assumes Kubernetes 1.18 and audits
// against cis-1.6, a benchmark for Kubernetes 1.16, and reports the result as though it were the
// one asked for.
//
// So the input is not the guarantee — the output is. kube-bench states the benchmark it used in
// every control it emits, and a run that used the wrong one is a failed scan rather than a
// finding-free pass.
func verifyBenchmark(doc kubeBenchDoc, platform string) error {
	want, ok := platformBenchmarkPrefix[platform]
	if !ok || len(doc.Controls) == 0 {
		return nil
	}
	for _, ctl := range doc.Controls {
		if ctl.Version == "" || strings.HasPrefix(ctl.Version, want) {
			continue
		}
		return fmt.Errorf(
			"kube-bench audited against %q, but this is a %s cluster and its benchmark starts with %q. "+
				"The result would describe the wrong standard. Set controllers.infrastructure.benchmark "+
				"to the config you want (see `kube-bench --help` for the names it ships)",
			ctl.Version, platform, want)
	}
	return nil
}

// majorMinor renders the version kube-bench maps against.
//
// Managed clusters report a minor with a trailing "+" — GKE and EKS both do, meaning "1.30 plus
// vendor patches". kube-bench's version_mapping has no "30+" key, so leaving it on means no
// benchmark matches and the tool falls back to the stale default this whole path exists to
// avoid.
func majorMinor(major, minor, gitVersion string) (string, error) {
	minor = strings.TrimRight(minor, "+")
	if major == "" || minor == "" {
		return "", fmt.Errorf("server reported an unusable version %q", gitVersion)
	}
	return major + "." + minor, nil
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
	Controls []kubeBenchControl `json:"Controls"`
}

// kubeBenchControl is one benchmark run. Version is the benchmark kube-bench actually applied —
// the field verifyBenchmark holds it to.
type kubeBenchControl struct {
	ID       string `json:"id"`
	Text     string `json:"text"`
	NodeType string `json:"node_type"`
	Version  string `json:"version"`
	Tests    []struct {
		Section string             `json:"section"`
		Desc    string             `json:"desc"`
		Results []kubeBenchFinding `json:"results"`
	} `json:"tests"`
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
// The tool name is a parameter because two scanners share this format — the read-only one and
// the in-cluster Job — and a finding should name the scanner that actually produced it. The
// report's Scanner column is how a reader tells a section-5 finding from a section-4 one.
//
// Only FAIL and WARN become findings. PASS and INFO are the benchmark confirming what it
// checked, and a report listing three hundred passing checks buries the dozen that failed —
// the same reasoning that keeps permissive licences out of the licences control.
func parseKubeBench(out []byte, tool, location string) (sarif.Report, error) {
	doc, err := decodeKubeBench(out)
	if err != nil {
		return sarif.Report{}, err
	}
	return reportFromKubeBench(doc, tool, location), nil
}

// decodeKubeBench reads the tool's JSON. Separate from rendering so a caller that has an
// expectation about the benchmark can check it before turning the output into findings — a
// report built from the wrong benchmark is worth nothing, so it should never be built.
func decodeKubeBench(out []byte) (kubeBenchDoc, error) {
	var doc kubeBenchDoc
	if err := json.Unmarshal(out, &doc); err != nil {
		return kubeBenchDoc{}, fmt.Errorf("decode kube-bench json: %w", err)
	}
	return doc, nil
}

func reportFromKubeBench(doc kubeBenchDoc, tool, location string) sarif.Report {
	report := sarif.Report{Tool: tool, Rules: map[string]sarif.Rule{}}
	// The benchmark kube-bench reports having used, which is the thing verifyBenchmark checks and
	// the thing a reader of the evidence needs: a report that does not name the standard it
	// applied cannot be defended, and the standard is chosen from the cluster rather than stated
	// in the descriptor.
	if len(doc.Controls) > 0 && doc.Controls[0].Version != "" {
		report.Provenance = []sarif.Provenance{{
			Tool:   tool,
			Fields: []sarif.Field{{Key: "benchmark", Value: doc.Controls[0].Version}},
		}}
	}
	for _, ctl := range doc.Controls {
		for _, test := range ctl.Tests {
			for _, res := range test.Results {
				// Decided before filtered. A PASS produces no finding and is still a verdict —
				// the scanner looked at that control and was satisfied. Recording only what
				// failed would make "no finding" mean two different things, and the whole point
				// of this list is telling them apart.
				//
				// WARN is kube-bench's "needs manual review", which is not a verdict: a check it
				// could not settle is not a dissent from a scanner that could.
				if decided := kubeBenchDecided(res.Status); decided {
					report.Decided = append(report.Decided, sarif.Taxon{
						Taxonomy: cisKubernetesTaxonomy,
						ID:       res.TestNumber,
						Name:     res.TestDesc,
						Version:  ctl.Version,
					})
				}
				level, ok := kubeBenchLevel(res.Status, res.Scored)
				if !ok {
					continue
				}
				ruleID := kubeBenchCISRulePrefix + res.TestNumber
				report.Results = append(report.Results, sarif.Result{
					Tool:     tool,
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
					// Same taxonomy and same control id as draugr-k8s-policies, which is how the
					// two scanners' accounts of one check stay recognisable as such now that
					// their rule ids are namespaced apart.
					Taxa: []sarif.Taxon{{
						Taxonomy: cisKubernetesTaxonomy,
						ID:       res.TestNumber,
						Name:     res.TestDesc,
						Version:  ctl.Version,
					}},
				}
			}
		}
	}
	return report
}

// kubeBenchLevel maps a check's status to a SARIF level.
//
// A scored FAIL is an error: the benchmark says the cluster is out of compliance and counts it.
// An unscored FAIL and a WARN are both warnings — WARN in CIS terms means "manual check
// required", which is a prompt for a human rather than a defect, and reporting it as an error
// would make a clean cluster impossible.
// kubeBenchDecided reports whether a status is a verdict rather than a referral.
//
// PASS and FAIL are conclusions. WARN is kube-bench's way of saying a human has to look, and INFO
// is context — neither settles the control, so neither can contradict a scanner that did.
func kubeBenchDecided(status string) bool {
	switch strings.ToUpper(status) {
	case "PASS", "FAIL":
		return true
	}
	return false
}

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

// refuseNamespaceScope stops a scanner that cannot honour a declared namespace scope.
//
// kube-bench's checks are shell pipelines with the scope written into them — `kubectl get pods
// --all-namespaces`, and no flag to change it. So a component that declares `namespaces:` and is
// audited by kube-bench gets the whole cluster, reported against a component that claims to own
// three of its eighty namespaces.
//
// That is the worst available outcome: not a missing feature but a wrong one, where the report
// looks scoped, the rule ids look scoped, and the findings are somebody else's. Refusing is the
// only honest answer, and the error names the scanner that can do it.
func refuseNamespaceScope(scanner string, namespaces []string) error {
	if len(namespaces) == 0 {
		return nil
	}
	return fmt.Errorf(
		"%s cannot audit a namespace scope: its checks query every namespace and offer no way to "+
			"narrow that, so it would report the whole cluster against a component that declared "+
			"%d namespace(s). Use the k8sPolicies scanner, which is the default and reads the "+
			"Kubernetes API directly, or remove `namespaces` from the component's infrastructure entry",
		scanner, len(namespaces))
}
