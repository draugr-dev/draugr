package scanners

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

func TestKubeBenchInfo(t *testing.T) {
	info := NewKubeBench().Info()
	if info.Name != "kube-bench" || info.Binary != "kube-bench" {
		t.Errorf("Info() = %+v", info)
	}
	if len(info.Controls) != 1 || info.Controls[0] != "infrastructure" {
		t.Errorf("controls = %v, want [infrastructure]", info.Controls)
	}
	if len(info.TargetKinds) != 1 || info.TargetKinds[0] != plugin.TargetInfra {
		t.Errorf("target kinds = %v, want [infrastructure]", info.TargetKinds)
	}
}

// withClusterVersion swaps the cluster lookup for a fixed vanilla-distribution answer.
func withClusterVersion(t *testing.T, version string, err error) {
	t.Helper()
	withClusterFacts(t, clusterFacts{Version: version}, err)
}

// withClusterFacts swaps the cluster lookup for a fixed answer, platform included.
func withClusterFacts(t *testing.T, facts clusterFacts, err error) {
	t.Helper()
	prev := detectCluster
	detectCluster = func(string) (clusterFacts, error) { return facts, err }
	t.Cleanup(func() { detectCluster = prev })
}

func argvString(argv []string) string { return strings.Join(argv, " ") }

// The default matters more than most: it is what makes a scan mean the same thing on a laptop,
// in CI, and on a node. See defaultKubeBenchTargets.
func TestKubeBenchArgvDefaults(t *testing.T) {
	withClusterVersion(t, "1.34", nil)
	// Stubbed absent, or the argv depends on whether the developer has run
	// `draugr tools install kube-bench` — which is a fact about the machine, not the default.
	withoutProvisionedCfg(t)
	plan, err := kubeBenchArgv(plugin.InfraTarget{Platform: "kubernetes"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := argvString(plan.argv), "kube-bench run --json --targets policies --version 1.34"; got != want {
		t.Errorf("argv = %q, want %q", got, want)
	}
}

// The bug this guards: kube-bench cannot read the kubelet off a node, so it falls back to
// Kubernetes 1.18 and audits against cis-1.6 without a word. On a 1.34 cluster that is a
// benchmark sixteen minor versions stale, and it under-reports. Draugr tells it the version.
func TestKubeBenchArgvPassesTheDetectedClusterVersion(t *testing.T) {
	withClusterVersion(t, "1.29", nil)
	plan, err := kubeBenchArgv(plugin.InfraTarget{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(argvString(plan.argv), "--version 1.29") {
		t.Errorf("argv %q should carry the detected version", argvString(plan.argv))
	}
}

// Guessing is what produced the stale-benchmark bug. If the version cannot be established, say
// so rather than letting kube-bench pick one.
func TestKubeBenchArgvRefusesToGuessTheVersion(t *testing.T) {
	withClusterVersion(t, "", errors.New("no kubeconfig"))
	_, err := kubeBenchArgv(plugin.InfraTarget{}, nil)
	if err == nil {
		t.Fatal("expected an error when the cluster version cannot be determined")
	}
	for _, want := range []string{"version", "benchmark"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error should name the settings that resolve it, got: %v", err)
		}
	}
}

// An explicit benchmark names a config directly — including the platform ones (gke-*, rke2-*)
// that no Kubernetes version maps to — so it must not be overridden by detection.
func TestKubeBenchArgvExplicitBenchmarkWins(t *testing.T) {
	withClusterVersion(t, "1.34", errors.New("should not be consulted"))
	plan, err := kubeBenchArgv(plugin.InfraTarget{}, plugin.Config{
		"targets": "policies", "benchmark": "gke-1.6.0", "configDir": "/opt/cfg",
	})
	if err != nil {
		t.Fatal(err)
	}
	got := argvString(plan.argv)
	for _, want := range []string{"--benchmark gke-1.6.0", "--config-dir /opt/cfg"} {
		if !strings.Contains(got, want) {
			t.Errorf("argv %q missing %q", got, want)
		}
	}
	if strings.Contains(got, "--version") {
		t.Errorf("an explicit benchmark should not also pass --version: %q", got)
	}
}

// A pinned version skips the cluster lookup, for an air-gapped run or a cluster Draugr cannot
// reach at plan time.
func TestKubeBenchArgvExplicitVersionSkipsDetection(t *testing.T) {
	withClusterVersion(t, "", errors.New("should not be consulted"))
	plan, err := kubeBenchArgv(plugin.InfraTarget{}, plugin.Config{"version": "1.31"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(argvString(plan.argv), "--version 1.31") {
		t.Errorf("argv = %q", argvString(plan.argv))
	}
}

// Parsed from real kube-bench output rather than hand-written JSON, so the field names and
// nesting are the tool's rather than what we remember of them.
func TestParseKubeBench(t *testing.T) {
	raw, err := os.ReadFile("testdata/kube-bench.json")
	if err != nil {
		t.Fatal(err)
	}
	rep, err := parseKubeBench(raw, kubeBenchScannerName, "kubernetes/prod")
	if err != nil {
		t.Fatal(err)
	}

	// The fixture holds one scored FAIL, one PASS and one unscored WARN.
	if len(rep.Results) != 2 {
		t.Fatalf("want 2 findings (the PASS is not one), got %d: %+v", len(rep.Results), rep.Results)
	}
	byRule := map[string]sarif.Result{}
	for _, r := range rep.Results {
		byRule[r.RuleID] = r
	}
	if got := byRule["kube-bench/cis/4.1.1"].Level; got != sarif.LevelError {
		t.Errorf("scored FAIL level = %q, want error", got)
	}
	if got := byRule["kube-bench/cis/4.1.3"].Level; got != sarif.LevelWarning {
		t.Errorf("WARN level = %q, want warning", got)
	}
	if _, ok := byRule["kube-bench/cis/4.1.2"]; ok {
		t.Error("a passing check should not be reported as a finding")
	}
	if got := byRule["kube-bench/cis/4.1.1"].Location.URI; got != "kubernetes/prod" {
		t.Errorf("location = %q, want the cluster it audited", got)
	}
	if rep.Rules["kube-bench/cis/4.1.1"].ShortDescription == "" || rep.Rules["kube-bench/cis/4.1.1"].HelpURI == "" {
		t.Errorf("rule metadata is missing: %+v", rep.Rules["kube-bench/cis/4.1.1"])
	}
	if rep.Rules["kube-bench/cis/4.1.1"].FullDescription == "" {
		t.Error("kube-bench supplies remediation text; it should reach the rule")
	}
}

// A cluster with no CIS failures is the point of running this, and has to render as a clean
// report rather than an error.
func TestParseKubeBenchAllPassing(t *testing.T) {
	raw := []byte(`{"Controls":[{"id":"5","text":"Policies","tests":[{"section":"5.1",
	  "results":[{"test_number":"5.1.1","test_desc":"ok","status":"PASS","scored":true}]}]}]}`)
	rep, err := parseKubeBench(raw, kubeBenchScannerName, "kubernetes/prod")
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 0 {
		t.Errorf("want no findings, got %+v", rep.Results)
	}
}

func TestParseKubeBenchRejectsGarbage(t *testing.T) {
	if _, err := parseKubeBench([]byte("not json"), kubeBenchScannerName, "kubernetes/prod"); err == nil {
		t.Error("expected an error decoding non-JSON output")
	}
}

// An unscored FAIL is a manual check the benchmark could not settle, not a confirmed breach.
func TestKubeBenchLevel(t *testing.T) {
	for _, tc := range []struct {
		status string
		scored bool
		want   sarif.Level
		report bool
	}{
		{"FAIL", true, sarif.LevelError, true},
		{"FAIL", false, sarif.LevelWarning, true},
		{"WARN", false, sarif.LevelWarning, true},
		{"PASS", true, "", false},
		{"INFO", false, "", false},
	} {
		got, ok := kubeBenchLevel(tc.status, tc.scored)
		if ok != tc.report || got != tc.want {
			t.Errorf("kubeBenchLevel(%q, scored=%v) = %q,%v want %q,%v",
				tc.status, tc.scored, got, ok, tc.want, tc.report)
		}
	}
}

// The Saga's `ref` names the cluster to audit, and findings are labelled with it. If it did not
// also select the cluster, a scan would name one cluster and describe another — which is the
// worst way for a compliance report to be wrong, because it looks right.
func TestKubeContextComesFromTheDeclaredRef(t *testing.T) {
	got := kubeContext(plugin.InfraTarget{Platform: "kubernetes", Ref: "prod-eu-west-1"}, nil)
	if got != "prod-eu-west-1" {
		t.Errorf("kubeContext = %q, want the declared ref", got)
	}
}

// An organisation's name for a cluster is not always its kubeconfig context name.
func TestKubeContextSettingOverridesTheRef(t *testing.T) {
	got := kubeContext(plugin.InfraTarget{Ref: "prod-eu-west-1"}, plugin.Config{"context": "arn:aws:eks:..."})
	if got != "arn:aws:eks:..." {
		t.Errorf("kubeContext = %q, want the explicit setting", got)
	}
}

// No ref and no setting means the ambient kubeconfig is already pointed where the operator wants.
func TestKubeContextEmptyMeansAmbient(t *testing.T) {
	if got := kubeContext(plugin.InfraTarget{Platform: "kubernetes"}, nil); got != "" {
		t.Errorf("kubeContext = %q, want empty", got)
	}
	env, cleanup, err := kubeContextEnv("")
	defer cleanup()
	if err != nil || env != nil {
		t.Errorf("an empty context should write nothing: env=%v err=%v", env, err)
	}
}

// Naming a context that does not exist is a typo or a missing kubeconfig entry, and either way
// the scan would otherwise silently audit the wrong cluster.
func TestKubeContextEnvRejectsAnUnknownContext(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	if err := os.WriteFile(path, []byte(`apiVersion: v1
kind: Config
current-context: real
contexts:
- name: real
  context: {cluster: c, user: u}
clusters:
- name: c
  cluster: {server: https://example.invalid}
users:
- name: u
  user: {}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KUBECONFIG", path)

	if _, cleanup, err := kubeContextEnv("typo"); err == nil {
		cleanup()
		t.Fatal("expected an error for a context that is not in the kubeconfig")
	} else if !strings.Contains(err.Error(), "typo") {
		t.Errorf("the error should name the missing context, got: %v", err)
	}

	env, cleanup, err := kubeContextEnv("real")
	defer cleanup()
	if err != nil {
		t.Fatalf("a known context should resolve: %v", err)
	}
	if len(env) != 1 || !strings.HasPrefix(env[0], "KUBECONFIG=") {
		t.Fatalf("env = %v, want a KUBECONFIG override", env)
	}
	// The written config selects the requested context, and the operator's own file is untouched.
	//nolint:gosec // the path came from kubeContextEnv, which just created it under t.TempDir
	written, err := os.ReadFile(strings.TrimPrefix(env[0], "KUBECONFIG="))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(written), "current-context: real") {
		t.Errorf("the temporary kubeconfig should select the requested context:\n%s", written)
	}
	orig, _ := os.ReadFile(path) //nolint:gosec // a path this test wrote under t.TempDir
	if !strings.Contains(string(orig), "current-context: real") {
		t.Error("the operator's own kubeconfig must not be modified")
	}
}

func TestKubeBenchRejectsNonInfraTargets(t *testing.T) {
	_, err := NewKubeBench().Scan(context.Background(), plugin.HostTarget{URL: "https://x"}, nil)
	if err == nil || !strings.Contains(err.Error(), "unsupported target") {
		t.Errorf("want an unsupported-target error, got %v", err)
	}
}

// The whole path: argv built with the detected version, env pointing at the declared cluster,
// output parsed.
func TestKubeBenchScan(t *testing.T) {
	withClusterVersion(t, "1.34", nil)
	raw, err := os.ReadFile("testdata/kube-bench.json")
	if err != nil {
		t.Fatal(err)
	}
	var gotArgv []string
	s := kubeBenchScanner{
		info: plugin.ScannerInfo{Name: kubeBenchScannerName},
		run: func(_ context.Context, argv, _ []string) ([]byte, error) {
			gotArgv = argv
			return raw, nil
		},
	}
	rep, err := s.Scan(context.Background(), plugin.InfraTarget{Platform: "kubernetes"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(gotArgv, " "), "--version 1.34") {
		t.Errorf("argv = %v", gotArgv)
	}
	if len(rep.Results) != 2 {
		t.Errorf("want the fixture's 2 findings, got %d", len(rep.Results))
	}
}

// The registered scanner is what the engine actually gets; the tests above exercise an injected
// one, so this checks the wiring rather than the logic.
func TestNewKubeBenchIsWired(t *testing.T) {
	s, ok := NewKubeBench().(kubeBenchScanner)
	if !ok {
		t.Fatalf("unexpected scanner type %T", NewKubeBench())
	}
	if s.run == nil {
		t.Error("the registered scanner has no exec function")
	}
}

// A tool that fails should surface as an error naming it, not as an empty report.
func TestKubeBenchScanReportsToolFailure(t *testing.T) {
	withClusterVersion(t, "1.34", nil)
	s := kubeBenchScanner{
		info: plugin.ScannerInfo{Name: kubeBenchScannerName},
		run: func(context.Context, []string, []string) ([]byte, error) {
			return nil, errors.New("exit status 1: kubectl not found")
		},
	}
	_, err := s.Scan(context.Background(), plugin.InfraTarget{Platform: "kubernetes"}, nil)
	if err == nil || !strings.Contains(err.Error(), "kube-bench") {
		t.Errorf("want an error naming the scanner, got %v", err)
	}
}

// Output the tool did produce but Draugr cannot read is a different failure from the tool
// failing, and should say so.
func TestKubeBenchScanReportsUnreadableOutput(t *testing.T) {
	withClusterVersion(t, "1.34", nil)
	s := kubeBenchScanner{
		info: plugin.ScannerInfo{Name: kubeBenchScannerName},
		run:  func(context.Context, []string, []string) ([]byte, error) { return []byte("not json"), nil },
	}
	if _, err := s.Scan(context.Background(), plugin.InfraTarget{}, nil); err == nil {
		t.Error("expected a decode error")
	}
}

// GKE and EKS report a minor version with a trailing "+" — "1.30+" meaning vendor patches on top
// of 1.30. kube-bench's version_mapping has no "30+" key, so passing it through would match no
// benchmark and drop the tool back to the stale default this whole path exists to avoid.
func TestMajorMinor(t *testing.T) {
	for _, tc := range []struct {
		major, minor, want string
		wantErr            bool
	}{
		{major: "1", minor: "34", want: "1.34"},
		{major: "1", minor: "30+", want: "1.30"}, // managed clusters
		{major: "1", minor: "", wantErr: true},
		{major: "", minor: "34", wantErr: true},
	} {
		got, err := majorMinor(tc.major, tc.minor, "v"+tc.major+"."+tc.minor+".0")
		if tc.wantErr {
			if err == nil {
				t.Errorf("majorMinor(%q,%q) = %q, want an error", tc.major, tc.minor, got)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("majorMinor(%q,%q) = %q,%v want %q", tc.major, tc.minor, got, err, tc.want)
		}
	}
}

// withCurrentContext swaps the ambient-context lookup for a fixed answer.
func withCurrentContext(t *testing.T, name string) {
	t.Helper()
	prev := currentKubeContext
	currentKubeContext = func() string { return name }
	t.Cleanup(func() { currentKubeContext = prev })
}

// `ref` is optional in the schema, so falling back to the ambient context is a reachable
// default. The label has to follow it: a compliance report reading "kubernetes/" says nothing
// about what was examined.
func TestClusterLabelNamesTheAmbientContext(t *testing.T) {
	withCurrentContext(t, "kind-local")
	if got := clusterLabel(""); got != "kubernetes/kind-local" {
		t.Errorf("clusterLabel(\"\") = %q, want the ambient context named", got)
	}
	if got := clusterLabel("prod-eu-west-1"); got != "kubernetes/prod-eu-west-1" {
		t.Errorf("clusterLabel = %q", got)
	}
}

// No ref, and no current context either — an in-cluster service account, say. There is nothing
// honest to name, and a trailing slash is not a name.
func TestClusterLabelWithNothingToName(t *testing.T) {
	withCurrentContext(t, "")
	if got := clusterLabel(""); got != "kubernetes" {
		t.Errorf("clusterLabel = %q, want a bare platform name", got)
	}
}

// End to end: a component that declares a cluster without naming it still produces findings that
// say which cluster they are about.
func TestKubeBenchScanLabelsAnUnnamedCluster(t *testing.T) {
	withClusterVersion(t, "1.34", nil)
	withCurrentContext(t, "kind-local")
	raw, err := os.ReadFile("testdata/kube-bench.json")
	if err != nil {
		t.Fatal(err)
	}
	s := kubeBenchScanner{
		info: plugin.ScannerInfo{Name: kubeBenchScannerName},
		run:  func(context.Context, []string, []string) ([]byte, error) { return raw, nil },
	}
	rep, err := s.Scan(context.Background(), plugin.InfraTarget{Platform: "kubernetes"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := rep.Results[0].Location.URI; got != "kubernetes/kind-local" {
		t.Errorf("location = %q, want the cluster actually audited", got)
	}
}

// A kubeconfig that cannot be read is a different failure from a context that is not in it, and
// the scan should say which rather than reporting a missing context that might well be there.
func TestKubeContextEnvReportsAnUnreadableKubeconfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	if err := os.WriteFile(path, []byte("\tthis: is: not: yaml\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KUBECONFIG", path)
	_, cleanup, err := kubeContextEnv("prod")
	defer cleanup()
	if err == nil {
		t.Fatal("expected an error for an unreadable kubeconfig")
	}
	if !strings.Contains(err.Error(), "kubeconfig") {
		t.Errorf("the error should name what it could not read, got: %v", err)
	}
}

// With no kubeconfig there is no current context, and the label falls back to the bare platform
// rather than inventing one.
func TestDetectCurrentKubeContextWithoutAConfig(t *testing.T) {
	t.Setenv("KUBECONFIG", filepath.Join(t.TempDir(), "does-not-exist"))
	if got := detectCurrentKubeContext(); got != "" {
		t.Errorf("detectCurrentKubeContext = %q, want empty", got)
	}
}

// The version strings are real ones from each provider, because the parse is the whole
// mechanism: a platform Draugr fails to recognize is a cluster audited against the wrong
// benchmark, and one it recognizes wrongly is the same thing with more confidence.
func TestPlatformFrom(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, gitVersion, want string
	}{
		{"eks", "v1.30.4-eks-a737599", "eks"},
		{"gke", "v1.29.7-gke.1104000", "gke"},
		{"aks", "v1.27.6+aks1", "aks"},
		{"k3s", "v1.28.5+k3s1", "k3s"},
		{"rke2", "v1.27.6+rke2r1", "rke2r"},
		{"aliyun", "v1.18.8-aliyun.1", "aliyun"},

		// A vanilla cluster must stay vanilla. kind and kubeadm report a bare version, and a
		// release candidate parses exactly like a platform suffix would — "rc" is a token in the
		// same position as "eks". Treating it as a platform would send the scan looking for a
		// benchmark that does not exist.
		{"kind", "v1.34.0", ""},
		{"release candidate", "v1.31.0-rc.1", ""},
		{"unknown distribution", "v1.30.1-acme.4", ""},
		{"empty", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := platformFrom(tc.gitVersion); got != tc.want {
				t.Errorf("platformFrom(%q) = %q, want %q", tc.gitVersion, got, tc.want)
			}
		})
	}
}

// The bug: kube-bench only consults its platform detection when neither --benchmark nor
// --version is set (cmd/common.go, getBenchmarkVersion). Supplying --version to avoid the stale
// 1.18 fallback therefore forced every managed cluster onto the generic cis-* benchmark, which
// is not a subset of the provider one — it fails a cluster for control-plane settings that are
// not the customer's to make, and skips the provider checks that are.
func TestKubeBenchArgvLetsAManagedClusterPickItsOwnBenchmark(t *testing.T) {
	withClusterFacts(t, clusterFacts{Version: "1.30", Platform: "eks"}, nil)

	plan, err := kubeBenchArgv(plugin.InfraTarget{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := argvString(plan.argv)
	for _, unwanted := range []string{"--version", "--benchmark"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("argv %q must not carry %s on a managed cluster: it suppresses kube-bench's platform benchmark", got, unwanted)
		}
	}
	if plan.platform != "eks" {
		t.Errorf("plan.platform = %q, want %q — without it the output cannot be checked", plan.platform, "eks")
	}
}

// A vanilla cluster keeps the behaviour that made --version necessary in the first place.
func TestKubeBenchArgvStillPinsTheVersionForAVanillaCluster(t *testing.T) {
	withClusterFacts(t, clusterFacts{Version: "1.34"}, nil)

	plan, err := kubeBenchArgv(plugin.InfraTarget{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(argvString(plan.argv), "--version 1.34") {
		t.Errorf("argv = %q, want the detected version pinned", argvString(plan.argv))
	}
	if plan.platform != "" {
		t.Errorf("plan.platform = %q, want empty: there is no platform expectation to check", plan.platform)
	}
}

func benchDoc(version string) kubeBenchDoc {
	return kubeBenchDoc{Controls: []kubeBenchControl{{Version: version}}}
}

// Withholding the flags hands the choice to a tool that has its own fallback: when kube-bench
// cannot detect the cluster it assumes Kubernetes 1.18, audits against cis-1.6, and reports the
// result as though it were the one asked for. The input is therefore not the guarantee — this
// is.
func TestVerifyBenchmark(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, benchmark, platform string
		wantErr                   bool
	}{
		{name: "matching platform benchmark", benchmark: "eks-1.8.0", platform: "eks"},
		{name: "k3s uses a compound prefix", benchmark: "k3s-cis-1.9", platform: "k3s"},
		{name: "rke2 is not rke", benchmark: "rke2-cis-1.8", platform: "rke2r"},

		// The failure this exists for: the scan ran, produced findings, and audited the wrong
		// standard.
		{name: "stale default on a managed cluster", benchmark: "cis-1.6", platform: "eks", wantErr: true},
		{name: "wrong provider", benchmark: "gke-1.9.0", platform: "eks", wantErr: true},
		{name: "rke benchmark on an rke2 cluster", benchmark: "rke-cis-1.7", platform: "rke2r", wantErr: true},

		// Nothing was withheld, so there is no expectation to hold the tool to.
		{name: "vanilla cluster", benchmark: "cis-1.9", platform: ""},
		{name: "unknown platform", benchmark: "cis-1.9", platform: "acme"},
		{name: "tool reported no benchmark", benchmark: "", platform: "eks"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := verifyBenchmark(benchDoc(tc.benchmark), tc.platform)
			if tc.wantErr && err == nil {
				t.Fatalf("verifyBenchmark(%q, %q) = nil, want an error", tc.benchmark, tc.platform)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("verifyBenchmark(%q, %q) = %v, want nil", tc.benchmark, tc.platform, err)
			}
			if tc.wantErr && !strings.Contains(err.Error(), "benchmark") {
				t.Errorf("the error should point at the setting that resolves it, got: %v", err)
			}
		})
	}
}

// An empty document is a decode that found nothing, not a benchmark mismatch. Reporting it as
// the wrong standard would send the reader after the wrong problem.
func TestVerifyBenchmarkIgnoresAnEmptyDocument(t *testing.T) {
	t.Parallel()
	if err := verifyBenchmark(kubeBenchDoc{}, "eks"); err != nil {
		t.Errorf("verifyBenchmark on an empty document = %v, want nil", err)
	}
}

// The end-to-end version of the guard: a managed cluster, kube-bench falling back to the
// benchmark it uses when its own detection fails, and a scan that must not return findings.
//
// The unit test covers the comparison; this covers the wiring, which is where a check like this
// usually dies — computed correctly, then never consulted on the path that matters.
func TestKubeBenchScanRefusesTheWrongBenchmark(t *testing.T) {
	withClusterFacts(t, clusterFacts{Version: "1.30", Platform: "eks"}, nil)

	stale := []byte(`{"Controls":[{"id":"5","version":"cis-1.6","text":"Kubernetes Policies","tests":[
		{"section":"5.1","desc":"RBAC","results":[
			{"test_number":"5.1.1","test_desc":"Ensure that the cluster-admin role is only used where required","status":"FAIL","scored":true}
		]}
	]}]}`)

	s := kubeBenchScanner{
		info: plugin.ScannerInfo{Name: kubeBenchScannerName},
		run: func(_ context.Context, argv, _ []string) ([]byte, error) {
			if strings.Contains(strings.Join(argv, " "), "--version") {
				t.Errorf("argv %v must not pin a version on a managed cluster", argv)
			}
			return stale, nil
		},
	}

	rep, err := s.Scan(context.Background(), plugin.InfraTarget{Platform: "kubernetes"}, nil)
	if err == nil {
		t.Fatalf("a scan against the wrong benchmark must fail, got %d findings", len(rep.Results))
	}
	if len(rep.Results) != 0 {
		t.Errorf("no findings should be built from the wrong benchmark, got %d", len(rep.Results))
	}
	for _, want := range []string{"cis-1.6", "eks", "benchmark"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error should name %q so the reader can act on it, got: %v", want, err)
		}
	}
}

// The matching case has to work too, or the guard is just a way to fail every managed scan.
func TestKubeBenchScanAcceptsThePlatformBenchmark(t *testing.T) {
	withClusterFacts(t, clusterFacts{Version: "1.30", Platform: "eks"}, nil)

	out := []byte(`{"Controls":[{"id":"4","version":"eks-1.8.0","text":"Kubernetes Policies","tests":[
		{"section":"4.1","desc":"RBAC","results":[
			{"test_number":"4.1.1","test_desc":"Ensure that the cluster-admin role is only used where required","status":"FAIL","scored":true}
		]}
	]}]}`)

	s := kubeBenchScanner{
		info: plugin.ScannerInfo{Name: kubeBenchScannerName},
		run:  func(context.Context, []string, []string) ([]byte, error) { return out, nil },
	}

	rep, err := s.Scan(context.Background(), plugin.InfraTarget{Platform: "kubernetes"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 1 {
		t.Fatalf("want the one finding, got %d", len(rep.Results))
	}
	if got := rep.Results[0].RuleID; got != "kube-bench/cis/4.1.1" {
		t.Errorf("rule id = %q, want the EKS benchmark's own numbering", got)
	}
}

// AKS is the distribution that does not announce itself. GKE and EKS stamp the version string;
// a real AKS cluster reports a bare v1.34.2 and is indistinguishable from kubeadm by version
// alone, so it was audited against the generic benchmark with nothing to signal it.
func TestPlatformFromNodes(t *testing.T) {
	t.Parallel()

	node := func(labels map[string]string, providerID string) *corev1.Node {
		return &corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: "n1", Labels: labels},
			Spec:       corev1.NodeSpec{ProviderID: providerID},
		}
	}

	for _, tc := range []struct {
		name string
		node *corev1.Node
		want string
	}{
		{"aks label", node(map[string]string{"kubernetes.azure.com/cluster": "mc_rg_cluster_region"}, ""), "aks"},
		// Deliberately not AKS: RKE2, RKE and kubeadm all carry this when the Azure cloud
		// provider is configured. The provider ID says which cloud the VM is on, not who runs
		// the control plane.
		{"azure provider id without the label", node(nil, "azure:///subscriptions/abc/resourceGroups/rg/providers/x"), ""},

		// A cluster on someone else's cloud is not automatically that cloud's managed service.
		{"gce provider id", node(nil, "gce://project/zone/instance"), ""},
		{"aws provider id", node(nil, "aws:///us-east-1a/i-0abc"), ""},
		{"bare node", node(nil, ""), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			client := fake.NewSimpleClientset(tc.node)
			if got := platformFromNodes(context.Background(), client); got != tc.want {
				t.Errorf("platformFromNodes = %q, want %q", got, tc.want)
			}
		})
	}
}

// Reading nodes can be denied on a shared cluster. That must not fail the scan: a missed platform
// leaves the version string to decide exactly as it did before, which is the pre-existing
// behaviour rather than a new failure.
func TestPlatformFromNodesToleratesNoNodes(t *testing.T) {
	t.Parallel()
	if got := platformFromNodes(context.Background(), fake.NewSimpleClientset()); got != "" {
		t.Errorf("platformFromNodes with no readable nodes = %q, want empty", got)
	}
}

// The ordering that protects every distribution which stamps its own version: node inspection is
// a fallback, not an override. An RKE2 cluster on Azure VMs carries an azure:// provider ID and
// is emphatically not AKS — auditing it against the AKS benchmark would drop the control-plane
// checks that are the whole point of running the benchmark on a cluster you manage yourself.
func TestVersionStringWinsOverNodeInspection(t *testing.T) {
	t.Parallel()

	// RKE2 announces itself, so this never reaches the node.
	if got := platformFrom("v1.27.6+rke2r1"); got != "rke2r" {
		t.Fatalf("platformFrom = %q, want rke2r", got)
	}

	// And if it did reach the node, an Azure VM must still not read as AKS.
	azureVM := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "rke2-worker"},
		Spec:       corev1.NodeSpec{ProviderID: "azure:///subscriptions/abc/resourceGroups/rg/providers/x"},
	}
	if got := platformFromNodes(context.Background(), fake.NewSimpleClientset(azureVM)); got != "" {
		t.Errorf("a self-managed cluster on Azure VMs read as %q; only AKS's own node label should count", got)
	}
}

func TestKubeBenchUsesTheProvisionedConfigDir(t *testing.T) {
	// Without this the install is useless: kube-bench searches /etc/kube-bench/cfg and its own
	// directory, and finds nothing Draugr put under ~/.draugr.
	orig := provisionedKubeBenchCfg
	t.Cleanup(func() { provisionedKubeBenchCfg = orig })
	provisionedKubeBenchCfg = func() string { return "/somewhere/data/kube-bench" }

	plan, err := kubeBenchArgv(plugin.InfraTarget{Platform: "kubernetes"},
		plugin.Config{"benchmark": "cis-1.12"})
	if err != nil {
		t.Fatalf("kubeBenchArgv: %v", err)
	}
	if !slices.Contains(plan.argv, "--config-dir") ||
		!slices.Contains(plan.argv, "/somewhere/data/kube-bench") {
		t.Errorf("argv should point at the provisioned tree: %v", plan.argv)
	}
}

func TestKubeBenchPrefersAnExplicitConfigDir(t *testing.T) {
	// A descriptor that says where the benchmarks are always wins; provisioning is the fallback.
	orig := provisionedKubeBenchCfg
	t.Cleanup(func() { provisionedKubeBenchCfg = orig })
	provisionedKubeBenchCfg = func() string { return "/provisioned" }

	plan, err := kubeBenchArgv(plugin.InfraTarget{Platform: "kubernetes"}, plugin.Config{"configDir": "/mine", "benchmark": "cis-1.12"})
	if err != nil {
		t.Fatalf("kubeBenchArgv: %v", err)
	}
	if slices.Contains(plan.argv, "/provisioned") {
		t.Errorf("the explicit setting should win: %v", plan.argv)
	}
	if !slices.Contains(plan.argv, "/mine") {
		t.Errorf("missing the explicit dir: %v", plan.argv)
	}
}

func TestKubeBenchLeavesTheSearchAloneWhenNothingIsProvisioned(t *testing.T) {
	// A system install with its own cfg keeps working exactly as before.
	orig := provisionedKubeBenchCfg
	t.Cleanup(func() { provisionedKubeBenchCfg = orig })
	provisionedKubeBenchCfg = func() string { return "" }

	plan, err := kubeBenchArgv(plugin.InfraTarget{Platform: "kubernetes"},
		plugin.Config{"benchmark": "cis-1.12"})
	if err != nil {
		t.Fatalf("kubeBenchArgv: %v", err)
	}
	if slices.Contains(plan.argv, "--config-dir") {
		t.Errorf("nothing to point at, so nothing should be passed: %v", plan.argv)
	}
}

// withoutProvisionedCfg pretends `draugr tools install` has not fetched kube-bench's benchmarks,
// so a test asserting argv is not answering a question about the machine it runs on.
func withoutProvisionedCfg(t *testing.T) {
	t.Helper()
	orig := provisionedKubeBenchCfg
	t.Cleanup(func() { provisionedKubeBenchCfg = orig })
	provisionedKubeBenchCfg = func() string { return "" }
}

// TestProviderOperatedNarrowsToWhatTheProviderRuns is the test the framework needs most.
//
// Marking a whole managed cluster as somebody else's problem would hide the half that is not:
// RBAC, Pod Security and network policy are the team's whoever runs the control plane, and they
// are usually the findings that matter. Between over- and under-claiming, under-claiming costs
// noise and over-claiming costs a fix nobody makes.
func TestProviderOperatedNarrowsToWhatTheProviderRuns(t *testing.T) {
	for _, c := range []struct {
		nodeType string
		want     bool
	}{
		{"master", true},
		{"etcd", true},
		{"controlplane", true},
		{"ControlPlane", true}, // kube-bench's casing is not something to depend on
		{"node", false},        // node pools are usually configurable by the team
		{"policies", false},    // RBAC and Pod Security are the team's, always
		{"", false},
	} {
		t.Run(c.nodeType, func(t *testing.T) {
			if got := providerRunsIt(c.nodeType); got != c.want {
				t.Errorf("providerRunsIt(%q) = %v, want %v", c.nodeType, got, c.want)
			}
		})
	}
}

// TestProviderOperatedIsOnlyClaimedWhenDeclared: a cluster nobody said anything about is the
// team's, and every finding on it is theirs to act on.
func TestProviderOperatedIsOnlyClaimedWhenDeclared(t *testing.T) {
	const doc = `{"Controls":[{"version":"cis-1.12","node_type":"master","tests":[
	 {"section":"1.1","desc":"Control plane node configuration","results":[
	  {"test_number":"1.1.1","test_desc":"API server pod file permissions","status":"FAIL","scored":true}]}]}]}`

	declared, err := parseKubeBenchOperated([]byte(doc), "kube-bench-job", "kubernetes/c", true)
	if err != nil {
		t.Fatal(err)
	}
	if !declared.Results[0].ProviderOperated {
		t.Error("a control-plane finding on a declared managed cluster is not the team's to fix")
	}

	undeclared, err := parseKubeBenchOperated([]byte(doc), "kube-bench-job", "kubernetes/c", false)
	if err != nil {
		t.Fatal(err)
	}
	if undeclared.Results[0].ProviderOperated {
		t.Error("claimed somebody else operates a cluster nobody said was managed")
	}
}
