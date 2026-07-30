package scanners

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

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

// withClusterVersion swaps the cluster lookup for a fixed answer.
func withClusterVersion(t *testing.T, version string, err error) {
	t.Helper()
	prev := clusterVersion
	clusterVersion = func(string) (string, error) { return version, err }
	t.Cleanup(func() { clusterVersion = prev })
}

func argvString(argv []string) string { return strings.Join(argv, " ") }

// The default matters more than most: it is what makes a scan mean the same thing on a laptop,
// in CI, and on a node. See defaultKubeBenchTargets.
func TestKubeBenchArgvDefaults(t *testing.T) {
	withClusterVersion(t, "1.34", nil)
	argv, err := kubeBenchArgv(plugin.InfraTarget{Platform: "kubernetes"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := argvString(argv), "kube-bench run --json --targets policies --version 1.34"; got != want {
		t.Errorf("argv = %q, want %q", got, want)
	}
}

// The bug this guards: kube-bench cannot read the kubelet off a node, so it falls back to
// Kubernetes 1.18 and audits against cis-1.6 without a word. On a 1.34 cluster that is a
// benchmark sixteen minor versions stale, and it under-reports. Draugr tells it the version.
func TestKubeBenchArgvPassesTheDetectedClusterVersion(t *testing.T) {
	withClusterVersion(t, "1.29", nil)
	argv, err := kubeBenchArgv(plugin.InfraTarget{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(argvString(argv), "--version 1.29") {
		t.Errorf("argv %q should carry the detected version", argvString(argv))
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
	argv, err := kubeBenchArgv(plugin.InfraTarget{}, plugin.Config{
		"targets": "policies", "benchmark": "gke-1.6.0", "configDir": "/opt/cfg",
	})
	if err != nil {
		t.Fatal(err)
	}
	got := argvString(argv)
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
	argv, err := kubeBenchArgv(plugin.InfraTarget{}, plugin.Config{"version": "1.31"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(argvString(argv), "--version 1.31") {
		t.Errorf("argv = %q", argvString(argv))
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
	if got := byRule["cis/4.1.1"].Level; got != sarif.LevelError {
		t.Errorf("scored FAIL level = %q, want error", got)
	}
	if got := byRule["cis/4.1.3"].Level; got != sarif.LevelWarning {
		t.Errorf("WARN level = %q, want warning", got)
	}
	if _, ok := byRule["cis/4.1.2"]; ok {
		t.Error("a passing check should not be reported as a finding")
	}
	if got := byRule["cis/4.1.1"].Location.URI; got != "kubernetes/prod" {
		t.Errorf("location = %q, want the cluster it audited", got)
	}
	if rep.Rules["cis/4.1.1"].ShortDescription == "" || rep.Rules["cis/4.1.1"].HelpURI == "" {
		t.Errorf("rule metadata is missing: %+v", rep.Rules["cis/4.1.1"])
	}
	if rep.Rules["cis/4.1.1"].FullDescription == "" {
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
