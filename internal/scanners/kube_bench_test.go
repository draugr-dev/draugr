package scanners

import (
	"errors"
	"os"
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
	clusterVersion = func() (string, error) { return version, err }
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
	rep, err := parseKubeBench(raw, plugin.InfraTarget{Platform: "kubernetes", Ref: "prod"}, nil)
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
	rep, err := parseKubeBench(raw, plugin.InfraTarget{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 0 {
		t.Errorf("want no findings, got %+v", rep.Results)
	}
}

func TestParseKubeBenchRejectsGarbage(t *testing.T) {
	if _, err := parseKubeBench([]byte("not json"), plugin.InfraTarget{}, nil); err == nil {
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
