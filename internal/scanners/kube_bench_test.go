package scanners

import (
	"os"
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

// The default matters more than most: it is what makes a scan mean the same thing on a laptop,
// in CI, and on a node. See defaultKubeBenchTargets.
func TestKubeBenchArgvDefaultsToTheClusterWideSection(t *testing.T) {
	argv, err := kubeBenchArgv(plugin.InfraTarget{Platform: "kubernetes"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"kube-bench", "run", "--json", "--targets", "policies"}
	if len(argv) != len(want) {
		t.Fatalf("argv = %v, want %v", argv, want)
	}
	for i := range want {
		if argv[i] != want[i] {
			t.Errorf("argv = %v, want %v", argv, want)
			break
		}
	}
}

func TestKubeBenchArgvHonoursConfig(t *testing.T) {
	argv, err := kubeBenchArgv(plugin.InfraTarget{}, plugin.Config{
		"targets": "master,node", "benchmark": "cis-1.9",
	})
	if err != nil {
		t.Fatal(err)
	}
	got := ""
	for _, a := range argv {
		got += a + " "
	}
	for _, want := range []string{"--targets master,node", "--benchmark cis-1.9"} {
		if !contains(got, want) {
			t.Errorf("argv %q missing %q", got, want)
		}
	}
}

func contains(hay, needle string) bool { return len(hay) >= len(needle) && indexOf(hay, needle) >= 0 }

func indexOf(hay, needle string) int {
	for i := 0; i+len(needle) <= len(hay); i++ {
		if hay[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
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
