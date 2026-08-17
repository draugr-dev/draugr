//go:build integration

package scanners

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
	"k8s.io/client-go/kubernetes/fake"
)

// cisCatalogBenchmark is the benchmark revision the catalog is pinned to.
const cisCatalogBenchmark = cisCatalogVersion

// kubeBenchCfgEnv points at kube-bench's own cfg/ tree.
const kubeBenchCfgEnv = "KUBE_BENCH_CFG"

// TestCISCatalogMatchesKubeBench holds the catalog to the benchmark it claims to describe.
//
// The catalog is what makes partial coverage honest: every check in the section is reported,
// so one this scanner cannot decide still reaches the reader instead of being absent. That
// guarantee is only as good as the list, and the list is hand-maintained — CIS renumbers checks
// between revisions, adds them, and retires them.
//
// The failure this prevents is quiet in both directions. A check added upstream and missing here
// is never reported at all, so a scan covers less than the benchmark and says nothing. A check
// removed upstream but left here is reported forever as needing review, sending someone after a
// requirement that no longer exists.
//
// Nothing about this test writes a check for us. It makes an out-of-date catalog impossible to
// ship without noticing, which is the part that can be automated.
func TestCISCatalogMatchesKubeBench(t *testing.T) {
	cfgDir := os.Getenv(kubeBenchCfgEnv)
	if cfgDir == "" {
		t.Skipf("%s is not set — point it at kube-bench's cfg/ directory to check the catalog for drift", kubeBenchCfgEnv)
	}

	path := filepath.Join(cfgDir, cisCatalogBenchmark, "policies.yaml")
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read %s: %v\n%s points at %q; it should be the cfg/ directory that ships with kube-bench",
			path, err, kubeBenchCfgEnv, cfgDir)
	}

	var doc struct {
		Groups []struct {
			Checks []struct {
				ID   string `yaml:"id"`
				Text string `yaml:"text"`
			} `yaml:"checks"`
		} `yaml:"groups"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}

	upstream := map[string]string{}
	for _, g := range doc.Groups {
		for _, c := range g.Checks {
			upstream[c.ID] = c.Text
		}
	}
	if len(upstream) == 0 {
		t.Fatalf("%s parsed to zero checks — a guard that checks nothing is worse than no guard", path)
	}

	var missing, extra []string
	for id := range upstream {
		if _, ok := cisPolicyByID[id]; !ok {
			missing = append(missing, id)
		}
	}
	for _, c := range cisPolicies {
		if _, ok := upstream[c.ID]; !ok {
			extra = append(extra, c.ID)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)

	for _, id := range missing {
		t.Errorf("%s adds check %s (%q), which the catalog does not list — it would never be reported",
			cisCatalogBenchmark, id, upstream[id])
	}
	for _, id := range extra {
		t.Errorf("the catalog lists check %s, which %s does not have — it would be reported forever as needing review",
			id, cisCatalogBenchmark)
	}

	// Wording drift matters less than the id set, but a check whose meaning changed under a
	// stable number is the one a reader would never think to question. The catalog drops the
	// benchmark's trailing "(Manual)", so the upstream text should still begin with ours.
	for _, c := range cisPolicies {
		text, ok := upstream[c.ID]
		if !ok {
			continue
		}
		if !strings.HasPrefix(text, c.Title) {
			t.Errorf("check %s was reworded upstream:\n  catalog: %q\n  %s: %q",
				c.ID, c.Title, cisCatalogBenchmark, text)
		}
	}

	t.Logf("catalog checked against %s: %d checks, %d decided here",
		cisCatalogBenchmark, len(upstream), decidedCheckCount(t))
}

// decidedCheckCount reports how many checks this scanner answers from the cluster rather than
// handing back for review. Logged so coverage is a number someone can watch move, instead of a
// claim in a doc that ages.
func decidedCheckCount(t *testing.T) int {
	t.Helper()
	// evaluatePolicies against an empty cluster still reports which checks it implements.
	decided, err := evaluatePolicies(t.Context(), fake.NewSimpleClientset(), nil)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	return len(decided)
}

// TestManagedServicesCountsMatchKubeBench holds the counts Draugr reports to the benchmarks they
// describe.
//
// The finding tells a reader how much of their benchmark went unassessed. A number that drifts
// understates or overstates exactly the thing it exists to disclose, and it is the kind of number
// nobody re-derives once written.
func TestManagedServicesCountsMatchKubeBench(t *testing.T) {
	cfgDir := os.Getenv(kubeBenchCfgEnv)
	if cfgDir == "" {
		t.Skipf("%s is not set — point it at kube-bench's cfg/ directory to check the counts", kubeBenchCfgEnv)
	}
	if len(managedServicesByPlatform) == 0 {
		t.Fatal("no platform is described, so this checks nothing")
	}

	for platform, section := range managedServicesByPlatform {
		path := filepath.Join(cfgDir, section.Benchmark, "managedservices.yaml")
		raw, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			t.Errorf("%s: read %s: %v", platform, path, err)
			continue
		}
		var doc struct {
			Groups []struct {
				Checks []struct {
					ID string `yaml:"id"`
				} `yaml:"checks"`
			} `yaml:"groups"`
		}
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			t.Errorf("%s: parse %s: %v", platform, path, err)
			continue
		}
		got := 0
		for _, g := range doc.Groups {
			got += len(g.Checks)
		}
		if got != section.Checks {
			t.Errorf("%s: %s has %d managed-services checks, Draugr reports %d",
				platform, section.Benchmark, got, section.Checks)
		}
	}
}
