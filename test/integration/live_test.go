//go:build integration

package integration

import (
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/test/sealed"
)

var updateLive = flag.Bool("update-live", false, "rewrite the live tier's recorded structures instead of comparing against them")

// liveEnv turns the live tier on. It reaches the internet, takes tens of minutes and its answer
// changes as the advisory databases do, so it runs where it is asked for rather than on every run
// of the integration suite.
const liveEnv = "DRAUGR_LIVE"

// liveDemoEnv names a checkout of draugr-demo for TestLiveDemo to scan.
const liveDemoEnv = "DRAUGR_LIVE_DEMO"

// requireLive skips unless the live tier was asked for. It is a skip under
// DRAUGR_INTEGRATION_STRICT too: strict mode says the tools are installed, not that a job wants
// results that move every day.
func requireLive(t *testing.T) {
	t.Helper()
	if os.Getenv(liveEnv) == "" {
		t.Skipf("set %s=1 to scan the fixtures against the latest advisory databases and real registries", liveEnv)
	}
}

// TestLiveScenarios scans every sealed scenario on the host, with the network, against whatever
// the advisory databases and package registries hold today, and holds the result to the
// scenario's live.yaml: the packages found and the scanners that found them, never the advisories.
//
// The sealed tier proves Draugr against databases that never change. This proves the other half,
// that the pinned scanners still read today's databases and registries, which a sealed run cannot
// see. Its answer moves as advisories are published, so a difference is recorded rather than
// failed: -update-live rewrites live.yaml, and the nightly job proposes the rewrite as a pull
// request. What still fails is a structure no advisory can explain, an ecosystem or a control that
// reported results before and reports none now, and a control that could not run.
//
// A scenario that takes something away from its container (a tool, a database) is about a sealed
// failure, and one that asks the sealed server for something is about what that server answers.
// Both are left to the sealed tier.
func TestLiveScenarios(t *testing.T) {
	requireLive(t)
	requireTool(t, "git", "each scenario is committed to a repository before it is scanned")
	for _, tool := range []string{"trivy", "semgrep", "gitleaks", "gosec", "govulncheck", "retire", "go"} {
		requireTool(t, tool, "a live scenario runs it")
	}
	bin := draugrBin(t)

	dirs, err := filepath.Glob(filepath.Join(ecosystems, "*", "expected.yaml"))
	if err != nil || len(dirs) == 0 {
		t.Fatalf("no scenarios under %s: %v", ecosystems, err)
	}
	for _, exp := range dirs {
		s, err := sealed.LoadScenario(filepath.Dir(exp))
		if err != nil {
			t.Fatal(err)
		}
		if s.Expected.Sealed != (sealed.RunOptions{}) || servedBySealed(s) {
			continue
		}
		t.Run(s.Name, func(t *testing.T) { runLive(t, s, bin) })
	}
}

// servedBySealed reports whether s scans something only the sealed server answers for: an image,
// a package repository or a host at its loopback address. Nothing listens there outside the
// sealed container.
func servedBySealed(s sealed.Scenario) bool {
	return len(s.Expected.Requests) > 0
}

func runLive(t *testing.T, s sealed.Scenario, bin string) {
	work := t.TempDir()
	rules := filepath.Join(work, "semgrep.yaml")
	for _, err := range []error{
		copyFile(filepath.Join(s.Dir, "draugr.saga.yaml"), filepath.Join(work, "draugr.saga.yaml"), 0o600),
		copyFile(filepath.Join(ecosystems, "semgrep.yaml"), rules, 0o600),
		s.CopyWorkdir(work),
	} {
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Prepare(work); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(work, "out")
	cmd := exec.Command(bin, "scan", "draugr.saga.yaml", "--output", out, "--log-level", "warn") // #nosec G204 -- the binary under test
	cmd.Dir = work
	cmd.Env = append(os.Environ(), "DRAUGR_SEALED_SEMGREP_RULES="+rules, "NO_COLOR=1")
	console, err := cmd.CombinedOutput()
	t.Logf("%s: draugr scan exit=%v\n%s", s.Name, err, console)

	checkLive(t, s.Name, s.Expected.Errors, out, filepath.Join(s.Dir, "live.yaml"))
}

// TestLiveDemo scans draugr-demo, the descriptor somebody evaluating Draugr runs first, with the
// network and today's databases, and holds it to testdata/draugr-demo.live.yaml. The structure is
// grouped by ecosystem, so a language the demo carries that stops producing findings is named as
// that language rather than as a smaller total.
//
// The images and provenance controls are left out. Their packages and signatures belong to tags
// that move on their publishers' schedules, which would make every night's structure differ for
// reasons that say nothing about Draugr. The licenses control stays: its results are recorded per
// image reference, which moves only when the demo's descriptor does.
func TestLiveDemo(t *testing.T) {
	requireLive(t)
	demo := os.Getenv(liveDemoEnv)
	if demo == "" {
		if os.Getenv(strictEnv) != "" {
			t.Fatalf("%s is set and %s is not: the job asked for the live tier and gave it no demo to scan", liveEnv, liveDemoEnv)
		}
		t.Skipf("set %s to a checkout of draugr-demo to scan it", liveDemoEnv)
	}
	for _, tool := range []string{"trivy", "semgrep", "gitleaks", "govulncheck", "retire", "go"} {
		requireTool(t, tool, "the demo's descriptor enables it")
	}
	bin := draugrBin(t)
	out := t.TempDir()
	cmd := exec.Command(bin, "scan", "draugr.saga.yaml", "--no-publish", // #nosec G204 -- the binary under test
		"--controls", "sca,secrets,sast,iac,licenses", "--output", out, "--log-level", "warn")
	cmd.Dir = demo
	cmd.Env = append(os.Environ(), "NO_COLOR=1")
	console, err := cmd.CombinedOutput()
	t.Logf("draugr-demo: draugr scan exit=%v\n%s", err, console)

	checkLive(t, "draugr-demo", nil, out, filepath.Join("testdata", "draugr-demo.live.yaml"))
}

// checkLive reads a live scan's output and compares its structure with the recording at path, or
// rewrites the recording under -update-live.
func checkLive(t *testing.T, name string, errs []sealed.ErrorExpectation, out, path string) {
	t.Helper()
	problems, err := sealed.CheckErrors(errs, readFile(t, filepath.Join(out, "report.json")))
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	for _, p := range problems {
		t.Errorf("%s: %s", name, p)
	}
	results := readFile(t, filepath.Join(out, "results.sarif"))
	if err := sealed.ValidateSARIF(results); err != nil {
		t.Errorf("%s: results.sarif is not valid SARIF 2.1.0: %v", name, err)
	}
	found, err := sealed.Observe(results)
	if err != nil {
		t.Fatal(err)
	}
	observed := sealed.Summarize(found)

	recorded, exists, err := sealed.LoadStructure(path)
	if err != nil {
		t.Fatal(err)
	}
	if lost := sealed.Lost(recorded, observed); len(lost) > 0 {
		t.Errorf("%s: %s. The fixtures pin versions with published advisories, so this is a scanner "+
			"that stopped reading something rather than a database that changed, and it is not written "+
			"down as the new expectation", name, strings.Join(lost, "; "))
		return
	}
	drift := sealed.Drift(recorded, observed)
	if *updateLive {
		if exists && len(drift) == 0 {
			return
		}
		raw, err := observed.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		t.Logf("%s: wrote %s\n%s", name, path, strings.Join(drift, "\n"))
		return
	}
	if !exists {
		t.Errorf("%s: %s does not exist; run with -update-live to record it", name, path)
		return
	}
	if len(drift) > 0 {
		t.Errorf("%s: the structure differs from %s (-update-live records it):\n%s", name, path, strings.Join(drift, "\n"))
	}
}
