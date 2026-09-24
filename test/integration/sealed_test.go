//go:build integration

package integration

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/draugr-dev/draugr/test/sealed"
)

var updateSealed = flag.Bool("update-sealed", false, "rewrite the sealed scenarios' golden reports")

// ecosystems holds the sealed scenarios, one directory each.
const ecosystems = "testdata/ecosystems"

// TestSealedScenarios scans every scenario under testdata/ecosystems in a container with no
// network, against advisory databases generated from advisories.yaml, and holds the result to the
// scenario's expected.yaml, the fixture's inline annotations and a normalized golden report.
//
// Exact results are the point. The databases are ours, so an advisory published upstream changes
// nothing here, and the only way a finding appears or disappears is a change in Draugr or in a
// pinned tool. The missing network is the other half: a fetch nobody designed for fails the
// scenario instead of quietly reaching the internet.
func TestSealedScenarios(t *testing.T) {
	requireTool(t, "docker", "the sealed tier runs every scan in a container with no network")
	requireTool(t, "git", "each scenario is committed to a repository before it is scanned")
	for _, tool := range []string{"trivy", "semgrep", "gitleaks", "gosec", "govulncheck", "retire", "go"} {
		requireTool(t, tool, "a sealed scenario runs it")
	}
	bin := draugrBin(t)

	advs, err := sealed.LoadAdvisories(filepath.Join(ecosystems, "advisories.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	dirs, err := filepath.Glob(filepath.Join(ecosystems, "*", "expected.yaml"))
	if err != nil || len(dirs) == 0 {
		t.Fatalf("no scenarios under %s: %v", ecosystems, err)
	}
	for _, exp := range dirs {
		s, err := sealed.LoadScenario(filepath.Dir(exp))
		if err != nil {
			t.Fatal(err)
		}
		t.Run(s.Name, func(t *testing.T) { runSealed(t, s, advs, bin) })
	}
}

func runSealed(t *testing.T, s sealed.Scenario, advs sealed.Advisories, bin string) {
	work := t.TempDir()
	c, err := sealed.HostContainer(work)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	home := c.Home()
	for _, err := range []error{
		os.MkdirAll(filepath.Join(work, "bin"), 0o750),
		copyFile(bin, filepath.Join(work, "bin", "draugr"), 0o700),
		sealed.WriteTrivyDB(filepath.Join(home, ".cache", "trivy"), advs),
		sealed.WriteGoVulnDB(home, advs, now),
		sealed.WriteRetireRepo(home, advs, now),
		copyFile(filepath.Join(s.Dir, "draugr.saga.yaml"), filepath.Join(work, "draugr.saga.yaml"), 0o600),
		copyFile(filepath.Join(ecosystems, "semgrep.yaml"), filepath.Join(work, "semgrep.yaml"), 0o600),
	} {
		if err != nil {
			t.Fatal(err)
		}
	}
	repo, err := s.Prepare(work)
	if err != nil {
		t.Fatal(err)
	}
	c.Env = map[string]string{"DRAUGR_SEALED_SEMGREP_RULES": filepath.Join(work, "semgrep.yaml")}
	draugr := filepath.Join(work, "bin", "draugr")

	// init, in the repository, as somebody meeting it for the first time would run it.
	initOut := filepath.Join(work, "init.saga.yaml")
	if out, err := c.Command(repo, draugr, "init", ".", "--output", initOut, "--offline").CombinedOutput(); err != nil {
		t.Fatalf("%s: draugr init: %v\n%s", s.Name, err, out)
	}
	got, err := sealed.ObserveInit(initOut)
	if err != nil {
		t.Fatalf("%s: %v", s.Name, err)
	}
	for _, p := range sealed.CheckInit(s.Expected.Init, got) {
		t.Errorf("%s: %s", s.Name, p)
	}

	// The scan. A non-zero exit is expected, because every scenario's findings trip the gate; a
	// control that could not run is not, and is checked from the report below.
	out := filepath.Join(work, "out")
	console, err := c.Command(work, draugr, "scan", "draugr.saga.yaml", "--offline", "--output", out, "--log-level", "warn").CombinedOutput()
	t.Logf("%s: draugr scan exit=%v\n%s", s.Name, err, console)

	report := readFile(t, filepath.Join(out, "report.json"))
	var summary struct {
		Controls []struct {
			Name    string `json:"name"`
			Verdict string `json:"verdict"`
		} `json:"controls"`
	}
	if err := json.Unmarshal(report, &summary); err != nil {
		t.Fatalf("%s: report.json: %v", s.Name, err)
	}
	for _, ctl := range summary.Controls {
		if ctl.Verdict == "error" {
			t.Errorf("%s: control %s could not run sealed; the console above says why", s.Name, ctl.Name)
		}
	}

	results := readFile(t, filepath.Join(out, "results.sarif"))
	if err := sealed.ValidateSARIF(results); err != nil {
		t.Errorf("%s: results.sarif is not valid SARIF 2.1.0: %v", s.Name, err)
	}
	found, err := sealed.Observe(results)
	if err != nil {
		t.Fatal(err)
	}
	anns, err := sealed.ReadAnnotations(filepath.Join(s.Dir, "repo"))
	if err != nil {
		t.Fatal(err)
	}
	problems, err := sealed.Check(s.Expected, anns, found)
	if err != nil {
		t.Fatalf("%s: %v", s.Name, err)
	}
	for _, p := range problems {
		t.Errorf("%s: %s", s.Name, p)
	}

	replace := sealed.RunReplacements(work, now)
	compareSealedGolden(t, s, "results.sarif", results, sealed.SARIFNormalizer(replace))
	compareSealedGolden(t, s, "report.json", report, sealed.ReportNormalizer(replace))
}

// compareSealedGolden holds a normalized document to the scenario's golden copy, or rewrites the
// copy under -update-sealed.
func compareSealedGolden(t *testing.T, s sealed.Scenario, name string, raw []byte, n sealed.Normalizer) {
	t.Helper()
	got, err := n.Apply(raw)
	if err != nil {
		t.Errorf("%s: %s: %v", s.Name, name, err)
		return
	}
	path := filepath.Join(s.Dir, "golden", name)
	if *updateSealed {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path) // #nosec G304 -- the scenario's own golden file
	if err != nil {
		t.Errorf("%s: %v; run with -update-sealed to write it", s.Name, err)
		return
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s: %s differs from %s; if the change is intended, run with -update-sealed\n%s",
			s.Name, name, path, sealed.Diff(string(want), string(got)))
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path) // #nosec G304 -- a path the scan wrote into t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func copyFile(src, dst string, mode os.FileMode) error {
	b, err := os.ReadFile(src) // #nosec G304 -- the binary under test or a scenario file
	if err != nil {
		return err
	}
	return os.WriteFile(dst, b, mode) // #nosec G703 -- a path under the test's work directory
}
