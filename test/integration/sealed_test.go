//go:build integration

package integration

import (
	"bytes"
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
	opts := s.Expected.Sealed
	goVulnFetched := now
	if opts.GoVulnDBAge != "" {
		age, err := time.ParseDuration(opts.GoVulnDBAge)
		if err != nil {
			t.Fatalf("%s: sealed.goVulnDBAge: %v", s.Name, err)
		}
		goVulnFetched = now.Add(-age)
	}
	trivyDB := func() error {
		if opts.WithoutTrivyDB {
			return nil
		}
		return sealed.WriteTrivyDB(filepath.Join(home, ".cache", "trivy"), advs)
	}
	for _, err := range []error{
		os.MkdirAll(filepath.Join(work, "bin"), 0o750),
		copyFile(bin, filepath.Join(work, "bin", "draugr"), 0o700),
		os.MkdirAll(home, 0o750),
		trivyDB(),
		sealed.WriteGoVulnDB(home, advs, goVulnFetched),
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
	if opts.WithoutTool != "" {
		if err := c.Hide(opts.WithoutTool); err != nil {
			t.Fatal(err)
		}
	}
	if opts.FailingTool != "" {
		if err := c.Fail(opts.FailingTool); err != nil {
			t.Fatal(err)
		}
	}

	// init, in the repository, as somebody meeting it for the first time would run it, and again
	// with --per-directory where the scenario says what that writes.
	checkInit(t, c, draugr, s.Name, repo, filepath.Join(work, "init.saga.yaml"), s.Expected.Init)
	if pd := s.Expected.Init.PerDirectory; pd != nil {
		checkInit(t, c, draugr, s.Name+" --per-directory", repo, filepath.Join(work, "init-per-directory.saga.yaml"), *pd, "--per-directory")
	}

	// The scan. A non-zero exit is expected, because every scenario either has findings that trip
	// the gate or a control that could not run; which controls failed is checked from the report.
	out := filepath.Join(work, "out")
	console, err := c.Command(work, draugr, "scan", "draugr.saga.yaml", "--offline", "--output", out, "--log-level", "warn").CombinedOutput()
	t.Logf("%s: draugr scan exit=%v\n%s", s.Name, err, console)

	report := readFile(t, filepath.Join(out, "report.json"))
	errProblems, err := sealed.CheckErrors(s.Expected.Errors, report)
	if err != nil {
		t.Fatalf("%s: %v", s.Name, err)
	}
	for _, p := range errProblems {
		t.Errorf("%s: %s", s.Name, p)
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
	// The fetch time a stale database is refused for, which moves with the run.
	replace[goVulnFetched.UTC().Format("2006-01-02 15:04 UTC")] = "<fetched>"
	// A scenario about a failure has a control that never started, and so fields nothing wrote.
	failing := len(s.Expected.Errors) > 0
	sarifN, reportN := sealed.SARIFNormalizer(replace), sealed.ReportNormalizer(replace)
	sarifN.AllowMissing, reportN.AllowMissing = failing, failing
	compareSealedGolden(t, s, "results.sarif", results, sarifN)
	compareSealedGolden(t, s, "report.json", report, reportN)
}

// compareSealedGolden holds a normalized document to the scenario's golden copy, or rewrites the
// copy under -update-sealed.
// checkInit runs `draugr init` in repo, checks what it wrote against exp, and has `draugr validate`
// read it, so a descriptor init writes is one the next command accepts.
func checkInit(t *testing.T, c sealed.Container, draugr, name, repo, out string, exp sealed.InitExpectation, flags ...string) {
	t.Helper()
	argv := append([]string{draugr, "init", ".", "--output", out, "--offline"}, flags...)
	if o, err := c.Command(repo, argv...).CombinedOutput(); err != nil {
		t.Fatalf("%s: draugr init: %v\n%s", name, err, o)
	}
	got, err := sealed.ObserveInit(out)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	for _, p := range sealed.CheckInit(exp, got) {
		t.Errorf("%s: %s", name, p)
	}
	if o, err := c.Command(repo, draugr, "validate", out, "--offline").CombinedOutput(); err != nil {
		t.Errorf("%s: draugr validate refuses what init wrote: %v\n%s", name, err, o)
	}
}

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
