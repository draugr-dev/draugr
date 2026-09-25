//go:build integration

package integration

import (
	"bytes"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
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
	for _, tool := range []string{"trivy", "grype", "semgrep", "gitleaks", "gosec", "govulncheck", "retire", "nuclei", "go"} {
		requireTool(t, tool, "a sealed scenario runs it")
	}
	bin := draugrBin(t)

	// The loopback server every sealed command runs beside, built without cgo so it needs nothing
	// from the container's libraries.
	server := filepath.Join(t.TempDir(), "serve")
	build := exec.Command("go", "build", "-o", server, "../sealed/serve") // #nosec G204 -- literal arguments
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build the sealed server: %v\n%s", err, out)
	}

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
		t.Run(s.Name, func(t *testing.T) { runSealed(t, s, advs, bin, server) })
	}
}

func runSealed(t *testing.T, s sealed.Scenario, advs sealed.Advisories, bin, server string) {
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
	served := filepath.Join(work, "served")
	for _, err := range []error{
		os.MkdirAll(filepath.Join(work, "bin"), 0o750),
		copyFile(bin, filepath.Join(work, "bin", "draugr"), 0o700),
		copyFile(server, filepath.Join(work, "bin", "serve"), 0o700),
		os.MkdirAll(home, 0o750),
		trivyDB(),
		sealed.WriteGrypeDB(home, advs, now),
		sealed.WriteGoVulnDB(home, advs, goVulnFetched),
		sealed.WriteRetireRepo(home, advs, now),
		copyFile(filepath.Join(s.Dir, "draugr.saga.yaml"), filepath.Join(work, "draugr.saga.yaml"), 0o600),
		copyFile(filepath.Join(ecosystems, "semgrep.yaml"), filepath.Join(work, "semgrep.yaml"), 0o600),
		s.CopyWorkdir(work),
		// The rules again, where Semgrep fetches its default pack from, so a descriptor naming no
		// rules, which is what init writes, runs the same ones.
		os.MkdirAll(filepath.Join(served, "c", "p"), 0o750),
		copyFile(filepath.Join(ecosystems, "semgrep.yaml"), filepath.Join(served, "c", "p", "default"), 0o600),
		s.CopyIfPresent("served", served),
		s.CopyIfPresent("home", home),
		s.ServeImage(served),
	} {
		if err != nil {
			t.Fatal(err)
		}
	}
	repo, err := s.Prepare(work)
	if err != nil {
		t.Fatal(err)
	}
	c.Server, c.Served, c.RequestLog = filepath.Join(work, "bin", "serve"), served, filepath.Join(work, "requests.log")
	c.Env = map[string]string{
		"DRAUGR_SEALED_SEMGREP_RULES": filepath.Join(work, "semgrep.yaml"),
		"SEMGREP_URL":                 sealed.ServedURL,
	}
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

	// The scan. Its exit status is not asserted: most scenarios have findings that trip the gate or
	// a control that could not run, and which controls failed is checked from the report.
	out := filepath.Join(work, "out")
	scan := append([]string{draugr, "scan", "draugr.saga.yaml", "--output", out}, opts.ScanFlags()...)
	console, err := c.Command(work, scan...).CombinedOutput()
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
	requests, _ := os.ReadFile(c.RequestLog) // #nosec G304 -- under the test's work directory
	for _, p := range sealed.CheckRequests(s.Expected.Requests, s.Expected.NeverRequested, requests) {
		t.Errorf("%s: %s", s.Name, p)
	}

	replace := sealed.RunReplacements(work, now)
	// The fetch time a stale database is refused for, which moves with the run.
	replace[goVulnFetched.UTC().Format("2006-01-02 15:04 UTC")] = "<fetched>"
	// The fixture's commits, which hold generated secrets and so differ on every run.
	commits, err := sealed.Commits(repo)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range commits {
		replace[c] = "<commit>"
	}
	sarifN, reportN := sealed.SARIFNormalizer(replace), sealed.ReportNormalizer(replace)
	missing := s.Expected.LeavesFieldsUnwritten()
	sarifN.AllowMissing, reportN.AllowMissing = missing, missing
	compareSealedGolden(t, s, "results.sarif", results, sarifN)
	compareSealedGolden(t, s, "report.json", report, reportN)

	scanWithInit(t, c, draugr, s, repo, anns)
}

// scanWithInit scans with the descriptor init wrote, from the repository, which is where init's
// own closing hint runs it and where the descriptor's `url: .` resolves.
func scanWithInit(t *testing.T, c sealed.Container, draugr string, s sealed.Scenario, repo string, anns []sealed.Annotation) {
	t.Helper()
	out := filepath.Join(c.Work, "out-init")
	scan := append([]string{draugr, "scan", filepath.Join(c.Work, "init.saga.yaml"), "--output", out}, s.Expected.Sealed.ScanFlags()...)
	console, err := c.Command(repo, scan...).CombinedOutput()
	t.Logf("%s: draugr scan with init's descriptor exit=%v\n%s", s.Name, err, console)

	exp, err := s.Expected.ForInitScan()
	if err != nil {
		t.Fatalf("%s: %v", s.Name, err)
	}
	// init names no rules for Semgrep, so it fetches its default pack, and a sast result in this
	// scan is one from the sealed rules only if that fetch reached the loopback server.
	if slices.Contains(s.Expected.Init.Controls, "sast") && s.Expected.Sealed.WithoutTool != "semgrep" {
		if log, _ := os.ReadFile(c.RequestLog); !strings.Contains(string(log), "GET /c/p/default\n") { // #nosec G304 -- under the test's work directory
			t.Errorf("%s: Semgrep never asked the sealed server for its default rules:\n%s", s.Name, log)
		}
	}
	errProblems, err := sealed.CheckErrors(exp.Errors, readFile(t, filepath.Join(out, "report.json")))
	if err != nil {
		t.Fatalf("%s, init's descriptor: %v", s.Name, err)
	}
	for _, p := range errProblems {
		t.Errorf("%s, init's descriptor: %s", s.Name, p)
	}
	found, err := sealed.Observe(readFile(t, filepath.Join(out, "results.sarif")))
	if err != nil {
		t.Fatal(err)
	}
	problems, err := sealed.Check(exp, anns, found)
	if err != nil {
		t.Fatalf("%s, init's descriptor: %v", s.Name, err)
	}
	for _, p := range problems {
		t.Errorf("%s, init's descriptor: %s", s.Name, p)
	}
}

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
