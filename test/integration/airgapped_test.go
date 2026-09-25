//go:build integration

package integration

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/draugr-dev/draugr/test/sealed"
)

// airGappedEnv turns the air-gapped run on. Preparing its home downloads every scanner's real
// database, several gigabytes, so it runs where it is asked for.
const airGappedEnv = "DRAUGR_AIRGAPPED"

// offlineNotice is the line a scan prints when it has been told there is no network.
const offlineNotice = "offline: not refreshing scanner data, using what is on disk"

// TestAirGapped holds Draugr to docs/guides/air-gapped.md. A home is prepared once, with the
// network, the way the guide says to prepare a runner; then every scenario in the corpus is scanned
// with --offline in a container with no network, from a copy of that home. A scenario that scans
// what the sealed server answers for is left to the sealed tier, since nothing answers here.
//
// The sealed tier proves offline against databases generated for it, laid out where the harness
// knows to put them. This proves the guide: that the commands it lists leave each scanner's real
// data where the scan looks for it, and that nothing a scan does needs a route out. Each scanner
// either works from what was prepared or the control reports that it could not, which is checked
// from the report; a finding the scenario expects has to be there, matched on what a real database
// cannot move; and every Trivy vulnerability scan carries --offline-scan, the flag that stops it
// resolving a pom.xml's dependencies against Maven Central.
func TestAirGapped(t *testing.T) {
	if os.Getenv(airGappedEnv) == "" {
		t.Skipf("set %s=1 to prepare a home as docs/guides/air-gapped.md describes and scan the corpus offline from it", airGappedEnv)
	}
	requireTool(t, "docker", "every scan runs in a container with no network")
	requireTool(t, "git", "each scenario is committed to a repository before it is scanned")
	for _, tool := range []string{"trivy", "semgrep", "gitleaks", "gosec", "govulncheck", "retire", "go"} {
		requireTool(t, tool, "a scenario runs it")
	}
	bin := draugrBin(t)

	dirs, err := filepath.Glob(filepath.Join(ecosystems, "*", "expected.yaml"))
	if err != nil || len(dirs) == 0 {
		t.Fatalf("no scenarios under %s: %v", ecosystems, err)
	}
	var scenarios []sealed.Scenario
	for _, exp := range dirs {
		s, err := sealed.LoadScenario(filepath.Dir(exp))
		if err != nil {
			t.Fatal(err)
		}
		scenarios = append(scenarios, s)
	}

	// One directory for the prepared home and every scenario's work, so each scenario's home can
	// be hard links into the prepared one rather than a copy of it.
	root := t.TempDir()
	prepared := filepath.Join(root, "prepared")
	prepareAirGappedHome(t, bin, prepared)

	for _, s := range scenarios {
		if servedBySealed(s) {
			continue
		}
		t.Run(s.Name, func(t *testing.T) {
			work := filepath.Join(root, "scenarios", s.Name)
			runAirGapped(t, s, bin, prepared, work, "draugr.saga.yaml", s.Expected)
		})
	}

	// The one scanner the guide says cannot run offline, with the configuration it would fetch.
	// The control has to say it could not run; a sast control that passes here passed on nothing.
	t.Run("semgrep-registry", func(t *testing.T) {
		var base sealed.Scenario
		for _, s := range scenarios {
			if s.Name == "js-npm" {
				base = s
			}
		}
		if base.Name == "" {
			t.Fatal("the js-npm scenario this run borrows a repository from is gone")
		}
		work := filepath.Join(root, "semgrep-registry")
		if err := os.MkdirAll(work, 0o750); err != nil {
			t.Fatal(err)
		}
		descriptor := "project: semgrep-registry\nrelease:\n  version: \"1.0\"\nconfig:\n  controls:\n" +
			"    sast:\n      enabled: true\ncomponents:\n  - name: js-npm\n    repositories:\n      - url: ./js-npm\n"
		if err := os.WriteFile(filepath.Join(work, "registry.saga.yaml"), []byte(descriptor), 0o600); err != nil {
			t.Fatal(err)
		}
		exp := sealed.Expected{Errors: []sealed.ErrorExpectation{{Control: "sast"}}}
		runAirGapped(t, base, bin, prepared, work, "registry.saga.yaml", exp)
	})
}

// prepareAirGappedHome runs the preparation docs/guides/air-gapped.md lists, with HOME at home and
// every variable that would move a cache elsewhere unset, so what the scans later find is what the
// guide's commands left behind.
//
// The guide's first step, `draugr tools install --all`, is the one not repeated here: the binaries
// are the ones already installed on the host and reached through PATH, inside the container as
// well as out. What that step leaves in the home, ~/.draugr/data, is created instead, because
// retire.js creates only the last directory of its --cachedir.
func prepareAirGappedHome(t *testing.T, bin, home string) {
	t.Helper()
	empty := filepath.Join(home, "empty")
	for _, dir := range []string{empty, filepath.Join(home, ".draugr", "data")} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	steps := [][]string{
		{bin, "feeds", "update"},
		{"trivy", "image", "--download-db-only"},
		{"retire", "--path", empty, "--cachedir", filepath.Join(home, ".draugr", "data", "retirejs")},
	}
	if corpusNames(t, "grype") {
		requireTool(t, "grype", "a scenario in the corpus runs it")
		steps = append(steps, []string{"grype", "db", "update"})
	}
	env := []string{"HOME=" + home}
	for _, kv := range os.Environ() {
		switch strings.SplitN(kv, "=", 2)[0] {
		case "HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME", "TRIVY_CACHE_DIR", "GRYPE_DB_CACHE_DIR":
			continue
		}
		env = append(env, kv)
	}
	for _, argv := range steps {
		cmd := exec.Command(argv[0], argv[1:]...) // #nosec G204 -- the guide's own commands
		cmd.Dir = home
		cmd.Env = env
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("preparing the home as the guide says: %s: %v\n%s", strings.Join(argv, " "), err, out)
		}
	}
	if err := os.Remove(empty); err != nil {
		t.Fatal(err)
	}
}

// corpusNames reports whether any scenario's descriptor mentions word.
func corpusNames(t *testing.T, word string) bool {
	t.Helper()
	descriptors, err := filepath.Glob(filepath.Join(ecosystems, "*", "draugr.saga.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range descriptors {
		if bytes.Contains(readFile(t, d), []byte(word)) {
			return true
		}
	}
	return false
}

func runAirGapped(t *testing.T, s sealed.Scenario, bin, prepared, work, descriptor string, exp sealed.Expected) {
	t.Helper()
	c, err := sealed.HostContainer(work)
	if err != nil {
		t.Fatal(err)
	}
	opts := s.Expected.Sealed
	for _, err := range []error{
		os.MkdirAll(filepath.Join(work, "bin"), 0o750),
		copyFile(bin, filepath.Join(work, "bin", "draugr"), 0o700),
		sealed.LinkTree(prepared, c.Home()),
		opts.TakeAway(c.Home(), time.Now()),
		copyFile(filepath.Join(ecosystems, "semgrep.yaml"), filepath.Join(work, "semgrep.yaml"), 0o600),
		s.CopyWorkdir(work),
	} {
		if err != nil {
			t.Fatal(err)
		}
	}
	if descriptor == "draugr.saga.yaml" {
		if err := copyFile(filepath.Join(s.Dir, descriptor), filepath.Join(work, descriptor), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Prepare(work); err != nil {
		t.Fatal(err)
	}
	c.Env = map[string]string{"DRAUGR_SEALED_SEMGREP_RULES": filepath.Join(work, "semgrep.yaml")}
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

	out, trace := filepath.Join(work, "out"), filepath.Join(work, "trace.log")
	console, err := c.Command(work, filepath.Join(work, "bin", "draugr"), "scan", descriptor,
		"--offline", "--output", out, "--log-file", trace).CombinedOutput()
	t.Logf("%s: draugr scan exit=%v\n%s", s.Name, err, console)

	if !bytes.Contains(console, []byte(offlineNotice)) {
		t.Errorf("%s: the scan did not say it was offline (%q)", s.Name, offlineNotice)
	}
	problems, err := sealed.CheckErrors(exp.Errors, readFile(t, filepath.Join(out, "report.json")))
	if err != nil {
		t.Fatalf("%s: %v", s.Name, err)
	}
	for _, p := range problems {
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
	if descriptor != "draugr.saga.yaml" {
		anns = nil // a borrowed repository's annotations belong to the scenario's own descriptor
	}
	missing, err := sealed.CheckPresent(exp, anns, found)
	if err != nil {
		t.Fatalf("%s: %v", s.Name, err)
	}
	for _, p := range missing {
		t.Errorf("%s: %s", s.Name, p)
	}

	unguarded, ran := sealed.TrivyRanOffline(readFile(t, trace))
	for _, argv := range unguarded {
		t.Errorf("%s: Trivy scanned without --offline-scan, so it may resolve dependencies against a registry: %s", s.Name, argv)
	}
	if expectsTrivy(exp) && ran == 0 {
		t.Errorf("%s: the scenario expects Trivy findings and the log records no Trivy vulnerability scan, so --offline-scan was checked on nothing", s.Name)
	}
}

// expectsTrivy reports whether a scenario expects a finding from Trivy's vulnerability scan.
func expectsTrivy(exp sealed.Expected) bool {
	for _, f := range exp.Findings {
		if f.Tool == "trivy" && f.Package != "" {
			return true
		}
	}
	return false
}
