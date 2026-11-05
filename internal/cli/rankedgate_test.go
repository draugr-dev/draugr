package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/draugr-dev/draugr/internal/feeds"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// namedRepoController plans one job per repository for the control it is named as, on the scanner
// of the same name.
type namedRepoController struct{ name string }

func (c namedRepoController) Info() plugin.ControllerInfo {
	return plugin.ControllerInfo{Name: c.name, Scope: plugin.ScopeComponent}
}

func (c namedRepoController) Plan(_ saga.Model, comp *saga.Component) ([]plugin.ScanJob, error) {
	if comp == nil {
		return nil, nil
	}
	var jobs []plugin.ScanJob
	for _, r := range comp.Repositories {
		jobs = append(jobs, plugin.ScanJob{Scanner: c.name + "-scanner", Target: plugin.RepositoryTarget{URL: r.URL}})
	}
	return jobs, nil
}

func (c namedRepoController) Aggregate(reports []sarif.Report) (plugin.ControlResult, error) {
	m := sarif.Merge(reports...)
	n := m.Counts()
	return plugin.ControlResult{Control: c.name, Report: m,
		Summary: plugin.Summary{Errors: n.Error, Warnings: n.Warning, Notes: n.Note}}, nil
}

// perRepoScanner reports, for each repository, the findings the test put there.
type perRepoScanner struct {
	name     string
	findings map[string][]sarif.Result
}

func (s *perRepoScanner) Info() plugin.ScannerInfo { return plugin.ScannerInfo{Name: s.name} }

func (s *perRepoScanner) Scan(_ context.Context, target plugin.Target, _ plugin.Config) (sarif.Report, error) {
	url := target.(plugin.RepositoryTarget).URL
	out := make([]sarif.Result, 0, len(s.findings[url]))
	for _, f := range s.findings[url] {
		f.Tool, f.Repository = s.name, url
		out = append(out, f)
	}
	return sarif.Report{Tool: s.name, Results: out}, nil
}

// rankedGateRun is two components on two repositories with KEV loaded from the cache. api's
// repository holds a CVE scored high that KEV lists; web's holds a CVE scored high that it does
// not, and a secret its scanner rated medium. A severity gate set at critical fails only on the
// first, and one set at high fails on all three.
func rankedGateRun(t *testing.T) (string, *engine.Registry, *perRepoScanner) {
	t.Helper()
	dir := cacheHome(t)
	seed(t, dir, feeds.KEV, kevJSON, time.Hour)
	sca := &perRepoScanner{name: "sca-scanner", findings: map[string][]sarif.Result{
		apiRepo: {{RuleID: "CVE-2021-44228", Level: sarif.LevelError, Score: 7.5, HasScore: true,
			Message: "log4j", Location: sarif.Location{URI: "pom.xml", StartLine: 1}}},
		webRepo: {{RuleID: "CVE-2099-0001", Level: sarif.LevelError, Score: 7.5, HasScore: true,
			Message: "a flaw", Location: sarif.Location{URI: "go.mod", StartLine: 1}}},
	}}
	secrets := &perRepoScanner{name: "secrets-scanner", findings: map[string][]sarif.Result{
		webRepo: {{RuleID: "generic-api-key", Level: sarif.LevelWarning,
			Message: "a credential", Location: sarif.Location{URI: "config.env", StartLine: 1}}},
	}}
	reg := engine.NewRegistry()
	reg.RegisterController(namedRepoController{name: "sca"})
	reg.RegisterController(namedRepoController{name: "secrets"})
	reg.RegisterScanner(sca)
	reg.RegisterScanner(secrets)
	path := writeSaga(t, `
project: shop
release:
  version: "1.0"
config:
  controls:
    sca:
      enabled: true
    secrets:
      enabled: true
  exploitability:
    kev: cache
components:
  - name: api
    repositories:
      - url: `+apiRepo+`
  - name: web
    repositories:
      - url: `+webRepo+`
`)
	return path, reg, sca
}

// controlsOf reads each control's verdict and highest severity from the report.json in dir.
func controlsOf(t *testing.T, dir string) map[string][2]string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "report.json")) // #nosec G304 -- this test's own temp file
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Controls []struct{ Name, Verdict, Highest string }
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	out := map[string][2]string{}
	for _, c := range doc.Controls {
		out[c.Name] = [2]string{c.Verdict, c.Highest}
	}
	return out
}

// A severity gate reads the severity the report prints: KEV raises the high it lists past
// --fail-on critical, and the secrets floor holds a medium at high, through a real scan of two
// repositories with the run's own prioritizer.
func TestASeverityGateReadsWhatTheScanRanked(t *testing.T) {
	path, reg, _ := rankedGateRun(t)

	critical := t.TempDir()
	err := runScan(context.Background(), path,
		scanOptions{outputDir: critical, noPublish: true, failOn: "critical", setFlags: map[string]bool{}}, reg, &bytes.Buffer{})
	if err == nil {
		t.Fatal("--fail-on critical passed a high that KEV lists, which the report prints critical")
	}
	if got := controlsOf(t, critical); got["sca"] != [2]string{"fail", "critical"} || got["secrets"] != [2]string{"pass", "high"} {
		t.Errorf("controls = %v, want sca failing on critical and secrets passing at high", got)
	}

	high := t.TempDir()
	if err := runScan(context.Background(), path,
		scanOptions{outputDir: high, noPublish: true, failOn: "high", setFlags: map[string]bool{}}, reg, &bytes.Buffer{}); err == nil {
		t.Fatal("--fail-on high passed")
	}
	if got := controlsOf(t, high); got["secrets"] != [2]string{"fail", "high"} {
		t.Errorf("secrets = %v, want the medium the floor holds at high to fail --fail-on high", got["secrets"])
	}

	// The floor is on the finding in results.sarif, where a later diff reads it.
	data, err := os.ReadFile(filepath.Join(high, "results.sarif")) // #nosec G304 -- this test's own temp file
	if err != nil {
		t.Fatal(err)
	}
	read, err := sarif.FromSARIF(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, res := range read.Results {
		want := sarif.Severity("")
		if res.RuleID == "generic-api-key" {
			want = sarif.SeverityHigh
		}
		if res.SeverityFloor != want {
			t.Errorf("%s: severityFloor %q in results.sarif, want %q", res.RuleID, res.SeverityFloor, want)
		}
	}
}

// --fail-on-new critical judges a new finding as the scan's own gate does: the high KEV lists,
// introduced in api's repository, fails it, and the unlisted high already in web's does not count.
func TestTheGateOnNewFindingsReadsWhatTheScanRanked(t *testing.T) {
	path, reg, sca := rankedGateRun(t)
	listed := sca.findings[apiRepo]
	delete(sca.findings, apiRepo)
	baseDir := t.TempDir()
	if err := runScan(context.Background(), path,
		scanOptions{outputDir: baseDir, noPublish: true, noGate: true}, reg, &bytes.Buffer{}); err != nil {
		t.Fatalf("base scan: %v", err)
	}
	base := filepath.Join(baseDir, "results.sarif")

	// Nothing new: the base and the head are the same scan.
	if err := runScan(context.Background(), path,
		scanOptions{outputDir: t.TempDir(), noPublish: true, base: base, failOnNew: "critical"}, reg, &bytes.Buffer{}); err != nil {
		t.Fatalf("no new finding, and the gate on new findings failed: %v", err)
	}

	sca.findings[apiRepo] = listed
	err := runScan(context.Background(), path,
		scanOptions{outputDir: t.TempDir(), noPublish: true, base: base, failOnNew: "critical"}, reg, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "1 new finding") {
		t.Fatalf("err = %v, want the new KEV-listed high to fail --fail-on-new critical", err)
	}
}
