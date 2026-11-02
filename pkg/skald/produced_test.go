package skald

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// producedBy is a run in which two scanners ran, one of which could not be asked its version.
func producedBy() engine.Result {
	return engine.Result{Controls: map[string]plugin.ControlResult{
		"sca": {Control: "sca", Report: sarif.Report{
			Provenance: []sarif.Provenance{
				{Tool: "trivy-fs", Version: "trivy@0.69.3;db@2026-09-12T13:01:09Z"},
				{Tool: "retirejs"},
				// Accounts for the run rather than for a tool, and is not a scanner.
				{Tool: "draugr/scope", Fields: []sarif.Field{{Key: "controls", Value: "sca"}}},
			},
		}},
		"secrets": {Control: "secrets", Report: sarif.Report{
			Provenance: []sarif.Provenance{{Tool: "gitleaks", Version: "8.30.1"}},
		}},
	}}
}

func renderProduced(t *testing.T, run engine.Result, prov Provenance) map[string]any {
	t.Helper()
	var b bytes.Buffer
	err := RenderJSONFor(&b, "storefront", saga.Release{Version: "1.0"}, run,
		norn.Result{Verdict: norn.Pass}, "", nil, sarif.MarshalOptions{}, prov)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return doc
}

// The document names the Draugr that produced it, which release.version beside it does not:
// that one is the version of the software being scanned.
func TestTheReportNamesTheDraugrThatProducedIt(t *testing.T) {
	doc := renderProduced(t, producedBy(), Provenance{Build: &Build{Version: "0.121.1", Commit: "273db6e"}})
	got, _ := doc["draugr"].(map[string]any)
	if got == nil {
		t.Fatal("no draugr block, so two reports that disagree cannot be told apart")
	}
	if got["version"] != "0.121.1" || got["commit"] != "273db6e" {
		t.Errorf("draugr = %v", got)
	}
	if rel, _ := doc["release"].(map[string]any); rel["version"] != "1.0" {
		t.Errorf("release.version = %v, want the scanned software's own version", rel["version"])
	}
}

// A caller that did not know which Draugr it was writes none, rather than a placeholder somebody
// could later mistake for a reading.
func TestNoBuildWritesNoBlock(t *testing.T) {
	if _, ok := renderProduced(t, producedBy(), Provenance{})["draugr"]; ok {
		t.Error("a draugr block appeared with nothing behind it")
	}
}

// One entry per scanner that ran, sorted, with what decides its answers. A tool that could not be
// asked is listed without a version rather than left out: it ran, and that is the fact.
func TestTheReportNamesTheScannersThatRan(t *testing.T) {
	doc := renderProduced(t, producedBy(), Provenance{})
	raw, _ := doc["scanners"].([]any)
	if len(raw) != 3 {
		t.Fatalf("scanners = %v, want three", raw)
	}
	var names, versions []string
	for _, e := range raw {
		m := e.(map[string]any)
		names = append(names, m["name"].(string))
		v, _ := m["version"].(string)
		versions = append(versions, v)
	}
	if got, want := names, []string{"gitleaks", "retirejs", "trivy-fs"}; !equal(got, want) {
		t.Errorf("names = %v, want %v sorted and without the run's own entries", got, want)
	}
	if versions[1] != "" {
		t.Errorf("retirejs reported %q, want an absence rather than an invention", versions[1])
	}
	if versions[2] != "trivy@0.69.3;db@2026-09-12T13:01:09Z" {
		t.Errorf("trivy-fs version = %q, want the tool and the data behind it", versions[2])
	}
}

// repoController plans one job per repository each component lists.
type repoController struct {
	name, scanner string
	repos         map[string]string
}

func (c repoController) Info() plugin.ControllerInfo {
	return plugin.ControllerInfo{Name: c.name, Scope: plugin.ScopeComponent}
}

func (c repoController) Plan(_ saga.Model, comp *saga.Component) ([]plugin.ScanJob, error) {
	return []plugin.ScanJob{{Scanner: c.scanner, Target: plugin.RepositoryTarget{URL: c.repos[comp.Name], Revision: "main"}}}, nil
}

func (c repoController) Aggregate(reports []sarif.Report) (plugin.ControlResult, error) {
	return plugin.ControlResult{Control: c.name, Report: sarif.Merge(reports...)}, nil
}

// repoScanner fails on one repository, reads the rest, and says which build it is.
type repoScanner struct{ name, version, failOn string }

func (s repoScanner) Info() plugin.ScannerInfo            { return plugin.ScannerInfo{Name: s.name} }
func (s repoScanner) CacheVersion(context.Context) string { return s.version }

func (s repoScanner) Scan(_ context.Context, t plugin.Target, _ plugin.Config) (sarif.Report, error) {
	if r := t.(plugin.RepositoryTarget); r.URL == s.failOn {
		return sarif.Report{}, errors.New("run " + s.name + ": exit status 2: no packages matched the provided patterns")
	}
	return sarif.Report{Tool: s.name}, nil
}

// Two components in two repositories, govulncheck failing in one and reading the other: it is listed
// with its version, and the failure is recorded beside it with the component, the repository and
// the error its control carries. trivy-fs, which read both, carries no failure, and gitleaks,
// registered and never configured, is not listed at all.
func TestTheReportNamesAScannerThatFailedWhereItFailed(t *testing.T) {
	const (
		api = "https://github.com/acme/api"
		web = "https://github.com/acme/web"
	)
	repos := map[string]string{"api": api, "web": web}
	reg := engine.NewRegistry()
	reg.RegisterController(repoController{name: "sca", scanner: "trivy-fs", repos: repos})
	reg.RegisterController(repoController{name: "reach", scanner: "govulncheck", repos: repos})
	reg.RegisterScanner(repoScanner{name: "trivy-fs", version: "trivy@0.76.1"})
	reg.RegisterScanner(repoScanner{name: "govulncheck", version: "v1.1.4", failOn: web})
	reg.RegisterScanner(repoScanner{name: "gitleaks", version: "8.30.1", failOn: web})
	on := map[string]saga.ControllerSettings{"sca": {}, "reach": {}}
	run, err := engine.New(reg).Run(context.Background(), saga.Model{
		Release:    saga.Release{Version: "1"},
		Components: []saga.Component{{Name: "api", Controls: on}, {Name: "web", Controls: on}},
	})
	if err == nil {
		t.Fatal("want the run to report govulncheck's failure")
	}

	raw, _ := renderProduced(t, run, Provenance{})["scanners"].([]any)
	got, _ := json.Marshal(raw)
	failure := "run govulncheck: exit status 2: no packages matched the provided patterns"
	want, _ := json.Marshal([]any{
		map[string]any{"name": "govulncheck", "version": "v1.1.4", "failed": []any{map[string]any{
			"control": "reach", "component": "web", "kind": "repository", "target": web + "@main", "detail": failure,
		}}},
		map[string]any{"name": "trivy-fs", "version": "trivy@0.76.1"},
	})
	if string(got) != string(want) {
		t.Errorf("scanners =\n %s\nwant\n %s", got, want)
	}
	if errs := run.ScanErrors["reach"]; len(errs) != 1 || errs[0] != failure {
		t.Errorf("reach errors = %v, want the failure the scanners entry carries", errs)
	}
}

// A scanner whose every job failed is still listed, with the version it reported.
func TestAScannerThatOnlyFailedIsListed(t *testing.T) {
	run := engine.Result{FailedScans: []engine.FailedScan{
		{Scanner: "govulncheck", Version: "v1.1.4", Control: "sca", Component: "api", Detail: "boom"},
	}}
	raw, _ := renderProduced(t, run, Provenance{})["scanners"].([]any)
	if len(raw) != 1 {
		t.Fatalf("scanners = %v, want govulncheck", raw)
	}
	e := raw[0].(map[string]any)
	if e["name"] != "govulncheck" || e["version"] != "v1.1.4" {
		t.Errorf("entry = %v, want govulncheck at the version it reported", e)
	}
	if failed, _ := e["failed"].([]any); len(failed) != 1 {
		t.Errorf("failed = %v, want the one failure", e["failed"])
	}
}

// A control with a scan error fails whatever the scanners that ran found, and names them: sca, where
// trivy-fs failed and grype-fs found nothing, fails as secrets, whose every scanner failed, does. A
// clean control keeps the verdict it was judged and names no scanners, so its entry is unchanged.
func TestAControlWithAFailedScannerFails(t *testing.T) {
	run := engine.Result{
		Controls: map[string]plugin.ControlResult{
			"sca":  {Control: "sca"},
			"sast": {Control: "sast"},
		},
		ScanErrors: map[string][]string{"sca": {"run trivy-fs: boom"}, "secrets": {"run gitleaks: boom"}},
		Reported:   map[string][]string{"sca": {"grype-fs"}, "sast": {"semgrep"}},
		FailedScans: []engine.FailedScan{
			{Scanner: "gitleaks", Control: "secrets", Component: "api"},
			{Scanner: "trivy-fs", Control: "sca", Component: "api"},
		},
	}
	verdict := norn.Result{Verdict: norn.Fail, Controls: []norn.ControlOutcome{
		{Control: "sast", Verdict: norn.Pass}, {Control: "sca", Verdict: norn.Pass},
	}}
	var b bytes.Buffer
	if err := RenderJSON(&b, saga.Release{Version: "1"}, run, verdict, ""); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Controls []struct {
			Name     string   `json:"name"`
			Verdict  string   `json:"verdict"`
			Reported []string `json:"reported"`
		} `json:"controls"`
	}
	if err := json.Unmarshal(b.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	got, _ := json.Marshal(doc.Controls)
	want := `[{"name":"sast","verdict":"pass","reported":null},` +
		`{"name":"sca","verdict":"fail","reported":["grype-fs"]},` +
		`{"name":"secrets","verdict":"fail","reported":null}]`
	if string(got) != want {
		t.Errorf("controls =\n %s\nwant\n %s", got, want)
	}
}

// A run that scanned nothing lists no scanners, rather than an empty array a consumer would read
// as "asked and none ran".
func TestARunWithNoScannersListsNone(t *testing.T) {
	if _, ok := renderProduced(t, engine.Result{}, Provenance{})["scanners"]; ok {
		t.Error("a scanners key appeared for a run that used none")
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
