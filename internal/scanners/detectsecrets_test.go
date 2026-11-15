package scanners

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/controllers"
	"github.com/draugr-dev/draugr/internal/git"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// detectSecretsBaseline is a baseline as detect-secrets writes it: line 8 records a hash. Line 2
// holds a value of the same shape that is not in a hashed_secret field.
//
// #nosec G101 -- a made-up digest in the shape detect-secrets writes, the case under test
const detectSecretsBaseline = `{
  "version": "0123456789abcdef0123456789abcdef01234567",
  "results": {
    "config.py": [
      {
        "type": "Secret Keyword",
        "filename": "config.py",
        "hashed_secret": "8ea3c3d7ab42d2f1b4d0d1c0b4b2e7b5e5f0a1c2",
        "line_number": 1
      }
    ]
  }
}
`

// runDetectSecretsBaselines scans two components, api and web, each on its own repository, with the
// real secrets control and Gitleaks replaying a report. Each repository's baseline has a
// generic-api-key finding on its hash and on its version line, and an aws-access-token finding on
// the hash. api also holds the hash line in another JSON file, with the same finding.
func runDetectSecretsBaselines(t *testing.T, secrets saga.ControllerSettings, components map[string]saga.ControllerSettings) engine.Result {
	t.Helper()
	dirs := map[string]string{}
	for _, repo := range []string{"api", "web"} {
		files := map[string]string{"deploy/.secrets.baseline": detectSecretsBaseline}
		if repo == "api" {
			files["fixtures/baseline-copy.json"] = detectSecretsBaseline
		}
		dirs[repo] = writeTree(t, files)
	}
	s := NewGitleaks().(repoScanner)
	s.cacheVersion = nil
	s.checkout = func(_ context.Context, url, _ string, _ git.Scope) (git.Tree, func(), error) {
		return git.Tree{Dir: dirs[url]}, func() {}, nil
	}
	s.run = func(_ context.Context, dir string, argv []string) ([]byte, error) {
		out := `{"runs":[{"tool":{"driver":{"name":"gitleaks"}},"results":[]}]}`
		if argv[1] != "git" {
			leaks := []leak{
				{"generic-api-key", filepath.Join(dir, "deploy/.secrets.baseline"), 8, "8ea3c3d7ab42d2f1b4d0d1c0b4b2e7b5e5f0a1c2"},
				{"generic-api-key", filepath.Join(dir, "deploy/.secrets.baseline"), 2, "0123456789abcdef0123456789abcdef01234567"},
				{"aws-access-token", filepath.Join(dir, "deploy/.secrets.baseline"), 8, "8ea3c3d7ab42d2f1b4d0d1c0b4b2e7b5e5f0a1c2"},
			}
			if _, err := os.Stat(filepath.Join(dir, "fixtures")); err == nil {
				leaks = append(leaks, leak{"generic-api-key", filepath.Join(dir, "fixtures/baseline-copy.json"), 8, "8ea3c3d7ab42d2f1b4d0d1c0b4b2e7b5e5f0a1c2"})
			}
			out = gitleaksReport(leaks...)
		}
		path := argv[slices.Index(argv, "--report-path")+1]
		return nil, os.WriteFile(path, []byte(out), 0o600)
	}
	s.runLogged = gitleaksTree(withoutLog(s.run), gitleaksVersion(""))

	reg := engine.NewRegistry()
	reg.RegisterController(controllers.NewSecrets())
	reg.RegisterScanner(s)
	project := saga.ControllerSettings{"enabled": true}
	for k, v := range secrets {
		project[k] = v
	}
	model := saga.Model{Config: saga.Config{Controls: map[string]saga.ControllerSettings{"secrets": project}}}
	for _, name := range []string{"api", "web"} {
		comp := saga.Component{Name: name, Repositories: []saga.Repository{{URL: name}}}
		if c, ok := components[name]; ok {
			comp.Controls = map[string]saga.ControllerSettings{"secrets": c}
		}
		model.Components = append(model.Components, comp)
	}
	res, err := engine.New(reg).Run(context.Background(), model)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// baselineFindings are a run's secrets findings as "<component> <rule> <path>:<line>", split into
// the counted ones, sorted, and the ones set aside with their suppressions.
func baselineFindings(res engine.Result) (counted []string, setAside map[string]sarif.Suppression) {
	setAside = map[string]sarif.Suppression{}
	for _, r := range res.Controls["secrets"].Report.Results {
		id := r.Component + " " + r.RuleID + " " + r.Location.URI + ":" + strconv.Itoa(r.Location.StartLine)
		if r.Suppressed() {
			setAside[id] = *r.Suppression
			continue
		}
		counted = append(counted, id)
	}
	slices.Sort(counted)
	return counted, setAside
}

// By default, a generic-api-key finding on a hash a detect-secrets baseline records stays in the
// report, suppressed by the setting with its reason, in each component. The same line in another
// file, another rule on the hash, and generic-api-key on another line of the baseline still count.
func TestDetectSecretsBaselineHashesAreSuppressedByDefault(t *testing.T) {
	res := runDetectSecretsBaselines(t, nil, nil)
	counted, setAside := baselineFindings(res)
	want := []string{
		"api aws-access-token deploy/.secrets.baseline:8",
		"api generic-api-key deploy/.secrets.baseline:2",
		"api generic-api-key fixtures/baseline-copy.json:8",
		"web aws-access-token deploy/.secrets.baseline:8",
		"web generic-api-key deploy/.secrets.baseline:2",
	}
	if strings.Join(counted, "\n") != strings.Join(want, "\n") {
		t.Errorf("counted\n%s\nwant\n%s", strings.Join(counted, "\n"), strings.Join(want, "\n"))
	}
	for _, id := range []string{"api generic-api-key deploy/.secrets.baseline:8", "web generic-api-key deploy/.secrets.baseline:8"} {
		s, ok := setAside[id]
		if !ok || s.Origin != sarif.OriginSetting || s.Justification != sarif.JustificationDetectSecretsBaseline ||
			s.Source != "config.controls.secrets.detectSecretsBaselines" {
			t.Errorf("%s: suppression %+v, want the setting config.controls.secrets.detectSecretsBaselines", id, s)
		}
	}
	if len(setAside) != 2 || res.DetectSecretsBaselines != 2 {
		t.Errorf("set aside %d, counted %d by the engine, want 2 and 2", len(setAside), res.DetectSecretsBaselines)
	}
}

// A component's report counts its hashes, and the other component keeps the project's default.
func TestAComponentsDetectSecretsBaselinesReplacesTheProjects(t *testing.T) {
	res := runDetectSecretsBaselines(t, nil, map[string]saga.ControllerSettings{"web": {"detectSecretsBaselines": "report"}})
	counted, setAside := baselineFindings(res)
	if !slices.Contains(counted, "web generic-api-key deploy/.secrets.baseline:8") {
		t.Errorf("web reports its baseline hashes and its hash was not counted: %v", counted)
	}
	if _, ok := setAside["api generic-api-key deploy/.secrets.baseline:8"]; !ok || len(setAside) != 1 {
		t.Errorf("set aside %v, want only api's hash", setAside)
	}
	for _, r := range res.Controls["secrets"].Report.Results {
		if r.Component == "web" && r.Location.URI == "deploy/.secrets.baseline" && r.Location.StartLine == 8 &&
			r.RuleID == "generic-api-key" && !r.DetectSecretsBaseline {
			t.Error("a counted hash lost its mark")
		}
	}
	res = runDetectSecretsBaselines(t, saga.ControllerSettings{"detectSecretsBaselines": "report"},
		map[string]saga.ControllerSettings{"web": {"detectSecretsBaselines": "suppress"}})
	if _, setAside := baselineFindings(res); setAside["web generic-api-key deploy/.secrets.baseline:8"].Source !=
		`components["web"].controls.secrets.detectSecretsBaselines` || len(setAside) != 1 {
		t.Errorf("set aside %v, want web's hash under its component's key", setAside)
	}
}

// A finding from history, or in a file that cannot be read, is not marked.
func TestMarkDetectSecretsBaselinesLeavesWhatItCannotRead(t *testing.T) {
	dir := writeTree(t, map[string]string{".secrets.baseline": detectSecretsBaseline})
	results := []sarif.Result{
		{Tool: "gitleaks", RuleID: "generic-api-key", Location: sarif.Location{URI: ".secrets.baseline", StartLine: 8}, Historical: true},
		{Tool: "gitleaks", RuleID: "generic-api-key", Location: sarif.Location{URI: "gone/.secrets.baseline", StartLine: 8}},
		{Tool: "gitleaks", RuleID: "generic-api-key", Location: sarif.Location{URI: ".secrets.baseline", StartLine: 99}},
		{Tool: "gitleaks", RuleID: "generic-api-key", Location: sarif.Location{URI: ".secrets.baseline", StartLine: 8}},
	}
	markDetectSecretsBaselines(results, dir)
	for i, want := range []bool{false, false, false, true} {
		if results[i].DetectSecretsBaseline != want {
			t.Errorf("result %d marked %v, want %v", i, results[i].DetectSecretsBaseline, want)
		}
	}
}
