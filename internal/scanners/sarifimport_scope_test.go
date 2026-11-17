package scanners

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/controllers"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/report"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// foundAt is a result of rule at uri, or with no location where uri is empty.
func foundAt(rule, uri string) string {
	if uri == "" {
		return `{"ruleId":"` + rule + `","message":{"text":"m"}}`
	}
	return `{"ruleId":"` + rule + `","message":{"text":"m"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"` + uri + `"}}}]}`
}

// monorepoLog is one file a tool wrote for a whole monorepo: a finding in each service, one in a
// vendored tree under the web service, and one in a directory neither service declares.
var monorepoLog = exampleLog(strings.Join([]string{
	foundAt("EX2", "services/api/handler.py"),
	foundAt("EX2", "services/web/app.py"),
	foundAt("EX2", "services/web/vendor/lib.py"),
	foundAt("EX2", "tools/gen.py"),
}, ","), "")

// importedPaths is each component's imported findings in control, by path.
func importedPaths(res engine.Result, control string) map[string][]string {
	out := map[string][]string{}
	for _, r := range res.Controls[control].Report.Results {
		if r.Scanner == plugin.ImportScanner {
			out[r.Component] = append(out[r.Component], r.Location.URI)
		}
	}
	for comp := range out {
		slices.Sort(out[comp])
	}
	return out
}

// One file imported by two components of one repository, each declaring its own subtree, splits by
// their paths as a native scan of the repository would: each keeps its own service's finding, and
// the run says how many it left out and why, on the console and in report.json.
func TestAnImportIntoTwoComponentsSplitsByTheirPaths(t *testing.T) {
	semgrep, config := replayingSemgrep(t)
	reg := engine.NewRegistry()
	reg.RegisterController(controllers.NewSAST())
	reg.RegisterScanner(semgrep)
	reg.RegisterScanner(NewSARIFImport())
	repo := t.TempDir()
	file := writeFile(t, monorepoLog)
	imports := []saga.Import{{Control: "sast", File: file}}
	model := saga.Model{
		Config: saga.Config{Controls: map[string]saga.ControllerSettings{
			"sast": {"enabled": true, "semgrep": map[string]any{"config": config}},
		}},
		Components: []saga.Component{
			{Name: "api", Imports: imports, Repositories: []saga.Repository{{URL: repo, Paths: []string{"services/api"}}}},
			{Name: "web", Imports: imports, Repositories: []saga.Repository{
				{URL: repo, Paths: []string{"services/web"}, Ignore: []string{"services/web/vendor/"}},
			}},
		},
	}
	res, err := engine.New(reg).Run(context.Background(), model)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.ScanErrors) > 0 {
		t.Fatalf("errors: %v", res.ScanErrors)
	}
	want := map[string][]string{"api": {"services/api/handler.py"}, "web": {"services/web/app.py"}}
	if got := importedPaths(res, "sast"); !reflect.DeepEqual(got, want) {
		t.Errorf("imported findings = %v, want %v", got, want)
	}

	// The verdict draws the controls block, which the account of each file is printed under.
	verdict := norn.Policy{}.Evaluate(map[string]sarif.Report{"sast": res.Controls["sast"].Report})
	d := report.Data{Project: "p", Run: res, Verdict: verdict}
	// The console wraps the account to the terminal, so it is read with its line breaks folded.
	console := strings.Join(strings.Fields(renderFormat(t, "console", d)), " ")
	for _, said := range []string{
		"component: api · left out: 3 findings outside paths, not counted",
		"component: web · left out: 2 findings outside paths, 1 matched by ignore, not counted",
	} {
		if !strings.Contains(console, said) {
			t.Errorf("the console does not say %q:\n%s", said, console)
		}
	}
	var doc struct {
		ScopedImports []map[string]any `json:"scopedImports"`
	}
	if err := json.Unmarshal([]byte(renderFormat(t, "json", d)), &doc); err != nil {
		t.Fatal(err)
	}
	wantDoc := []map[string]any{
		{"component": "api", "file": file, "controls": []any{"sast"}, "outsidePaths": 3.0},
		{"component": "web", "file": file, "controls": []any{"sast"}, "outsidePaths": 2.0, "ignored": 1.0},
	}
	if !reflect.DeepEqual(doc.ScopedImports, wantDoc) {
		t.Errorf("scopedImports = %v, want %v", doc.ScopedImports, wantDoc)
	}
}

// A component of two repositories, each scoped to its own subtree. Where the file names one of them,
// that repository's paths decide, and the other's do not: a finding under the service's paths is
// still outside the tools repository the file is about. Where the file names neither, which paths
// apply is unknown, so every finding stays and the run counts them as not scoped.
func TestAnImportIsScopedByTheRepositoryItIsPlacedIn(t *testing.T) {
	root := t.TempDir()
	service, tools := filepath.Join(root, "service"), filepath.Join(root, "tools")
	for _, dir := range []string{service, tools} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	repos := []plugin.RepositoryTarget{{URL: service, Paths: []string{"app"}}, {URL: tools, Paths: []string{"cmd"}}}
	results := strings.Join([]string{foundAt("EX2", "app/x.py"), foundAt("EX2", "cmd/y.go"), foundAt("EX2", "docs/z.md")}, ",")
	for _, c := range []struct {
		name, extra string
		want        []string
		said        map[string]string
		detail      []sarif.Field
	}{
		{
			name:   "the file names the tools repository",
			extra:  `"versionControlProvenance":[{"repositoryUri":"https://example.com/acme/tools.git"}],`,
			want:   []string{"cmd/y.go"},
			said:   map[string]string{"left out": "2 findings outside paths, not counted"},
			detail: []sarif.Field{{Key: sarif.ImportOutsidePaths, Value: "2"}},
		},
		{
			name: "the file names neither",
			want: []string{"app/x.py", "cmd/y.go", "docs/z.md"},
			said: map[string]string{
				"not scoped": "3 findings, not in any one repository, so paths and ignore were not applied. Add versionControlProvenance to the file",
			},
			detail: []sarif.Field{{Key: sarif.ImportNotScoped, Value: "3"}},
		},
	} {
		rep, err := NewSARIFImport().Scan(context.Background(),
			plugin.FileTarget{Path: writeFile(t, exampleLog(results, c.extra)), Component: "api", Repositories: repos}, nil)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		var got []string
		for _, r := range rep.Results {
			got = append(got, r.Location.URI)
		}
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: kept %v, want %v", c.name, got, c.want)
		}
		for key, want := range c.said {
			if got := field(t, rep, key); got != want {
				t.Errorf("%s: %s = %q, want %q", c.name, key, got, want)
			}
		}
		if d := rep.Provenance[0].Detail; !reflect.DeepEqual(d, c.detail) {
			t.Errorf("%s: detail = %v, want %v", c.name, d, c.detail)
		}
	}
}

// What nothing can place stays: a finding with no location, and one whose path is outside every
// checkout, which the run lists as unread. A repository listed once per subtree keeps a finding in
// any of them. The severity source describes the findings kept.
func TestAnImportKeepsWhatItCannotPlace(t *testing.T) {
	dir := t.TempDir()
	repos := []plugin.RepositoryTarget{{URL: dir, Paths: []string{"app"}}, {URL: dir, Paths: []string{"deploy"}}}
	results := strings.Join([]string{
		foundAt("EX2", "/opt/ci/build/gen.go"),
		foundAt("EX2", ""),
		foundAt("EX2", "app/a.go"),
		foundAt("EX2", "deploy/chart.yaml"),
		foundAt("EX1", "lib/b.go"),
	}, ",")
	rep, err := NewSARIFImport().Scan(context.Background(),
		plugin.FileTarget{Path: writeFile(t, exampleLog(results, "")), Component: "api", Repositories: repos}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range rep.Results {
		got = append(got, r.Location.URI)
	}
	if want := []string{"/opt/ci/build/gen.go", "", "app/a.go", "deploy/chart.yaml"}; !slices.Equal(got, want) {
		t.Errorf("kept %q, want %q", got, want)
	}
	if got := field(t, rep, "left out"); got != "1 finding outside paths, not counted" {
		t.Errorf("left out = %q", got)
	}
	if got := field(t, rep, "severity"); got != "SARIF level" {
		t.Errorf("severity = %q, want the kept findings' source alone", got)
	}
	if len(rep.Inputs) != 1 || rep.Inputs[0].Path != "/opt/ci/build/gen.go" {
		t.Errorf("inputs = %+v, want the path outside the checkout listed", rep.Inputs)
	}
}

// A component whose repository declares no scope keeps every finding, and its account of the file
// reads as it did before scoping existed.
func TestAnImportIntoAnUnscopedComponentIsUnchanged(t *testing.T) {
	rep, err := NewSARIFImport().Scan(context.Background(), plugin.FileTarget{
		Path: writeFile(t, monorepoLog), Component: "api", Repositories: []plugin.RepositoryTarget{{URL: t.TempDir()}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 4 || len(rep.Provenance[0].Detail) != 0 {
		t.Errorf("results = %d, detail = %v, want all four and no counts", len(rep.Results), rep.Provenance[0].Detail)
	}
	for _, f := range rep.Provenance[0].Fields {
		if f.Key == "left out" || f.Key == "not scoped" {
			t.Errorf("an unscoped component's account says %s: %s", f.Key, f.Value)
		}
	}
}

// Only an ignore pattern: a finding it matches is counted as ignored, not as outside paths, and the
// count reads as one clause.
func TestImportScopeFields(t *testing.T) {
	if got := (importScope{ignored: 1}).fields(); len(got) != 1 || got[0].Value != "1 finding matched by ignore, not counted" {
		t.Errorf("fields = %v", got)
	}
	if got := (importScope{}).fields(); len(got) != 0 {
		t.Errorf("nothing left out still says %v", got)
	}
	if got := keepOnly([]int{1, 2, 3}, []bool{false}); !slices.Equal(got, []int{2, 3}) {
		t.Errorf("keepOnly = %v, want an item past the mask kept", got)
	}
	rep, err := NewSARIFImport().Scan(context.Background(), plugin.FileTarget{
		Path: writeFile(t, monorepoLog), Component: "web",
		Repositories: []plugin.RepositoryTarget{{URL: t.TempDir(), Ignore: []string{"services/web/vendor"}}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 3 || field(t, rep, "left out") != "1 finding matched by ignore, not counted" {
		t.Errorf("results = %d, left out = %q", len(rep.Results), field(t, rep, "left out"))
	}
}
