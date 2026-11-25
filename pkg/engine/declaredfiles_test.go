package engine

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/draugr-dev/draugr/pkg/cache"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/vex"
)

const (
	revA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	revB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// jobsController plans the jobs it is given, as a project-wide control.
type jobsController struct {
	name string
	jobs []plugin.ScanJob
}

func (c jobsController) Info() plugin.ControllerInfo {
	return plugin.ControllerInfo{Name: c.name, Scope: plugin.ScopeProject}
}

func (c jobsController) Plan(saga.Model, *saga.Component) ([]plugin.ScanJob, error) {
	return c.jobs, nil
}

func (c jobsController) Aggregate(reports []sarif.Report) (plugin.ControlResult, error) {
	return plugin.ControlResult{Control: c.name, Report: sarif.Merge(reports...)}, nil
}

// configScanner records, as a repository scanner does while its checkout exists, the
// configuration files each repository holds at each revision and those it honored without listing
// what they kept. It counts its calls, so a test can tell a cache hit from a scan.
type configScanner struct {
	name string
	// files are the configuration files' digests by repository and revision, then by path.
	files map[string]map[string]string
	// unlisted are the files it honored without listing what they kept, by repository.
	unlisted map[string][]string
	mu       sync.Mutex
	call     int
}

func (s *configScanner) Info() plugin.ScannerInfo { return plugin.ScannerInfo{Name: s.name} }

func (s *configScanner) Scan(_ context.Context, target plugin.Target, _ plugin.Config) (sarif.Report, error) {
	s.mu.Lock()
	s.call++
	s.mu.Unlock()
	repo := target.(plugin.RepositoryTarget)
	p := sarif.Provenance{Tool: s.name, Fields: []sarif.Field{{Key: "repository", Value: repo.URL}},
		Detail: []sarif.Field{{Key: "module", Value: "go.mod"}}}
	for path, digest := range s.files[repo.URL+"@"+repo.Revision] {
		p.Detail = append(p.Detail, sarif.Field{Key: sarif.DetailConfigFile + path, Value: digest})
	}
	for _, path := range s.unlisted[repo.URL] {
		p.Detail = append(p.Detail, sarif.Field{Key: sarif.DetailUnlistedSetAside + path, Value: s.name})
	}
	return sarif.Report{Tool: s.name, Provenance: []sarif.Provenance{p}}, nil
}

func (s *configScanner) calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.call
}

// The configuration files every scanner's checkout held are recorded once per repository and path,
// with a digest for each revision two jobs read, and taken out of the reports. A cache hit records
// what the scan it reuses recorded, since the cache keeps the report the scanner returned.
func TestTheCheckoutsConfigFilesAreRecordedOncePerRepository(t *testing.T) {
	api, web := "https://example.com/api.git", "https://example.com/web.git"
	a := &configScanner{name: "a", files: map[string]map[string]string{
		api + "@" + revA: {".trivyignore": "1111111111111111", ".gitleaksignore": "2222222222222222"},
		api + "@" + revB: {".trivyignore": "3333333333333333"},
		web + "@" + revA: {".semgrepignore": "4444444444444444"},
	}, unlisted: map[string][]string{web: {".semgrepignore"}}}
	b := &configScanner{name: "b", files: a.files}
	reg := NewRegistry()
	reg.RegisterScanner(a)
	reg.RegisterScanner(b)
	reg.RegisterController(jobsController{name: "secrets", jobs: []plugin.ScanJob{
		{Scanner: "a", Target: plugin.RepositoryTarget{URL: api, Revision: revA}},
		{Scanner: "b", Target: plugin.RepositoryTarget{URL: api, Revision: revA}},
		{Scanner: "a", Target: plugin.RepositoryTarget{URL: api, Revision: revB}},
		{Scanner: "a", Target: plugin.RepositoryTarget{URL: web, Revision: revA}},
	}})
	model := saga.Model{Config: saga.Config{Controls: map[string]saga.ControllerSettings{"secrets": {"enabled": true}}}}
	want := []DeclaredFile{
		{Kind: FileScanner, Repository: api, Path: ".gitleaksignore", Digests: []string{"2222222222222222"}},
		{Kind: FileScanner, Repository: api, Path: ".trivyignore", Digests: []string{"1111111111111111", "3333333333333333"}},
		{Kind: FileScanner, Repository: web, Path: ".semgrepignore", Digests: []string{"4444444444444444"}},
	}
	wantUnlisted := []UnlistedSetAside{{Repository: web, File: ".semgrepignore", Scanner: "a"}}

	e := New(reg, WithCache(cache.NewLocal(t.TempDir(), 0)))
	for run := 1; run <= 2; run++ {
		res, err := e.Run(context.Background(), model)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(res.Declared.Files, want) {
			t.Errorf("run %d: files = %+v\nwant %+v", run, res.Declared.Files, want)
		}
		if !reflect.DeepEqual(res.Unlisted, wantUnlisted) {
			t.Errorf("run %d: unlisted = %+v", run, res.Unlisted)
		}
		for _, p := range res.Controls["secrets"].Report.Provenance {
			for _, d := range p.Detail {
				if strings.HasPrefix(d.Key, sarif.DetailConfigFile) || strings.HasPrefix(d.Key, sarif.DetailUnlistedSetAside) {
					t.Errorf("run %d: the report still carries %s", run, d.Key)
				}
			}
			if len(p.Detail) != 1 || p.Detail[0].Key != "module" {
				t.Errorf("run %d: the scanner's own detail was not kept: %+v", run, p.Detail)
			}
		}
		if run == 2 && (res.Stats.CacheHits != 4 || a.calls()+b.calls() != 4) {
			t.Errorf("the second run scanned again: %d hits, %d calls", res.Stats.CacheHits, a.calls()+b.calls())
		}
	}
}

// settingScanner names the paths under its config's "files" as the files its settings point it at.
type settingScanner struct{ fakeScanner }

func (s *settingScanner) SettingFiles(cfg plugin.Config) []string {
	files, _ := cfg["files"].([]string)
	return files
}

// A file or directory a setting names is recorded by the path the setting gives, read where Draugr
// runs, once however many jobs name it. A directory is named by every file under it, and one that
// is not there is not recorded.
func TestTheFilesASettingNamesAreRecorded(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	for path, body := range map[string]string{"rules.yml": "rules: []", "rules/a.yml": "rules: [a]", "rules/sub/b.yml": "rules: [b]"} {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	run := func() []DeclaredFile {
		reg := NewRegistry()
		reg.RegisterScanner(&settingScanner{fakeScanner{name: "s"}})
		reg.RegisterScanner(&fakeScanner{name: "plain"})
		files := []string{"rules.yml", "rules", "missing.yml"}
		reg.RegisterController(jobsController{name: "sast", jobs: []plugin.ScanJob{
			{Scanner: "s", Target: plugin.RepositoryTarget{URL: "r/api"}, Config: plugin.Config{"files": files}},
			{Scanner: "s", Target: plugin.RepositoryTarget{URL: "r/web"}, Config: plugin.Config{"files": files}},
			{Scanner: "plain", Target: plugin.RepositoryTarget{URL: "r/web"}, Config: plugin.Config{"files": files}},
		}})
		model := saga.Model{Config: saga.Config{Controls: map[string]saga.ControllerSettings{"sast": {"enabled": true}}}}
		res, err := New(reg).Run(context.Background(), model)
		if err != nil {
			t.Fatal(err)
		}
		return res.Declared.Files
	}
	before := run()
	if len(before) != 2 || before[0].Path != "rules" || before[1].Path != "rules.yml" ||
		before[0].Kind != FileSetting || len(before[0].Digests) != 1 || len(before[0].Digests[0]) != 16 {
		t.Fatalf("files = %+v, want rules and rules.yml once each", before)
	}
	if err := os.WriteFile("rules/sub/b.yml", []byte("rules: []"), 0o600); err != nil {
		t.Fatal(err)
	}
	after := run()
	if after[0].Digests[0] == before[0].Digests[0] || after[1].Digests[0] != before[1].Digests[0] {
		t.Errorf("an edit under the directory: %+v, then %+v", before, after)
	}
}

// A setting is digested as the descriptor wrote it, so one descriptor loaded under two values of a
// pipeline variable records one declaration, and a change to the reference as written records
// another. The file a substituted path names is recorded by the reference, with its content's
// digest.
func TestSettingsAreDigestedAsWritten(t *testing.T) {
	descriptor := func(config string) []byte {
		return []byte(`project: shop
release: { version: "1.0" }
config:
  controls:
    sast:
      enabled: true
      semgrep: { config: "` + config + `" }
components:
  - name: api
    repositories:
      - url: .
`)
	}
	t.Setenv(saga.SagaEnvsVar, "RULES")
	declare := func(value, config string) (map[string]ControlSettings, []DeclaredFile) {
		t.Helper()
		dir := t.TempDir()
		rules := filepath.Join(dir, value)
		if err := os.WriteFile(rules, []byte("rules: []"), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("RULES", rules)
		model, err := saga.Load(descriptor(config))
		if err != nil {
			t.Fatal(err)
		}
		reg := NewRegistry()
		reg.RegisterController(jobsController{name: "sast"})
		reg.RegisterScanner(&settingScanner{fakeScanner{name: "semgrep"}})
		e := New(reg)
		planned := []PlannedJob{{Control: "sast", Job: plugin.ScanJob{Scanner: "semgrep",
			Config: plugin.Config{"files": []string{rules}}}}}
		return e.declarations(*model, time.Now()).Settings, e.settingFiles(planned, model)
	}
	first, firstFiles := declare("a.yml", "${{ RULES }}")
	second, secondFiles := declare("b.yml", "${{ RULES }}")
	if !reflect.DeepEqual(first, second) || len(first["sast"]) != 1 {
		t.Errorf("one descriptor under two values: %v, then %v", first, second)
	}
	if !reflect.DeepEqual(firstFiles, secondFiles) || len(firstFiles) != 1 || firstFiles[0].Path != "${{ RULES }}" {
		t.Errorf("files = %+v, then %+v, want the file named by its reference", firstFiles, secondFiles)
	}
	if moved, _ := declare("a.yml", "${{ RULES }}.d"); reflect.DeepEqual(moved, first) {
		t.Error("a reference written differently kept the digest")
	}
}

// A VEX document on disk is recorded with its digest and one elsewhere by where it is, for the
// project and for each component the run covers, once each.
func TestTheVEXDocumentsReadAreRecorded(t *testing.T) {
	doc := func(kind, location, digest string) vex.Resolved {
		return vex.Resolved{Provenance: vex.Provenance{Kind: kind, Location: location, Digest: digest}}
	}
	set := vex.Set{
		Project: []vex.Resolved{doc("url", "https://vendor.example.com/vex.json", "sha256:0123456789abcdef0123")},
		ByComponent: map[string][]vex.Resolved{
			"api": {doc("path", "vex/api.json", "sha256:fedcba9876543210fedc")},
			"web": {doc("repository", "https://example.com/vex.git#web.json", "sha256:00"),
				doc("path", "vex/api.json", "sha256:fedcba9876543210fedc")},
			"docs": {doc("path", "vex/docs.json", "sha256:1111111111111111")},
		},
	}
	got := New(NewRegistry(), WithVEX(set), WithScope(Scope{Components: []string{"api", "web"}})).vexFiles(&saga.Model{})
	sortDeclaredFiles(got)
	want := []DeclaredFile{
		{Kind: FileVEX, Path: "https://example.com/vex.git#web.json"},
		{Kind: FileVEX, Path: "https://vendor.example.com/vex.json"},
		{Kind: FileVEX, Path: "vex/api.json", Digests: []string{"fedcba9876543210"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("files = %+v\nwant %+v", got, want)
	}
}

func TestRepositoryScopesAreRecordedAsWritten(t *testing.T) {
	descriptor := []byte(`project: shop
release: { version: "1.0" }
components:
  - name: api
    repositories:
      - url: ${{ REMOTE }}/api
        revision: ${{ SHA }}
        paths: ["${{ SUBDIR }}"]
        ignore: ["${{ SUBDIR }}/vendor/"]
      - url: ${{ REMOTE }}/web
        revision: ${{ SHA }}
`)
	t.Setenv(saga.SagaEnvsVar, "REMOTE,SHA,SUBDIR")
	declare := func(remote, sha, subdir string) []RepositoryScope {
		t.Helper()
		t.Setenv("REMOTE", remote)
		t.Setenv("SHA", sha)
		t.Setenv("SUBDIR", subdir)
		model, err := saga.Load(descriptor)
		if err != nil {
			t.Fatal(err)
		}
		d := New(NewRegistry()).declarations(*model, time.Now())
		if len(d.Components) != 1 {
			t.Fatalf("components = %+v", d.Components)
		}
		return d.Components[0].Scopes
	}
	base := declare("/runner/1", "1111111111111111111111111111111111111111", "src")
	head := declare("/runner/2", "2222222222222222222222222222222222222222", "lib")
	if !reflect.DeepEqual(base, head) {
		t.Errorf("one descriptor under two runs' values recorded two scopes:\n  %+v\n  %+v", base, head)
	}
	want := []RepositoryScope{
		{URL: "${{ REMOTE }}/api", Revision: "${{ SHA }}", Paths: []string{"${{ SUBDIR }}"},
			Ignore: []string{"${{ SUBDIR }}/vendor/"}},
		{URL: "${{ REMOTE }}/web", Revision: "${{ SHA }}"},
	}
	if !reflect.DeepEqual(base, want) {
		t.Errorf("scopes = %+v, want each field as written: %+v", base, want)
	}
}

func TestARepositoryScopeWithoutReferencesIsRecordedAsItReads(t *testing.T) {
	model, err := saga.Load([]byte(`project: shop
release: { version: "1.0" }
components:
  - name: api
    repositories:
      - url: .
        revision: v1
        paths: [src]
        ignore: [src/vendor/]
      - url: ../web
`))
	if err != nil {
		t.Fatal(err)
	}
	got := New(NewRegistry()).declarations(*model, time.Now()).Components[0].Scopes
	want := []RepositoryScope{
		{URL: ".", Revision: "v1", Paths: []string{"src"}, Ignore: []string{"src/vendor/"}},
		{URL: "../web"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("scopes = %+v, want %+v", got, want)
	}
}
