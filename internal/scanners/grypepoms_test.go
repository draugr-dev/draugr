package scanners

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/controllers"
	"github.com/draugr-dev/draugr/internal/git"
	"github.com/draugr-dev/draugr/internal/manifests"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// The recorded output under testdata/grype-poms is Grype 0.121.0 (Syft 1.55.0), `grype dir:<repo>
// --by-cve -o sarif -o cyclonedx-json`, over two repositories of two poms each. In `shop`, web/ and
// worker/ both declare commons-text 1.9, worker through a property; Syft lists the package once, at
// web/pom.xml. In `billing`, api/ declares commons-text 1.9 and batch/ 1.10.0, two packages Syft
// keeps apart. One component per repository.

// runGrypePoms scans both components with grype-fs under the real sca control, each scan replaying
// what Grype wrote for its repository, over a checkout holding the recorded poms.
func runGrypePoms(t *testing.T) engine.Result {
	t.Helper()
	read := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join("testdata", "grype-poms", name)) // #nosec G304 -- under testdata
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	dirs := map[string]string{"shop": t.TempDir(), "billing": t.TempDir()}
	modules := map[string][]string{"shop": {"web", "worker"}, "billing": {"api", "batch"}}
	repoOf := map[string]string{}
	for repo, dir := range dirs {
		repoOf[dir] = repo
		for _, m := range modules[repo] {
			if err := os.MkdirAll(filepath.Join(dir, m), 0o750); err != nil {
				t.Fatal(err)
			}
			// #nosec G703 -- a fixture copied into t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, m, "pom.xml"), read(repo+"."+m+".pom.xml"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	checkout := func(_ context.Context, url, _ string, _ git.Scope) (git.Tree, func(), error) {
		return git.Tree{Dir: dirs[url]}, func() {}, nil
	}
	prior := grypeRunInDir
	t.Cleanup(func() { grypeRunInDir = prior })
	grypeRunInDir = func(_ context.Context, dir string, argv []string) ([]byte, error) {
		repo := repoOf[dir]
		// The JSON report holds nothing ignored, and the inventory is the one Grype wrote.
		fakeGrypeOutputs(t, argv, grypeJSON())
		for i, a := range argv {
			if format, path, ok := strings.Cut(argv[min(i+1, len(argv)-1)], "="); a == "-o" && ok && format == "cyclonedx-json" {
				// #nosec G703 -- the path the scanner asked Grype to write, under the system temp dir
				if err := os.WriteFile(path, read(repo+".grype.cdx.json"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
		}
		return read(repo + ".grype.sarif"), nil
	}
	grype := NewGrypeFS().(repoScanner)
	grype.checkout, grype.prewarm, grype.cacheVersion, grype.dataState = checkout, nil, nil, nil

	reg := engine.NewRegistry()
	reg.RegisterController(controllers.NewSCA())
	reg.RegisterScanner(grype)
	model := saga.Model{Config: saga.Config{Controls: map[string]saga.ControllerSettings{"sca": {
		"enabled": true, "trivyFs": map[string]any{"enabled": false}, "grypeFs": map[string]any{"enabled": true},
	}}}}
	for _, name := range []string{"shop", "billing"} {
		model.Components = append(model.Components, saga.Component{Name: name, Repositories: []saga.Repository{{URL: name}}})
	}
	res, err := engine.New(reg).Run(context.Background(), model)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// A flaw in a package two poms declare identically names both poms, and each counts the package as
// read. A pom that declares another version of the package gets no copy.
func TestGrypeNamesEveryPomThatDeclaresThePackage(t *testing.T) {
	res := runGrypePoms(t)
	cr := res.Controls["sca"]
	where := map[string][]string{}
	for _, r := range cr.Report.Results {
		if r.RuleID == "CVE-2022-42889-commons-text" {
			where[r.Component] = append(where[r.Component], r.Location.URI)
		}
	}
	for comp, want := range map[string][]string{
		"shop":    {"web/pom.xml", "worker/pom.xml"},
		"billing": {"api/pom.xml"},
	} {
		got := where[comp]
		slices.Sort(got)
		if !slices.Equal(got, want) {
			t.Errorf("%s: the commons-text flaw names %v, want %v", comp, got, want)
		}
	}
	read := map[string]int{}
	for _, in := range cr.Report.Inputs {
		read[in.Component+" "+in.Path] = in.Packages
	}
	// Each pom's own artifact is a package Syft reads from it, beside its dependencies.
	for file, want := range map[string]int{
		"shop web/pom.xml": 2, "shop worker/pom.xml": 2, "billing api/pom.xml": 2, "billing batch/pom.xml": 2,
	} {
		if read[file] != want {
			t.Errorf("%s: %d packages read, want %d (all: %v)", file, read[file], want, read)
		}
	}
}

// A pom outside the checkout, one that cannot be read, and one with no dependency at the version
// are left alone, as is a finding that is not about a Maven package.
func TestSpreadPomFindingsLeavesWhatItCannotConfirm(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "pom.xml"), []byte(`<project><dependencies>
<dependency><groupId>g</groupId><artifactId>a</artifactId><version>2</version></dependency>
</dependencies></project>`), 0o600); err != nil {
		t.Fatal(err)
	}
	finding := func(purl, uri string) sarif.Result {
		return sarif.Result{RuleID: "CVE-1", Location: sarif.Location{URI: uri},
			Package: &sarif.Package{Name: "a", Version: "1", PURL: purl}}
	}
	report := sarif.Report{
		Inputs: []sarif.Input{{Path: "m/pom.xml"}, {Path: "pom.xml"}, {Path: "../pom.xml"}, {Path: "gone/pom.xml"}},
		Results: []sarif.Result{
			finding("pkg:maven/g/a@1", "m/pom.xml"),
			finding("pkg:npm/a@1", "m/pom.xml"),
			{RuleID: "x", Location: sarif.Location{URI: "m/pom.xml"}},
		},
	}
	spreadPomFindings(&report, dir)
	if len(report.Results) != 3 {
		t.Errorf("results = %+v, want the three it was given", report.Results)
	}
	for _, in := range report.Inputs {
		if in.Packages != 0 {
			t.Errorf("%s counted %d packages", in.Path, in.Packages)
		}
	}
	// One pom is nothing to spread across.
	one := sarif.Report{Inputs: []sarif.Input{{Path: "pom.xml"}}, Results: []sarif.Result{finding("pkg:maven/g/a@2", "x/pom.xml")}}
	spreadPomFindings(&one, dir)
	if len(one.Results) != 1 {
		t.Errorf("a single pom took a copy: %+v", one.Results)
	}
}

// A version comes from the dependency, a property, or the same pom's dependencyManagement, and one
// managed elsewhere is left out.
func TestPomVersions(t *testing.T) {
	got, err := manifests.PomVersions([]byte(`<project><groupId>ex</groupId><version>3.0</version>
<properties><v>1.2</v></properties>
<dependencyManagement><dependencies>
  <dependency><groupId>m</groupId><artifactId>managed</artifactId><version>4.0</version></dependency>
</dependencies></dependencyManagement>
<dependencies>
  <dependency><groupId>g</groupId><artifactId>literal</artifactId><version>1.0</version></dependency>
  <dependency><groupId>g</groupId><artifactId>literal</artifactId><version>1.0</version><classifier>x</classifier></dependency>
  <dependency><groupId>g</groupId><artifactId>property</artifactId><version>${v}</version></dependency>
  <dependency><groupId>${project.groupId}</groupId><artifactId>sibling</artifactId><version>${project.version}</version></dependency>
  <dependency><groupId>m</groupId><artifactId>managed</artifactId></dependency>
  <dependency><groupId>p</groupId><artifactId>parent-managed</artifactId></dependency>
  <dependency><groupId>p</groupId><artifactId>undefined</artifactId><version>${nowhere}</version></dependency>
</dependencies></project>`))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{
		"g:literal": {"1.0"}, "g:property": {"1.2"}, "ex:sibling": {"3.0"}, "m:managed": {"4.0"},
	}
	if len(got) != len(want) {
		t.Errorf("versions = %v, want %v", got, want)
	}
	for k, v := range want {
		if !slices.Equal(got[k], v) {
			t.Errorf("%s = %v, want %v", k, got[k], v)
		}
	}
	if _, err := manifests.PomVersions([]byte("<project")); err == nil {
		t.Error("a pom that does not parse returned no error")
	}
}
