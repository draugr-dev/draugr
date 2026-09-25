package scanners

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/git"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// writeTree writes files under a fresh directory, keyed by slash-separated path.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, content := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// checkoutOf serves each repository URL from its own directory.
func checkoutOf(trees map[string]string) func(context.Context, string, string, git.Scope) (git.Tree, func(), error) {
	return func(_ context.Context, url, _ string, _ git.Scope) (git.Tree, func(), error) {
		return git.Tree{Dir: trees[url]}, func() {}, nil
	}
}

const npmManifest = `{"name":"web","dependencies":{"lodash":"4.17.20"}}`

// Two repositories, because an input keyed on anything coarser than the repository would let the
// second scan's files answer for the first's.
func TestRepoScanAccountsForWhatItReadInEachRepository(t *testing.T) {
	trees := map[string]string{
		"https://example.com/api.git": writeTree(t, map[string]string{
			"requirements.txt":     "flask==2.0.0\n",
			"requirements-dev.txt": "pytest==8.0.0\n",
		}),
		"https://example.com/web.git": writeTree(t, map[string]string{
			"package.json": npmManifest,
		}),
	}
	s := repoScanner{
		info:     plugin.ScannerInfo{Name: "trivy-fs", Controls: []string{"sca"}},
		args:     func(dir string, _ plugin.Config) []string { return []string{"trivy", "fs", dir} },
		checkout: checkoutOf(trees),
		run: func(context.Context, string, []string) ([]byte, error) {
			return []byte(`{}`), nil
		},
		parse: func(_ []byte, dir string, _ plugin.Config) (sarif.Report, error) {
			var rep sarif.Report
			if _, err := os.Stat(filepath.Join(dir, "requirements.txt")); err == nil {
				rep.Inputs = []sarif.Input{{Path: "requirements.txt", Packages: 1}}
			}
			return rep, nil
		},
		accounts: true,
	}

	want := map[string][]sarif.Input{
		"https://example.com/api.git": {
			{Scanner: "trivy-fs", Repository: "https://example.com/api", Path: "requirements.txt", Packages: 1},
			{Scanner: "trivy-fs", Repository: "https://example.com/api", Path: "requirements-dev.txt",
				Unread: "no packages read"},
		},
		"https://example.com/web.git": {
			{Scanner: "trivy-fs", Repository: "https://example.com/web", Path: "package.json",
				Unread: "no lockfile"},
		},
	}
	for url, inputs := range want {
		rep, err := s.Scan(context.Background(), plugin.RepositoryTarget{URL: url}, plugin.Config{})
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(rep.Inputs, inputs) {
			t.Errorf("%s inputs =\n%+v\nwant\n%+v", url, rep.Inputs, inputs)
		}
	}
}

// A scanner that does not account for its reads says nothing about the files in the tree, rather
// than reporting every one of them unread.
func TestRepoScanWithoutAccountingNamesNoInputs(t *testing.T) {
	dir := writeTree(t, map[string]string{"package.json": npmManifest})
	s := newFakeRepoScanner(func(context.Context, string, []string) ([]byte, error) {
		return []byte(repoSARIF), nil
	})
	s.checkout = checkoutOf(map[string]string{".": dir})
	rep, err := s.Scan(context.Background(), plugin.RepositoryTarget{URL: "."}, plugin.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Inputs) != 0 {
		t.Errorf("inputs = %+v, want none", rep.Inputs)
	}
}

// inventoryPath is the file an argv asks Grype to write its CycloneDX to.
func inventoryPath(argv []string) string {
	for _, a := range argv {
		if p, ok := strings.CutPrefix(a, "cyclonedx-json="); ok {
			return p
		}
	}
	return ""
}

func TestGrypeFSAccountsFromItsInventory(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"sub/setup.py":         "setup(install_requires=['flask==1.0'])\n",
		"requirements-dev.txt": "jinja2==2.10\n",
		"web/package.json":     npmManifest,
	})
	inventory := `{"components":[
		{"type":"library","name":"flask","properties":[{"name":"syft:location:0:path","value":"/sub/setup.py"}]},
		{"type":"library","name":"jinja2","properties":[{"name":"syft:location:0:path","value":"/requirements-dev.txt"}]},
		{"type":"file","name":"` + dir + `/sub/setup.py"}
	]}`
	g, ok := NewGrypeFS().(repoScanner)
	if !ok {
		t.Fatal("grype-fs is not a repository scanner")
	}
	g.checkout = checkoutOf(map[string]string{"https://example.com/app.git": dir})
	g.run = func(_ context.Context, _ string, argv []string) ([]byte, error) {
		if err := os.WriteFile(inventoryPath(argv), []byte(inventory), 0o600); err != nil {
			return nil, err
		}
		return []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"grype"}},"results":[]}]}`), nil
	}
	rep, err := g.Scan(context.Background(), plugin.RepositoryTarget{URL: "https://example.com/app.git"}, plugin.Config{})
	if err != nil {
		t.Fatal(err)
	}
	repo := "https://example.com/app"
	want := []sarif.Input{
		{Scanner: "grype-fs", Repository: repo, Path: "requirements-dev.txt", Packages: 1},
		{Scanner: "grype-fs", Repository: repo, Path: "sub/setup.py", Packages: 1},
		{Scanner: "grype-fs", Repository: repo, Path: "web/package.json", Unread: "no lockfile"},
	}
	if !reflect.DeepEqual(rep.Inputs, want) {
		t.Errorf("inputs =\n%+v\nwant\n%+v", rep.Inputs, want)
	}
}

// An empty inventory would say Grype read nothing, and report every file in the tree unread.
func TestGrypeFSRefusesAScanThatWroteNoInventory(t *testing.T) {
	g, _ := NewGrypeFS().(repoScanner)
	g.checkout = checkoutOf(map[string]string{".": t.TempDir()})
	g.run = func(context.Context, string, []string) ([]byte, error) {
		return []byte(`{"version":"2.1.0","runs":[]}`), nil
	}
	_, err := g.Scan(context.Background(), plugin.RepositoryTarget{URL: "."}, plugin.Config{})
	if err == nil || !strings.Contains(err.Error(), "no inventory") {
		t.Errorf("err = %v, want a refusal naming the missing inventory", err)
	}
}

func TestGrypeFSRefusesAnInventoryItCannotRead(t *testing.T) {
	g, _ := NewGrypeFS().(repoScanner)
	g.checkout = checkoutOf(map[string]string{".": t.TempDir()})
	g.run = func(_ context.Context, _ string, argv []string) ([]byte, error) {
		return []byte(`{"version":"2.1.0","runs":[]}`), os.WriteFile(inventoryPath(argv), []byte("not json"), 0o600)
	}
	_, err := g.Scan(context.Background(), plugin.RepositoryTarget{URL: "."}, plugin.Config{})
	if err == nil || !strings.Contains(err.Error(), "inventory") {
		t.Errorf("err = %v", err)
	}
}

func TestGrypeFSReportsARunFailureBeforeItsInventory(t *testing.T) {
	g, _ := NewGrypeFS().(repoScanner)
	g.checkout = checkoutOf(map[string]string{".": t.TempDir()})
	g.run = func(context.Context, string, []string) ([]byte, error) {
		return nil, os.ErrPermission
	}
	if _, err := g.Scan(context.Background(), plugin.RepositoryTarget{URL: "."}, plugin.Config{}); err == nil {
		t.Error("a failed run was accepted")
	}
}

func TestParseGrypeInventoryCountsEveryLocation(t *testing.T) {
	got, err := parseGrypeInventory([]byte(`{"components":[
		{"type":"library","properties":[
			{"name":"syft:location:0:path","value":"/web/package-lock.json"},
			{"name":"syft:location:1:path","value":"/web/package.json"},
			{"name":"syft:package:type","value":"npm"}]},
		{"type":"library","properties":[{"name":"syft:location:0:path","value":"/web/package-lock.json"}]}
	]}`), "/checkout")
	if err != nil {
		t.Fatal(err)
	}
	want := []sarif.Input{
		{Path: "web/package-lock.json", Packages: 2},
		{Path: "web/package.json", Packages: 1},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("inputs = %+v, want %+v", got, want)
	}
}

const trivyLangPkgs = `{"Results":[
	{"Target":"api/requirements.txt","Class":"lang-pkgs","Type":"pip",
	 "Packages":[{"Identifier":{"UID":"a"}},{"Identifier":{"UID":"b"}}]},
	{"Target":"debian","Class":"os-pkgs","Type":"debian","Packages":[{"Identifier":{"UID":"c"}}]},
	{"Target":"web/package-lock.json","Class":"license","Licenses":[]}
]}`

func TestTrivyParsersRecordTheFilesTheyRead(t *testing.T) {
	want := []sarif.Input{{Path: "api/requirements.txt", Packages: 2}}
	vulns, err := parseTrivyVulns([]byte(trivyLangPkgs), t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(vulns.Inputs, want) {
		t.Errorf("trivy-fs inputs = %+v, want %+v", vulns.Inputs, want)
	}
	licenses, err := parseTrivyLicenses([]byte(trivyLangPkgs), t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(licenses.Inputs, want) {
		t.Errorf("trivy-license inputs = %+v, want %+v", licenses.Inputs, want)
	}
}

// An image has no tree to account against.
func TestTrivyLicenseRecordsNoInputsForAnImage(t *testing.T) {
	rep, err := parseTrivyLicenses([]byte(trivyLangPkgs), "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Inputs) != 0 {
		t.Errorf("inputs = %+v, want none", rep.Inputs)
	}
}

func TestTrivyScannersAccountForTheirReads(t *testing.T) {
	fs, _ := NewTrivyFS().(repoScanner)
	if !fs.accounts {
		t.Error("trivy-fs does not account for what it read")
	}
	lic, _ := NewTrivyLicense().(licenseScanner)
	if repo, _ := lic.repo.(repoScanner); !repo.accounts {
		t.Error("trivy-license does not account for what it read")
	}
}

// Trivy lists a conda environment's packages, and warns that it does not check them for
// vulnerabilities. Its license scan reads them; its vulnerability scan does not, and says nothing in
// its JSON to tell the two apart.
func TestTrivyVulnsLeaveOutWhatTrivyOnlyLists(t *testing.T) {
	doc := []byte(`{"Results":[
		{"Target":"environment.yml","Class":"lang-pkgs","Type":"conda-environment",
		 "Packages":[{"Identifier":{"UID":"a"}}]},
		{"Target":"requirements.txt","Class":"lang-pkgs","Type":"pip","Packages":[{"Identifier":{"UID":"b"}}]}
	]}`)
	vulns, err := parseTrivyVulns(doc, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if want := []sarif.Input{{Path: "requirements.txt", Packages: 1}}; !reflect.DeepEqual(vulns.Inputs, want) {
		t.Errorf("trivy-fs inputs = %+v, want %+v", vulns.Inputs, want)
	}
	licenses, err := parseTrivyLicenses(doc, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(licenses.Inputs) != 2 {
		t.Errorf("trivy-license inputs = %+v, want both files", licenses.Inputs)
	}
}
