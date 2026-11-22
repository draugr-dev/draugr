package scanners

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/draugr-dev/draugr/internal/controllers"
	"github.com/draugr-dev/draugr/internal/git"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// The recorded output under testdata/pip-range is Trivy 0.76.1 (fs --scanners vuln --format json
// --list-all-pkgs --offline-scan --include-dev-deps --detection-priority comprehensive) run over the
// two trees runPipRanges writes. Both hold a requirements.txt reading `flask>=0.12`; api also holds
// the uv.lock of test/integration's python-uv scenario, which pins Flask at 0.12.2. Trivy reads the
// range as Flask 0.12 and reports each of its advisories in both files of api, under two package URLs.
func pipRangeRead(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "pip-range", name)) // #nosec G304 -- under testdata
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// runPipRanges scans one component holding two repositories, api and web, with trivy-fs under the
// real sca control and detectionPriority: comprehensive, replaying what Trivy wrote for each.
func runPipRanges(t *testing.T) engine.Result {
	t.Helper()
	dirs := map[string]string{
		"api": writeTree(t, map[string]string{
			"requirements.txt": "flask>=0.12\n",
			"uv.lock":          string(pipRangeRead(t, "uv.lock.fixture")),
		}),
		"web": writeTree(t, map[string]string{"requirements.txt": "flask>=0.12\n"}),
	}
	repoOf := map[string]string{dirs["api"]: "api", dirs["web"]: "web"}
	trivy := NewTrivyFS().(repoScanner)
	trivy.checkout = func(_ context.Context, url, _ string, _ git.Scope) (git.Tree, func(), error) {
		return git.Tree{Dir: dirs[url]}, func() {}, nil
	}
	trivy.prewarm, trivy.cacheVersion, trivy.dataState = nil, nil, nil
	trivy.runLogged = trivyFSRun(func(_ context.Context, dir string, _ []string) ([]byte, []byte, error) {
		return pipRangeRead(t, repoOf[dir]+".trivy.json"), nil, nil
	})
	reg := engine.NewRegistry()
	reg.RegisterController(controllers.NewSCA())
	reg.RegisterScanner(trivy)
	model := saga.Model{
		Config: saga.Config{Controls: map[string]saga.ControllerSettings{"sca": {
			"enabled": true, "trivyFs": map[string]any{"detectionPriority": "comprehensive"},
		}}},
		Components: []saga.Component{{Name: "app", Repositories: []saga.Repository{{URL: "api"}, {URL: "web"}}}},
	}
	res, err := engine.New(reg).Run(context.Background(), model)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// Over Trivy's own output, each advisory the api repository's requirements.txt range and its uv.lock
// both report is counted once, at the lockfile, with the range's copy kept and counted under it. The
// web repository has no lockfile and the same requirements.txt: its findings stay counted, and none
// is folded into api's lockfile, which pins nothing for web.
func TestTrivyRangeFindingsAreCountedOnceAtTheLockfileOverRecordedOutput(t *testing.T) {
	res := runPipRanges(t)
	counted, folded := map[string][]string{}, map[string][]string{}
	for _, r := range res.Controls["sca"].Report.Results {
		row := r.RuleID + " " + r.Location.URI + " " + r.Package.Version
		if r.Correlated() {
			folded[r.Repository] = append(folded[r.Repository], row)
		} else {
			counted[r.Repository] = append(counted[r.Repository], row)
		}
	}
	for _, rows := range []map[string][]string{counted, folded} {
		for _, list := range rows {
			sort.Strings(list)
		}
	}
	advisories := []string{"CVE-2018-1000656", "CVE-2019-1010083", "CVE-2023-30861", "CVE-2026-27205"}
	var atLock, atRange []string
	for _, id := range advisories {
		atLock = append(atLock, id+" uv.lock 0.12.2")
		atRange = append(atRange, id+" requirements.txt 0.12")
	}
	wantCounted := map[string][]string{
		"api": append(append([]string{}, atLock[:3]...), "CVE-2026-102598 uv.lock 3.1.8", atLock[3]),
		"web": atRange,
	}
	if !reflect.DeepEqual(counted, wantCounted) {
		t.Errorf("counted = %v, want %v", counted, wantCounted)
	}
	if want := map[string][]string{"api": atRange}; !reflect.DeepEqual(folded, want) {
		t.Errorf("folded = %v, want %v", folded, want)
	}
}

// rangeDoc is Trivy's JSON for two projects in one checkout, each with a requirements.txt Trivy read
// with detectionPriority: comprehensive, and one with the uv.lock pinning what installs. The lines
// are the ones Trivy's pip parser records for each package.
const rangeDoc = `{"Results":[
  {"Target":"api/requirements.txt","Type":"pip","Class":"lang-pkgs",
   "Packages":[{"Name":"pillow","Version":"10.4","Identifier":{"UID":"a1"},"Locations":[{"StartLine":1}]},
               {"Name":"requests","Version":"2.19.1","Identifier":{"UID":"a2"},"Locations":[{"StartLine":2}]}],
   "Vulnerabilities":[
     {"VulnerabilityID":"CVE-1","PkgName":"pillow","InstalledVersion":"10.4","PkgIdentifier":{"UID":"a1"},"Severity":"HIGH"},
     {"VulnerabilityID":"CVE-2","PkgName":"requests","InstalledVersion":"2.19.1","PkgIdentifier":{"UID":"a2"},"Severity":"HIGH"}]},
  {"Target":"api/uv.lock","Type":"uv","Class":"lang-pkgs",
   "Packages":[{"Name":"pillow","Version":"10.4.0","Identifier":{"UID":"l1"},"Locations":[{"StartLine":2}]}],
   "Vulnerabilities":[
     {"VulnerabilityID":"CVE-1","PkgName":"pillow","InstalledVersion":"10.4.0","PkgIdentifier":{"UID":"l1"},"Severity":"HIGH"}]},
  {"Target":"web/requirements.txt","Type":"pip","Class":"lang-pkgs",
   "Packages":[{"Name":"Pillow","Version":"9.0","Identifier":{"UID":"w1"},"Locations":[{"StartLine":2}]}],
   "Vulnerabilities":[
     {"VulnerabilityID":"CVE-1","PkgName":"Pillow","InstalledVersion":"9.0","PkgIdentifier":{"UID":"w1"},"Severity":"HIGH"}],
   "ExperimentalModifiedFindings":[{"Type":"vulnerability","Status":"ignored","Source":".trivyignore",
     "Finding":{"VulnerabilityID":"CVE-3","PkgName":"Pillow","InstalledVersion":"9.0","PkgIdentifier":{"UID":"w1"},"Severity":"LOW"}}]}
]}`

// writeRangeCheckout writes the files rangeDoc names.
func writeRangeCheckout(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range map[string]string{
		"api/requirements.txt": "pillow>=10.4\nrequests==2.19.1\n",
		"api/uv.lock":          "[[package]]\nname = \"pillow\"\nversion = \"10.4.0\"\n",
		"web/requirements.txt": "# imaging\nPillow[tiff] ~= 9.0 ; python_version > '3'  # pinned by the lockfile\n",
	} {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// rangesByFinding is each finding's range, keyed "file rule".
func rangesByFinding(t *testing.T, dir string, cfg plugin.Config) map[string]string {
	t.Helper()
	rep, err := parseTrivyVulns([]byte(rangeDoc), dir, cfg)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, r := range rep.Results {
		out[r.Location.URI+" "+r.RuleID] = r.Package.Range
	}
	return out
}

// With detectionPriority: comprehensive, a finding whose version Trivy read from a range's minimum
// carries the range, in each project's own requirements file, a finding Trivy set aside included. A
// pinned requirement and a lockfile's entry carry none, so correlation can count the range copy at
// the lockfile beside it.
func TestAFindingReadFromARangeCarriesTheRange(t *testing.T) {
	got := rangesByFinding(t, writeRangeCheckout(t), plugin.Config{"detectionPriority": "comprehensive"})
	want := map[string]string{
		"api/requirements.txt CVE-1": ">=10.4",
		"api/requirements.txt CVE-2": "",
		"api/uv.lock CVE-1":          "",
		"web/requirements.txt CVE-1": "~=9.0",
		"web/requirements.txt CVE-3": "~=9.0",
	}
	for k, w := range want {
		if g, ok := got[k]; !ok || g != w {
			t.Errorf("%s: range = %q (present %v), want %q", k, g, ok, w)
		}
	}
	if len(got) != len(want) {
		t.Errorf("findings = %v, want %d", got, len(want))
	}
}

// Without comprehensive Trivy reads no range, so no finding is marked as read from one, whatever its
// line says.
func TestNoRangeIsClaimedWithoutComprehensive(t *testing.T) {
	dir := writeRangeCheckout(t)
	for _, cfg := range []plugin.Config{nil, {"detectionPriority": "precise"}} {
		for k, r := range rangesByFinding(t, dir, cfg) {
			if r != "" {
				t.Errorf("%v: %s range = %q, want none", cfg, k, r)
			}
		}
	}
}

// pipRange reads a line as Trivy's pip parser does, and claims a range only where the version came
// from one.
func TestPipRangeReadsTheLineAsTrivyDoes(t *testing.T) {
	for _, c := range []struct{ line, version, want string }{
		{"pillow>=10.4", "10.4", ">=10.4"},
		{"pillow >= 10.4, < 11", "10.4", ">=10.4,<11"},
		{"pillow~=10.4", "10.4", "~=10.4"},
		{"pillow>=10.*", "10.0", ">=10.*"},
		{"pillow[tiff]>=10.4 ; python_version>'3'", "10.4", ">=10.4"},
		{"pillow>=10.4 --hash=sha256:aaaa", "10.4", ">=10.4"},
		{"pillow>=10.4 \\", "10.4", ">=10.4"},
		// ~= is read before >=, and either before ==.
		{"pillow>=9,~=10.4", "10.4", ">=9,~=10.4"},
		{"pillow==10.4.0,>=10", "10", "==10.4.0,>=10"},
		// A pin is not a range.
		{"pillow==10.4.0", "10.4.0", ""},
		{"pillow!=9.0,==10.4.0", "10.4.0", ""},
		// A line whose range does not start at the version is not the line it was read from.
		{"pillow>=9.0", "10.4", ""},
		{"pillow>=10.*", "10.4", ""},
		// Nothing to read.
		{"# pillow>=10.4", "10.4", ""},
		{"pillow", "10.4", ""},
		{">=10.4", "10.4", ""},
		{"pillow>=10.4", "", ""},
		{"", "10.4", ""},
	} {
		if got := pipRange(c.line, c.version); got != c.want {
			t.Errorf("pipRange(%q, %q) = %q, want %q", c.line, c.version, got, c.want)
		}
	}
}
