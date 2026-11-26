package scanners

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// The tool JSON these tests import is recorded output already under testdata:
//
//   - sarif-import/trivy-fs-gomod.json, Trivy 0.76.1's `trivy fs --format json --list-all-pkgs`
//     over a go.mod of module example.com/app that requires golang.org/x/text v0.3.5;
//   - govulncheck-reachable.json, govulncheck's stream over module example.com/reach, which calls
//     a vulnerable function of golang.org/x/text v0.3.0.

// appGoMod is the go.mod Trivy read for trivy-fs-gomod.json.
const appGoMod = "module example.com/app\n\ngo 1.22\n\nrequire golang.org/x/text v0.3.5\n"

// reachGoMod and reachMain are the module govulncheck read for govulncheck-reachable.json.
const (
	reachGoMod = "module example.com/reach\n\ngo 1.22\n\nrequire golang.org/x/text v0.3.0\n"
	reachMain  = "package main\n\nfunc main() {}\n"
)

// checkoutWith is a directory holding files, by name, as a component's local repository.
func checkoutWith(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// copiedAt writes data to a file of its own last written at, so a verdict dated by the file's day
// can be compared with a native run dated the same.
func copiedAt(t *testing.T, data []byte, at time.Time) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "tool.json")
	if err := os.WriteFile(p, data, 0o600); err != nil { // #nosec G703 -- a file of the test's own temporary directory
		t.Fatal(err)
	}
	if err := os.Chtimes(p, at, at); err != nil {
		t.Fatal(err)
	}
	return p
}

// asNative is an imported result with what only the import sets taken off, to compare with the
// finding the native parser makes of the same file.
func asNative(r sarif.Result) sarif.Result {
	r.ImportFormat, r.ImportedRepository = "", ""
	return r
}

// Trivy's JSON read through the import is, finding by finding, what trivy-fs's parser makes of the
// same file over the same checkout: the advisory, the package and its installed and fixed versions,
// the package URL, the CVSS score and the level, the line of the package's entry and the other
// identifiers Trivy names. The report names the format beside the tool.
func TestAnImportedTrivyJSONIsTheFindingTrivyFSMakesOfIt(t *testing.T) {
	dir := checkoutWith(t, map[string]string{"go.mod": appGoMod})
	data := importTestdata(t, "trivy-fs-gomod.json")
	native, err := parseTrivyVulns(data, dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	ft := plugin.FileTarget{Path: filepath.Join("testdata", "sarif-import", "trivy-fs-gomod.json"), Format: saga.ImportFormatTrivyJSON,
		Component: "app", Repositories: []plugin.RepositoryTarget{{URL: dir}}}
	rep, err := NewSARIFImport().Scan(context.Background(), ft, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != len(native.Results) || len(rep.Results) != 4 {
		t.Fatalf("imported %d findings, native %d, want Trivy's four", len(rep.Results), len(native.Results))
	}
	for i, got := range rep.Results {
		if got.ImportFormat != saga.ImportFormatTrivyJSON || got.ImportedRepository == "" {
			t.Errorf("%s: format %q, repository %q, want trivy-json placed in the component's repository",
				got.RuleID, got.ImportFormat, got.ImportedRepository)
		}
		if !reflect.DeepEqual(asNative(got), native.Results[i]) {
			t.Errorf("imported %+v\nnative   %+v", asNative(got), native.Results[i])
		}
	}
	first := rep.Results[0]
	if first.RuleID != "CVE-2021-38561" || first.Package == nil || first.Package.Name != "golang.org/x/text" ||
		first.Package.Version != "v0.3.5" || first.Package.FixedVersion != "0.3.7" ||
		first.Package.PURL != "pkg:golang/golang.org/x/text@v0.3.5" || first.Location.URI != "go.mod" || first.Location.StartLine != 5 {
		t.Errorf("first finding %+v, package %+v", first, first.Package)
	}
	if first.Severity("") != sarif.SeverityHigh || !first.HasScore {
		t.Errorf("CVE-2021-38561 rated %s (scored %v), want Trivy's CVSS score, high", first.Severity(""), first.HasScore)
	}
	first.Scanner = plugin.ImportScanner
	if got := first.Reporter(); got != "imported trivy (trivy-json)" {
		t.Errorf("reporter = %q", got)
	}
	for key, want := range map[string]string{
		"tool": "trivy 0.76.1", "format": "trivy-json", "written": "2026-11-17 00:48 UTC", "severity": "CVSS score", "commit": notStated,
	} {
		if got := field(t, rep, key); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
	if len(rep.Inputs) != 0 || len(rep.Inventory) != 0 {
		t.Errorf("inputs %v, inventory %d: an import accounts for no tree of this machine's", rep.Inputs, len(rep.Inventory))
	}
}

// govulncheck's JSON read through the import is what govulncheck's parser makes of the same stream:
// the advisory under its CVE, the module, its fixed version and the verdict with its call path,
// located at the go.mod of the module the run analyzed and dated by the day the file was written.
// One difference: govulncheck's JSON does not say which platform its run built for, so an imported
// unreachable verdict names no build, where Draugr's own run names the one it analyzed.
func TestAnImportedGovulncheckJSONIsTheFindingGovulncheckMakesOfIt(t *testing.T) {
	dir := checkoutWith(t, map[string]string{"go.mod": reachGoMod, "main.go": reachMain})
	data, err := os.ReadFile(filepath.Join("testdata", "govulncheck-reachable.json"))
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 11, 3, 9, 0, 0, 0, time.UTC)
	native, err := parseGovulncheckAt(data, dir, at)
	if err != nil {
		t.Fatal(err)
	}
	// Bound to the commit this run reads, so its verdicts are about this code.
	ft := plugin.FileTarget{Path: copiedAt(t, data, at), Format: saga.ImportFormatGovulncheckJSON, Component: "app",
		Repositories: []plugin.RepositoryTarget{{URL: dir}}, Commit: boundHead}
	rep, err := boundImport().Scan(context.Background(), ft, nil)
	if err != nil {
		t.Fatal(err)
	}
	if field(t, rep, "commit") != boundHead[:12] {
		t.Fatalf("commit = %q, want the file bound", field(t, rep, "commit"))
	}
	if len(rep.Results) == 0 || len(rep.Results) != len(native.Results) {
		t.Fatalf("imported %d findings, native %d", len(rep.Results), len(native.Results))
	}
	for i, got := range rep.Results {
		want := native.Results[i]
		if r := want.Reachability; r != nil && r.State == sarif.ReachabilityUnreachable {
			if r.Build == nil || len(r.Build.Platforms) == 0 {
				t.Errorf("%s: Draugr's own unreachable verdict names no build", want.RuleID)
			}
			if got.Reachability != nil && got.Reachability.Build != nil {
				t.Errorf("%s: an imported verdict names build %v the file never stated", got.RuleID, got.Reachability.Build)
			}
			unnamed := *r
			unnamed.Build = nil
			want.Reachability = &unnamed
		}
		if !reflect.DeepEqual(asNative(got), want) {
			t.Errorf("imported %+v\nnative   %+v", asNative(got), want)
		}
	}
	byRule := map[string]sarif.Result{}
	for _, r := range rep.Results {
		byRule[r.RuleID] = r
	}
	// GO-2020-0015, in a module the run built and never called, and GO-2021-0113, called from main.
	unreached, called := byRule["CVE-2020-14040"], byRule["CVE-2021-38561"]
	if unreached.Package == nil || unreached.Package.Name != "golang.org/x/text" || unreached.Package.FixedVersion != "0.3.3" ||
		unreached.Location.URI != "go.mod" || unreached.Reachability == nil || unreached.Reachability.State != sarif.ReachabilityUnreachable {
		t.Errorf("CVE-2020-14040: %+v, package %+v", unreached, unreached.Package)
	}
	reach := called.Reachability
	if called.Package == nil || called.Package.FixedVersion != "0.3.7" || reach == nil || reach.State != sarif.ReachabilityReachable ||
		len(reach.Paths) == 0 || reach.Analyzer != govulncheckScanner || reach.AsOf != "2026-11-03" {
		t.Errorf("CVE-2021-38561: package %+v, reachability %+v, want govulncheck's reachable verdict with its call path, "+
			"dated by the file", called.Package, reach)
	}
	if called.Severity("") != sarif.SeverityMedium {
		t.Errorf("rated %s, want medium, as govulncheck's own finding", called.Severity(""))
	}
	for key, want := range map[string]string{
		"tool": "govulncheck", "format": "govulncheck-json", "severity": "govulncheck states none, read as medium",
	} {
		if got := field(t, rep, key); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
	if len(rep.PackageVerdicts) != 0 {
		t.Errorf("package verdicts %+v: the not-built mark describes this machine's build, not the file's", rep.PackageVerdicts)
	}
}

// boundHead is the commit boundImport says this run reads.
const boundHead = "0123456789abcdef0123456789abcdef01234567"

// boundImport is the import scanner reading every repository at boundHead.
func boundImport() sarifImport {
	return sarifImport{resolve: func(context.Context, string, string) (string, error) { return boundHead, nil }}
}

// An unbound govulncheck file's unreachable verdict is undetermined, since nothing shows its run
// analyzed this code, and its message says why; a reachable verdict stays. Bound, the same file
// keeps both, as TestAnImportedGovulncheckJSONIsTheFindingGovulncheckMakesOfIt shows.
func TestAnUnboundGovulncheckFileDecidesNothingUnreachable(t *testing.T) {
	path := copiedAt(t, mustRead(t, filepath.Join("testdata", "govulncheck-reachable.json")), time.Now())
	for _, c := range []struct {
		name   string
		repos  []plugin.RepositoryTarget
		commit string
	}{
		{"no commit", []plugin.RepositoryTarget{{URL: "https://github.com/acme/api"}}, ""},
		{"two repositories", []plugin.RepositoryTarget{{URL: "https://github.com/acme/api"}, {URL: "https://github.com/acme/web"}}, boundHead},
	} {
		rep, err := boundImport().Scan(context.Background(),
			plugin.FileTarget{Path: path, Format: saga.ImportFormatGovulncheckJSON, Repositories: c.repos, Commit: c.commit}, nil)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		states := map[string]sarif.ReachabilityState{}
		for _, r := range rep.Results {
			states[r.RuleID] = r.Reachability.State
			if r.RuleID == "CVE-2020-14040" &&
				!strings.HasSuffix(r.Message, ", reachability not determined: the file is bound to no commit") {
				t.Errorf("%s: message %q", c.name, r.Message)
			}
		}
		if states["CVE-2020-14040"] != sarif.ReachabilityUnknown || states["CVE-2021-38561"] != sarif.ReachabilityReachable {
			t.Errorf("%s: states %v, want the unreachable verdict undetermined and the reachable one kept", c.name, states)
		}
	}
}

// A module in a subdirectory is located at its own go.mod, found from the packages the run started
// from, as a native run locates it; with no local checkout the finding is at go.mod.
func TestAnImportedGovulncheckRunIsLocatedAtItsModule(t *testing.T) {
	dir := checkoutWith(t, map[string]string{"services/reach/go.mod": reachGoMod, "services/reach/main.go": reachMain})
	data, err := os.ReadFile(filepath.Join("testdata", "govulncheck-reachable.json"))
	if err != nil {
		t.Fatal(err)
	}
	path := copiedAt(t, data, time.Now())
	for _, c := range []struct {
		name  string
		repos []plugin.RepositoryTarget
		want  string
	}{
		{"a local checkout", []plugin.RepositoryTarget{{URL: dir}}, "services/reach/go.mod"},
		{"a remote repository", []plugin.RepositoryTarget{{URL: "https://github.com/acme/reach"}}, "go.mod"},
	} {
		rep, err := NewSARIFImport().Scan(context.Background(),
			plugin.FileTarget{Path: path, Format: saga.ImportFormatGovulncheckJSON, Repositories: c.repos}, nil)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		for _, r := range rep.Results {
			if r.Location.URI != c.want {
				t.Errorf("%s: %s at %s, want %s", c.name, r.RuleID, r.Location.URI, c.want)
			}
		}
	}
}

// A tool's JSON names no commit, so only the import's commit binds it: the same commit binds it,
// another is refused naming both, none leaves it unbound, and in a component of two repositories
// the commit binds nothing, since the file cannot say which repository it is in.
func TestAnImportedToolJSONIsHeldToTheDescriptorsCommit(t *testing.T) {
	const (
		head  = "0123456789abcdef0123456789abcdef01234567"
		other = "fedcba9876543210fedcba9876543210fedcba98" // a commit this run does not read
	)
	scanner := sarifImport{resolve: func(context.Context, string, string) (string, error) { return head, nil }}
	one := []plugin.RepositoryTarget{{URL: "https://github.com/acme/api"}}
	two := []plugin.RepositoryTarget{{URL: "https://github.com/acme/api"}, {URL: "https://github.com/acme/web"}}
	govulncheck := copiedAt(t, mustRead(t, filepath.Join("testdata", "govulncheck-reachable.json")), time.Now())
	for _, f := range []struct{ format, path string }{
		{saga.ImportFormatTrivyJSON, filepath.Join("testdata", "sarif-import", "trivy-fs-gomod.json")},
		{saga.ImportFormatGovulncheckJSON, govulncheck},
		{saga.ImportFormatGrypeJSON, grypeLodash},
		{saga.ImportFormatOSVScannerJSON, osvLodash},
	} {
		for _, c := range []struct {
			name   string
			repos  []plugin.RepositoryTarget
			commit string
			want   string // the commit field, or the error
			fails  bool
		}{
			{"no commit", one, "", notStated, false},
			{"the commit this run reads", one, head[:10], "0123456789ab", false},
			{"another commit", one, other, "scanned fedcba987654, this run reads 0123456789ab. Run the tool again", true},
			{"two repositories", two, head, "not stated, " + f.format + " names no repository and the component has several", false},
		} {
			ft := plugin.FileTarget{Path: f.path, Format: f.format, Component: "api", Repositories: c.repos, Commit: c.commit}
			rep, err := scanner.Scan(context.Background(), ft, nil)
			if c.fails {
				if err == nil || !strings.Contains(err.Error(), c.want) {
					t.Errorf("%s, %s: err = %v, want %q", f.format, c.name, err, c.want)
				}
				continue
			}
			if err != nil {
				t.Fatalf("%s, %s: %v", f.format, c.name, err)
			}
			if got := field(t, rep, "commit"); got != c.want {
				t.Errorf("%s, %s: commit = %q, want %q", f.format, c.name, got, c.want)
			}
		}
	}
}

// mustRead reads a file under testdata.
func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path) // #nosec G304 -- under testdata
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A tool's JSON is placed and scoped as a SARIF file is: in a component of one repository its
// findings are in it and its paths: leave out what lies outside them, and in a component of two
// they are in neither, kept whole and counted as not scoped, with a remedy the JSON can follow.
func TestAnImportedToolJSONIsPlacedAndScopedByTheComponentsRepositories(t *testing.T) {
	ft := plugin.FileTarget{Path: filepath.Join("testdata", "sarif-import", "trivy-fs-gomod.json"), Format: saga.ImportFormatTrivyJSON}

	ft.Repositories = []plugin.RepositoryTarget{{URL: "https://github.com/acme/api", Paths: []string{"web"}}}
	rep, err := NewSARIFImport().Scan(context.Background(), ft, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 0 || field(t, rep, "left out") != "4 findings outside paths, not counted" {
		t.Errorf("one repository scoped to web/: %d findings kept, left out %q", len(rep.Results), field(t, rep, "left out"))
	}

	ft.Repositories = []plugin.RepositoryTarget{
		{URL: "https://github.com/acme/api", Paths: []string{"web"}},
		{URL: "https://github.com/acme/web", Paths: []string{"web"}},
	}
	rep, err = NewSARIFImport().Scan(context.Background(), ft, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 4 {
		t.Fatalf("two repositories: %d findings kept, want all four, unscoped", len(rep.Results))
	}
	for _, r := range rep.Results {
		if r.ImportedRepository != "" {
			t.Errorf("%s placed in %s, which the file does not name", r.RuleID, r.ImportedRepository)
		}
	}
	want := "4 findings, not in any one repository, so paths and ignore were not applied. " +
		"Move the trivy-json import to a component with one repository"
	if got := field(t, rep, "not scoped"); got != want {
		t.Errorf("not scoped = %q, want %q", got, want)
	}
}

// An absolute path in a tool's JSON is made relative to the checkout holding it, and one in no
// checkout is kept as written and listed once as an input the path rules do not reach.
func TestAnImportedToolJSONPlacesAbsolutePaths(t *testing.T) {
	dir := checkoutWith(t, map[string]string{"go.mod": appGoMod})
	results := []sarif.Result{
		{Location: sarif.Location{URI: filepath.Join(dir, "go.mod")}},
		{Location: sarif.Location{URI: "file:///elsewhere/go.mod"}},
		{Location: sarif.Location{URI: "/elsewhere/go.mod"}},
		{Location: sarif.Location{URI: "go.mod"}},
	}
	outside := relativeToCheckouts(results, []string{dir})
	if results[0].Location.URI != "go.mod" || results[1].Location.URI != "/elsewhere/go.mod" || results[3].Location.URI != "go.mod" {
		t.Errorf("paths %+v", results)
	}
	if !reflect.DeepEqual(outside, []string{"/elsewhere/go.mod"}) {
		t.Errorf("outside = %v", outside)
	}
}

// A Trivy file is read in the control its scan belongs to: an image scan in images, a filesystem scan
// in sca. In the other, its findings would read as that control's, so the file is refused.
func TestATrivyFileIsReadInTheControlItsScanBelongsTo(t *testing.T) {
	image := filepath.Join("testdata", "sarif-import", "trivy-image-alpine.json")
	fs := filepath.Join("testdata", "sarif-import", "trivy-fs-gomod.json")
	for _, c := range []struct{ name, path, control, want string }{
		{"an image scan in images", image, "images", ""},
		{"a filesystem scan in sca", fs, "sca", ""},
		{"an image scan in sca", image, "sca", "an image scan; import it into images"},
		{"a filesystem scan in images", fs, "images", "a filesystem scan; images reads trivy image --format json"},
	} {
		rep, err := NewSARIFImport().Scan(context.Background(), plugin.FileTarget{Path: c.path,
			Format: saga.ImportFormatTrivyJSON, Control: c.control}, nil)
		switch {
		case c.want == "" && (err != nil || len(rep.Results) == 0):
			t.Errorf("%s: %d findings, err %v, want the file read", c.name, len(rep.Results), err)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
			t.Errorf("%s: err = %v, want %q", c.name, err, c.want)
		}
	}
	if err := trivyImportControl("", "images"); err == nil || !strings.Contains(err.Error(), "a Trivy scan;") {
		t.Errorf("no ArtifactType in images: %v", err)
	}
}

// A file that is not the format the import names is refused, rather than read as a clean scan, in
// words the errors block keeps whole: its last clause, within 80 characters.
func TestAnImportRefusesAFileThatIsNotItsFormat(t *testing.T) {
	sarifLog := exampleLog(scoredResult, "")
	for _, c := range []struct{ name, format, body, want string }{
		{"SARIF as Trivy JSON", saga.ImportFormatTrivyJSON, sarifLog, "not Trivy JSON. Write it with trivy fs --format json"},
		{"not JSON as Trivy JSON", saga.ImportFormatTrivyJSON, "not json", "not Trivy JSON. Write it with trivy fs --format json"},
		{"a mistyped Trivy JSON", saga.ImportFormatTrivyJSON, `{"SchemaVersion":2,"Results":"none"}`, "not Trivy JSON"},
		{"another Trivy schema", saga.ImportFormatTrivyJSON, `{"SchemaVersion":3,"Results":[]}`, "schema 3 Trivy JSON; Draugr reads schema 2"},
		{"SARIF as govulncheck JSON", saga.ImportFormatGovulncheckJSON, sarifLog, "not govulncheck JSON. Write it with govulncheck -format json"},
		{"not JSON as govulncheck JSON", saga.ImportFormatGovulncheckJSON, "{not json", "not govulncheck JSON"},
		{"Trivy JSON as govulncheck JSON", saga.ImportFormatGovulncheckJSON, `{"SchemaVersion":2,"Results":[]}`, "not govulncheck JSON"},
		{"SARIF as Grype JSON", saga.ImportFormatGrypeJSON, sarifLog, "not Grype JSON. Write it with grype dir:. -o json"},
		{"SARIF as OSV-Scanner JSON", saga.ImportFormatOSVScannerJSON, sarifLog, "not OSV-Scanner JSON. Write it with osv-scanner scan --format json"},
		{"an unknown format", "sarif-2.0", sarifLog, "format sarif-2.0 is not one Draugr reads. draugr validate lists them"},
		{"no converter declared", saga.ImportFormatConverter, sarifLog, "declares no converter. Add converter to the import"},
	} {
		_, err := NewSARIFImport().Scan(context.Background(), plugin.FileTarget{Path: writeFile(t, c.body), Format: c.format}, nil)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", c.name, err, c.want)
			continue
		}
		parts := strings.Split(err.Error(), ": ")
		if last := parts[len(parts)-1]; len(last) > 80 {
			t.Errorf("%s: the errors block's reason %q is %d characters", c.name, last, len(last))
		}
	}
	// A clean govulncheck run, a config and no findings, is a clean result rather than a refusal.
	rep, err := NewSARIFImport().Scan(context.Background(),
		plugin.FileTarget{Path: writeFile(t, `{"config":{"scanner_name":"govulncheck","scanner_version":"v1.1.4","scan_level":"symbol"}}`),
			Format: saga.ImportFormatGovulncheckJSON}, nil)
	if err != nil || len(rep.Results) != 0 || field(t, rep, "tool") != "govulncheck v1.1.4" || field(t, rep, "severity") != "no findings" {
		t.Errorf("a clean run: %v, %+v", err, rep.Provenance)
	}
}

// Trivy's own rating is named where a finding has no CVSS score, as the severity it was read from.
func TestAnImportedTrivyJSONSaysWhereSeveritiesCameFrom(t *testing.T) {
	doc := `{"SchemaVersion":2,"Results":[{"Target":"go.mod","Class":"lang-pkgs","Type":"gomod","Vulnerabilities":[
{"VulnerabilityID":"CVE-2026-0001","PkgName":"a","InstalledVersion":"1.0.0","Severity":"CRITICAL","CVSS":{"nvd":{"V3Score":9.8}}},
{"VulnerabilityID":"CVE-2026-0002","PkgName":"b","InstalledVersion":"1.0.0","Severity":"HIGH"}]}]}`
	rep, err := NewSARIFImport().Scan(context.Background(), plugin.FileTarget{Path: writeFile(t, doc), Format: saga.ImportFormatTrivyJSON}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := field(t, rep, "severity"); got != "CVSS score for 1, Trivy's severity for 1" {
		t.Errorf("severity = %q", got)
	}
	if got := field(t, rep, "written"); !strings.Contains(got, "modification time") {
		t.Errorf("written = %q, want the file's modification time, the file stating no CreatedAt", got)
	}
}

// Doctor describes a file by the reader the scan uses, so a file the scan would refuse fails it with
// the same words.
func TestDescribeImportReadsEachFormat(t *testing.T) {
	govulncheck := mustRead(t, filepath.Join("testdata", "govulncheck-reachable.json"))
	for _, c := range []struct {
		format string
		data   []byte
		want   string
	}{
		{"", importTestdata(t, "trivy-deps.sarif"), "SARIF 2.1.0, "},
		{saga.ImportFormatSARIF, []byte(exampleLog(scoredResult, "")), "SARIF 2.1.0, 1 result"},
		{saga.ImportFormatTrivyJSON, importTestdata(t, "trivy-fs-gomod.json"), "Trivy JSON, 4 findings"},
		{saga.ImportFormatGovulncheckJSON, govulncheck, "govulncheck JSON, "},
		{saga.ImportFormatGrypeJSON, importTestdata(t, "grype-dir-lodash.json"), "Grype JSON, 4 findings"},
		{saga.ImportFormatOSVScannerJSON, importTestdata(t, "osv-scanner-lodash.json"), "OSV-Scanner JSON, 4 findings"},
	} {
		got, err := DescribeImport(c.data, c.format)
		if err != nil || !strings.HasPrefix(got, c.want) {
			t.Errorf("%q: %q, %v, want %q", c.format, got, err, c.want)
		}
	}
	if _, err := DescribeImport([]byte(exampleLog(scoredResult, "")), saga.ImportFormatTrivyJSON); err == nil ||
		!strings.Contains(err.Error(), "not Trivy JSON") {
		t.Errorf("SARIF described as Trivy JSON: %v", err)
	}
}

// DescribeBound adds the commit the scan holds a file to, and refuses one written for another
// commit with the scan's error, a file that does not read with its reader's, and passes on what
// resolving the commit returned.
func TestDescribeBoundHoldsAFileToTheCommit(t *testing.T) {
	const head = "0123456789abcdef0123456789abcdef01234567"
	resolve := func(context.Context, string, string) (string, error) { return head, nil }
	data := []byte(exampleLog(scoredResult, ""))
	ft := plugin.FileTarget{Component: "api", Repositories: []plugin.RepositoryTarget{{URL: "."}}}
	for _, c := range []struct {
		commit, want string
	}{
		{head[:7], "SARIF 2.1.0, 1 result, commit 0123456789ab"},
		{"", "SARIF 2.1.0, 1 result, commit not stated. The scan lists it under unbound-imports"},
	} {
		ft.Commit = c.commit
		if got, err := DescribeBound(context.Background(), data, ft, resolve); err != nil || got != c.want {
			t.Errorf("commit %q: %q, %v, want %q", c.commit, got, err, c.want)
		}
	}
	ft.Commit = "fedcba9876543210"
	if _, err := DescribeBound(context.Background(), data, ft, resolve); err == nil ||
		!strings.Contains(err.Error(), "scanned fedcba987654, this run reads 0123456789ab") {
		t.Errorf("another commit: %v", err)
	}
	if _, err := DescribeBound(context.Background(), []byte("junk"), ft, resolve); err == nil {
		t.Error("junk described")
	}
	offline := errors.New("not checked")
	refuse := func(context.Context, string, string) (string, error) { return "", offline }
	ft.Commit = head
	if _, err := DescribeBound(context.Background(), data, ft, refuse); !errors.Is(err, offline) {
		t.Errorf("resolve's error: %v, want it wrapped", err)
	}
}
