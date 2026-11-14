package engine

import (
	"slices"
	"testing"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// unaddressed is one scanner's copy of a flaw in repository repo, with the package URL it wrote,
// none where purl is empty.
func unaddressed(tool, repo, ecosystem, name, version, purl string) sarif.Result {
	rule := "CVE-2021-29937"
	if tool == "grype" {
		rule += "-" + name
	}
	return sarif.Result{
		Tool: tool, RuleID: rule, Level: sarif.LevelError, Score: 9.8, HasScore: true,
		Component: "app", Repository: repo, Location: sarif.Location{URI: "Cargo.lock"},
		Package: &sarif.Package{Name: name, Version: version, Ecosystem: ecosystem, PURL: purl},
	}
}

// countedOf is each finding a run counts, as "<repository> <tool>".
func countedOf(results []sarif.Result) []string {
	var out []string
	for _, r := range results {
		if !r.Correlated() {
			out = append(out, r.Repository+" "+r.Tool)
		}
	}
	slices.Sort(out)
	return out
}

// Grype writes no package URL for a Cargo workspace member and Trivy writes pkg:cargo, so the two
// copies meet on the URL's type, name and version. Each of two repositories counts the flaw once,
// under Trivy's copy, the one reported under the advisory's own id.
func TestACopyWithNoPackageURLMeetsTheCopyWithOne(t *testing.T) {
	var results []sarif.Result
	for _, repo := range []string{"one", "two"} {
		results = append(results,
			unaddressed("trivy", repo, "cargo", "telemetry", "0.1.0", "pkg:cargo/telemetry@0.1.0"),
			unaddressed("grype", repo, "rust-crate", "telemetry", "0.1.0", ""))
	}
	ctrls := controlsWith(results...)
	if groups, _ := applyCorrelation(ctrls); groups != 2 {
		t.Errorf("groups = %d, want one per repository", groups)
	}
	if got, want := countedOf(ctrls["sca"].Report.Results), []string{"one trivy", "two trivy"}; !slices.Equal(got, want) {
		t.Errorf("counted %v, want %v", got, want)
	}
	for _, r := range ctrls["sca"].Report.Results {
		if r.Tool == "grype" && r.Package.PURL != "" {
			t.Errorf("Grype's copy gained a package URL %q; the finding keeps what its scanner wrote", r.Package.PURL)
		}
	}
}

// Copies of a package that do not read as the same one stay apart: another version, the same scanner
// on both sides, a name two URL-keyed flaws share, and a copy in another repository.
func TestACopyWithNoPackageURLStaysApartWhereItIsNotTheSamePackage(t *testing.T) {
	for _, c := range []struct {
		name    string
		results []sarif.Result
		want    []string
	}{
		{"another version", []sarif.Result{
			unaddressed("trivy", "one", "cargo", "telemetry", "0.1.0", "pkg:cargo/telemetry@0.1.0"),
			unaddressed("grype", "one", "rust-crate", "telemetry", "0.1.1", ""),
		}, []string{"one grype", "one trivy"}},
		{"one scanner on both sides", []sarif.Result{
			unaddressed("grype", "one", "rust-crate", "telemetry", "0.1.0", "pkg:cargo/telemetry@0.1.0"),
			unaddressed("grype", "one", "rust-crate", "telemetry", "0.1.0", ""),
		}, []string{"one grype", "one grype"}},
		{"two URLs for the name", []sarif.Result{
			unaddressed("trivy", "one", "cargo", "telemetry", "0.1.0", "pkg:cargo/telemetry@0.1.0"),
			unaddressed("osv", "one", "cargo", "telemetry", "0.1.0", "pkg:cargo/telemetry@0.1.0?repository_url=x"),
			unaddressed("grype", "one", "rust-crate", "telemetry", "0.1.0", ""),
		}, []string{"one grype", "one osv", "one trivy"}},
		{"another repository", []sarif.Result{
			unaddressed("trivy", "one", "cargo", "telemetry", "0.1.0", "pkg:cargo/telemetry@0.1.0"),
			unaddressed("grype", "two", "rust-crate", "telemetry", "0.1.0", ""),
		}, []string{"one trivy", "two grype"}},
		{"an ecosystem with no URL type", []sarif.Result{
			unaddressed("trivy", "one", "cargo", "telemetry", "0.1.0", "pkg:cargo/telemetry@0.1.0"),
			unaddressed("grype", "one", "binary", "telemetry", "0.1.0", ""),
		}, []string{"one grype", "one trivy"}},
	} {
		ctrls := controlsWith(c.results...)
		applyCorrelation(ctrls)
		if got := countedOf(ctrls["sca"].Report.Results); !slices.Equal(got, c.want) {
			t.Errorf("%s: counted %v, want %v", c.name, got, c.want)
		}
	}
}

// Two copies with no package URL meet across the scanners' names for one ecosystem, and the copies of
// a URL-keyed flaw that two scanners already agree on take the copy with none in with them.
func TestCopiesWithNoPackageURLMeetAcrossEcosystemNames(t *testing.T) {
	ctrls := controlsWith(
		unaddressed("trivy", "one", "cargo", "telemetry", "0.1.0", ""),
		unaddressed("grype", "one", "rust-crate", "telemetry", "0.1.0", ""),
		unaddressed("trivy", "two", "cargo", "telemetry", "0.1.0", "pkg:cargo/telemetry@0.1.0"),
		unaddressed("osv", "two", "cargo", "telemetry", "0.1.0", "pkg:cargo/telemetry@0.1.0"),
		unaddressed("grype", "two", "rust-crate", "telemetry", "0.1.0", ""),
	)
	if groups, _ := applyCorrelation(ctrls); groups != 2 {
		t.Errorf("groups = %d, want one per repository", groups)
	}
	// Trivy's and osv's copies tie, both under the advisory's own id, and the tool's name decides.
	if got, want := countedOf(ctrls["sca"].Report.Results), []string{"one trivy", "two osv"}; !slices.Equal(got, want) {
		t.Errorf("counted %v, want %v", got, want)
	}
}

func TestPackageNameKey(t *testing.T) {
	for _, c := range []struct {
		name string
		p    sarif.Package
		want string
		ok   bool
	}{
		{"type from the URL", sarif.Package{Name: "telemetry", Version: "0.1.0", Ecosystem: "whatever", PURL: "pkg:Cargo/telemetry@0.1.0"}, "\x00cargo\x00telemetry\x000.1.0", true},
		{"type from the ecosystem", sarif.Package{Name: "telemetry", Version: "0.1.0", Ecosystem: "rust-crate"}, "\x00cargo\x00telemetry\x000.1.0", true},
		{"an unknown ecosystem as written", sarif.Package{Name: "7-Zip", Version: "26.00", Ecosystem: "binary"}, "\x00binary\x007-Zip\x0026.00", true},
		{"a Go path folded", sarif.Package{Name: "github.com/Azure/go-ntlmssp", Version: "v0.1.0", Ecosystem: "go-module"}, "\x00golang\x00github.com/azure/go-ntlmssp\x00v0.1.0", true},
		{"a Python name folded", sarif.Package{Name: "Typing_Extensions", Version: "4.0", Ecosystem: "python"}, "\x00pypi\x00typing-extensions\x004.0", true},
		{"not a package URL", sarif.Package{Name: "x", Version: "1", Ecosystem: "npm", PURL: "npm:x"}, "\x00npm\x00x\x001", true},
		{"no ecosystem", sarif.Package{Name: "x", Version: "1"}, "", false},
		{"no name", sarif.Package{Version: "1", Ecosystem: "npm"}, "", false},
		{"no version", sarif.Package{Name: "x", Ecosystem: "npm"}, "", false},
	} {
		got, ok := packageNameKey(&c.p)
		if got != c.want || ok != c.ok {
			t.Errorf("%s: packageNameKey = %q, %v; want %q, %v", c.name, got, ok, c.want, c.ok)
		}
	}
	if got := purlType("pkg:cargo"); got != "" {
		t.Errorf("purlType of a URL with no slash = %q, want empty", got)
	}
}
