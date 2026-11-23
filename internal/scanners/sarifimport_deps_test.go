package scanners

import (
	"context"
	"slices"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// The files under testdata/sarif-import/*-deps.sarif are what Trivy 0.76.1, Grype 0.121.0 and
// OSV-Scanner 2.7.1 wrote, unedited, about one project at /src/app holding a package-lock.json that
// pins lodash 4.17.15 and a go.mod that requires golang.org/x/text v0.3.5. Each tool states the
// package, its version and the fix in a place of its own, and these tests hold the import to reading
// each one.

// importedDeps reads one of those files through the import scanner.
func importedDeps(t *testing.T, file string) []sarif.Result {
	t.Helper()
	rep, err := NewSARIFImport().Scan(context.Background(), plugin.FileTarget{Path: "testdata/sarif-import/" + file}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) == 0 {
		t.Fatalf("%s: no results", file)
	}
	return rep.Results
}

// byRule is the first result under a rule id.
func byRule(t *testing.T, results []sarif.Result, rule string) sarif.Result {
	t.Helper()
	for _, r := range results {
		if r.RuleID == rule {
			return r
		}
	}
	t.Fatalf("no result for %s", rule)
	return sarif.Result{}
}

// Every dependency finding in each tool's file carries its package, and the fix the tool states.
func TestSARIFImportReadsThePackageEachToolStates(t *testing.T) {
	for _, c := range []struct {
		file, rule string
		want       sarif.Package
	}{
		// Trivy states the package, the installed version and the fix only in each result's message.
		// The ecosystem is the dependency file's, which orders the versions an upgrade picks from.
		{"trivy-deps.sarif", "CVE-2021-38561",
			sarif.Package{Name: "golang.org/x/text", Version: "v0.3.5", FixedVersion: "0.3.7", Ecosystem: "gomod"}},
		{"trivy-deps.sarif", "CVE-2020-8203",
			sarif.Package{Name: "lodash", Version: "4.17.15", FixedVersion: "4.17.19", Ecosystem: "npm"}},
		// An advisory with no CVE, which Trivy writes as a bound.
		{"trivy-deps.sarif", "NSWG-ECO-516",
			sarif.Package{Name: "lodash", Version: "4.17.15", FixedVersion: ">=4.17.19", Ecosystem: "npm"}},
		// Grype states the package as a package URL on the rule, one rule per advisory and package,
		// and the fix in the rule's help.
		{"grype-deps.sarif", "GHSA-35jh-r3h4-6jhm-lodash",
			sarif.Package{Name: "lodash", Version: "4.17.15", FixedVersion: "4.17.21", PURL: "pkg:npm/lodash@4.17.15", Ecosystem: "npm"}},
		{"grype-deps.sarif", "GO-2026-5970-golang.org/x/text",
			sarif.Package{Name: "golang.org/x/text", Version: "v0.3.5", FixedVersion: "0.39.0",
				PURL: "pkg:golang/golang.org/x/text@v0.3.5", Ecosystem: "golang"}},
		// OSV-Scanner states the package in the message and the fix in a table in the rule's help,
		// which lists lodash-es and lodash-rails beside lodash at other fixed versions. It writes a Go
		// module's version without the "v", 0.3.5, which is read as go.mod writes it, as Trivy's and
		// Grype's are; the fix is kept as written, as theirs is.
		{"osv-scanner-deps.sarif", "CVE-2020-8203",
			sarif.Package{Name: "lodash", Version: "4.17.15", FixedVersion: "4.17.19", Ecosystem: "npm"}},
		{"osv-scanner-deps.sarif", "CVE-2022-32149",
			sarif.Package{Name: "golang.org/x/text", Version: "v0.3.5", FixedVersion: "0.3.8", Ecosystem: "gomod"}},
	} {
		r := byRule(t, importedDeps(t, c.file), c.rule)
		if r.Package == nil || *r.Package != c.want {
			t.Errorf("%s %s: package = %+v, want %+v", c.file, c.rule, r.Package, c.want)
		}
	}
	for _, file := range []string{"trivy-deps.sarif", "grype-deps.sarif", "osv-scanner-deps.sarif"} {
		for _, r := range importedDeps(t, file) {
			if r.Package == nil || r.Package.FixedVersion == "" {
				t.Errorf("%s %s: package = %+v, want one with the fix the file states", file, r.RuleID, r.Package)
			}
		}
	}
}

// The identifiers a file lists for an advisory become the finding's aliases, so KEV and EPSS reach a
// finding by its CVE and correlation knows its other names. OSV-Scanner lists them as the rule's
// deprecated ids; Trivy and Grype list none, and their findings get none.
func TestSARIFImportReadsTheAliasesAFileStates(t *testing.T) {
	osv := importedDeps(t, "osv-scanner-deps.sarif")
	if got, want := byRule(t, osv, "CVE-2022-32149").Aliases, []string{"GO-2022-1059", "GHSA-69ch-w2m2-3vjp"}; !slices.Equal(got, want) {
		t.Errorf("aliases = %q, want %q", got, want)
	}
	for _, file := range []string{"trivy-deps.sarif", "grype-deps.sarif"} {
		for _, r := range importedDeps(t, file) {
			if len(r.Aliases) != 0 {
				t.Errorf("%s %s: aliases = %q, want none, the file stating none", file, r.RuleID, r.Aliases)
			}
		}
	}
}
