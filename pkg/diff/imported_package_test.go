package diff

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// importedAdvisory is one advisory as an imported Trivy SARIF file states it about pkg: at go.mod:1,
// under the advisory's title, which names no package.
func importedAdvisory(pkg string) sarif.Result {
	return sarif.Result{
		Tool: "Trivy", RuleID: "CVE-2026-128085", Level: sarif.LevelWarning, Message: "OpenTelemetry-Go: Denial of Service",
		Location: sarif.Location{URI: "go.mod", StartLine: 1}, Component: "api", Priority: "P2",
		Scanner: sarif.ImportScanner, Package: &sarif.Package{Name: pkg, Version: "v1.45.0", FixedVersion: "1.47.0"},
	}
}

// The advisory reaching a second package at the same line of an imported file is a new finding, and
// the package it left is fixed. Keyed without the package, the two copies are one, and the change
// reports nothing.
func TestAnImportedAdvisoryInAnotherPackageIsNew(t *testing.T) {
	sdk, trace := importedAdvisory("go.opentelemetry.io/otel/sdk"), importedAdvisory("go.opentelemetry.io/otel/trace")
	d := Compare(report(sdk), report(sdk, trace))
	if got := tally(d); got != [3]int{1, 1, 0} || d.New[0].Package.Name != trace.Package.Name {
		t.Errorf("new, unchanged, fixed = %v, want the trace package new", got)
	}
	d = Compare(report(sdk, trace), report(trace))
	if got := tally(d); got != [3]int{0, 1, 1} || d.Fixed[0].Package.Name != sdk.Package.Name {
		t.Errorf("new, unchanged, fixed = %v, want the sdk package fixed", got)
	}
	d = Compare(report(sdk, trace), report(sdk, trace))
	if got := tally(d); got != [3]int{0, 2, 0} {
		t.Errorf("new, unchanged, fixed = %v, want both unchanged", got)
	}
}
