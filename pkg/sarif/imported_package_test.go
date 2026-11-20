package sarif

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"
)

// importedAt is an imported dependency finding as Trivy's SARIF places one: at go.mod:1, under the
// advisory's title, about pkg.
func importedAt(pkg string) Result {
	return Result{Tool: "Trivy", RuleID: "CVE-2026-128085", Level: LevelWarning, Message: "OpenTelemetry-Go: Denial of Service",
		Location: Location{URI: "go.mod", StartLine: 1}, Component: "api", Scanner: ImportScanner,
		Package: &Package{Name: pkg, Version: "v1.45.0", FixedVersion: "1.47.0"}}
}

// One advisory in two packages at one line of an imported file is two findings with two identities,
// and keeps them across report.json and back.
func TestAnImportedFindingsPackageIsPartOfItsIdentity(t *testing.T) {
	sdk, trace := importedAt("go.opentelemetry.io/otel/sdk"), importedAt("go.opentelemetry.io/otel/trace")
	if sdk.Fingerprint() == trace.Fingerprint() {
		t.Fatal("two imported packages share a fingerprint")
	}
	if got := sdk.ImportedPackage(); got != "go.opentelemetry.io/otel/sdk@v1.45.0" {
		t.Errorf("ImportedPackage() = %q", got)
	}
	if merged := Merge(Report{Results: []Result{sdk, trace}}); len(merged.Results) != 2 {
		t.Errorf("merged into %d results, want both packages", len(merged.Results))
	}

	doc, err := Report{Tool: "Trivy", Results: []Result{sdk}}.MarshalSARIF()
	if err != nil {
		t.Fatal(err)
	}
	back, err := FromSARIF(doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(back.Results) != 1 || back.Results[0].Fingerprint() != sdk.Fingerprint() {
		t.Error("the fingerprint moved across the file")
	}
}

// A native finding, and an imported one about no package, keep the identity they had before the
// package was part of an imported finding's.
func TestOnlyAnImportedFindingsPackageIsPartOfItsIdentity(t *testing.T) {
	legacy := func(r Result) string {
		sum := sha256.Sum256([]byte(strings.Join([]string{r.Tool, r.RuleID, string(r.Level), r.Message,
			r.Location.URI, strconv.Itoa(r.Location.StartLine), r.Component, r.Repository}, "\x00")))
		return hex.EncodeToString(sum[:])
	}
	native := importedAt("go.opentelemetry.io/otel/sdk")
	native.Scanner = "trivy-fs"
	noPackage := importedAt("")
	noPackage.Package = nil
	unnamed := importedAt("")
	for name, r := range map[string]Result{"native": native, "imported, no package": noPackage, "imported, unnamed package": unnamed} {
		if r.ImportedPackage() != "" || r.Fingerprint() != legacy(r) {
			t.Errorf("%s: identity moved", name)
		}
	}
}
