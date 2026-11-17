package scanners

import (
	"context"
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/controllers"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// testdata/sarif-import/trivy-gomod-two-packages.sarif is three results cut from what Trivy 0.76.1's
// `trivy fs --format sarif` wrote about a Go project, the rules they name kept and its ROOTPATH base
// moved to /src/app: CVE-2026-128085 in go.opentelemetry.io/otel/sdk and again in
// go.opentelemetry.io/otel/trace, and CVE-2026-56864 in golang.org/x/mod. Trivy places every Go
// dependency result at go.mod:1 and names the package only in its message, so the two
// CVE-2026-128085 results differ in nothing but the package.

// importedPackages is each component's imported findings in sca, as rule and package@version → fix,
// for the findings the import counts.
func importedPackages(t *testing.T, comps map[string]importComponent) map[string][]string {
	t.Helper()
	res, _ := runBesideImport(t, controllers.NewSCA(), replayingTrivyFS(t), saga.ControllerSettings{"enabled": true}, comps)
	if len(res.ScanErrors) > 0 {
		t.Fatalf("errors: %v", res.ScanErrors)
	}
	out := map[string][]string{}
	for _, r := range res.Controls["sca"].Report.Results {
		if r.Scanner != plugin.ImportScanner || r.Suppressed() {
			continue
		}
		if r.Package == nil {
			t.Fatalf("%s: imported with no package", r.RuleID)
		}
		out[r.Component] = append(out[r.Component], r.RuleID+" "+r.Package.Name+"@"+r.Package.Version+" → "+r.Package.FixedVersion)
	}
	for comp := range out {
		slices.Sort(out[comp])
	}
	return out
}

// One advisory in two packages, both at go.mod:1 in an imported Trivy SARIF file, is two findings,
// each with its own package and fix, in each of two components.
func TestAnImportedAdvisoryInTwoPackagesAtOneLineStaysTwoFindings(t *testing.T) {
	got := importedPackages(t, twoComponents("trivy-gomod-two-packages.sarif"))
	want := []string{
		"CVE-2026-128085 go.opentelemetry.io/otel/sdk@v1.45.0 → 1.47.0",
		"CVE-2026-128085 go.opentelemetry.io/otel/trace@v1.45.0 → 1.47.0",
		"CVE-2026-56864 golang.org/x/mod@v0.38.0 → 0.40.0",
	}
	for _, comp := range []string{"api", "web"} {
		if !slices.Equal(got[comp], want) {
			t.Errorf("%s: imported\n  %s\nwant\n  %s", comp, strings.Join(got[comp], "\n  "), strings.Join(want, "\n  "))
		}
	}
}

// importFields is the import's provenance fields and detail, by key.
func importFields(t *testing.T, rep sarif.Report) (fields, detail map[string]string) {
	t.Helper()
	if len(rep.Provenance) != 1 {
		t.Fatalf("provenance = %+v, want the import's", rep.Provenance)
	}
	fields, detail = map[string]string{}, map[string]string{}
	for _, f := range rep.Provenance[0].Fields {
		fields[f.Key] = f.Value
	}
	for _, f := range rep.Provenance[0].Detail {
		detail[f.Key] = f.Value
	}
	return fields, detail
}

// A result the file lists twice, the same rule, place and package, is one finding, and the import
// says it counted the repeat once rather than folding it without a word. The file's other results,
// the advisory's second package among them, are each counted, and a file without a repeat says
// nothing about folding.
func TestAnImportCountsARepeatedResultOnceAndSaysSo(t *testing.T) {
	var doc map[string]any
	if err := json.Unmarshal(importTestdata(t, "trivy-gomod-two-packages.sarif"), &doc); err != nil {
		t.Fatal(err)
	}
	run := doc["runs"].([]any)[0].(map[string]any)
	results := run["results"].([]any)
	run["results"] = append(results, results[0])
	twice, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}

	rep, err := NewSARIFImport().Scan(context.Background(), plugin.FileTarget{Path: writeFile(t, string(twice)), Component: "api"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 3 {
		t.Errorf("%d findings, want the three distinct ones", len(rep.Results))
	}
	fields, detail := importFields(t, rep)
	if fields["folded"] != "1 finding repeating another of the file's exactly, counted once" || detail[sarif.ImportFolded] != "1" {
		t.Errorf("fields %v, detail %v, want the one repeat stated", fields, detail)
	}

	rep, err = NewSARIFImport().Scan(context.Background(), plugin.FileTarget{
		Path: filepath.Join("testdata", "sarif-import", "trivy-gomod-two-packages.sarif"), Component: "api"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	fields, detail = importFields(t, rep)
	if _, ok := fields["folded"]; ok || detail[sarif.ImportFolded] != "" || len(rep.Results) != 3 {
		t.Errorf("a file with no repeat: %d findings, fields %v, detail %v", len(rep.Results), fields, detail)
	}
}
