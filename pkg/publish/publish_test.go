package publish

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/report"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/sbom"
)

func sampleData() report.Data {
	run := engine.Result{Controls: map[string]plugin.ControlResult{
		"images": {Control: "images", Report: sarif.Report{Tool: "trivy", Results: []sarif.Result{
			{RuleID: "CVE-1", Level: sarif.LevelError, Priority: "P1", Tool: "trivy"},
		}}},
	}}
	verdict := norn.Result{Verdict: norn.Fail}
	return report.Data{Release: saga.Release{Name: "app", Version: "1.0"}, Run: run, Verdict: verdict}
}

func TestForKnownAndUnknown(t *testing.T) {
	if _, err := For(saga.PublisherConfig{Kind: "file", Dir: "x"}); err != nil {
		t.Errorf("file publisher should resolve: %v", err)
	}
	if _, err := For(saga.PublisherConfig{Kind: "bogus"}); err == nil {
		t.Error("expected error for unknown kind")
	}
}

func TestFilePublisherRequiresDir(t *testing.T) {
	if _, err := For(saga.PublisherConfig{Kind: "file"}); err == nil {
		t.Error("file publisher without dir should error")
	}
}

func TestKinds(t *testing.T) {
	got := Kinds()
	want := []string{"azure-pr-comment", "draugr-api", "file", "github", "github-pr-comment", "gitlab-mr-comment"}
	if len(got) != len(want) {
		t.Fatalf("Kinds() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Kinds()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestRunWritesReports(t *testing.T) {
	dir := t.TempDir()
	err := Run(context.Background(),
		[]saga.ReportConfig{{Format: "json"}, {Format: "sarif"}, {Format: "markdown"}},
		[]saga.PublisherConfig{{Kind: "file", Dir: dir}},
		sampleData(),
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"report.json", "results.sarif", "report.md"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("expected %s to be written: %v", f, err)
		}
	}
}

func TestRunNoPublishersIsNoop(t *testing.T) {
	if err := Run(context.Background(), []saga.ReportConfig{{Format: "json"}}, nil, sampleData()); err != nil {
		t.Errorf("no publishers should be a no-op, got %v", err)
	}
}

func TestRunUnknownFormatErrors(t *testing.T) {
	dir := t.TempDir()
	err := Run(context.Background(),
		[]saga.ReportConfig{{Format: "bogus"}},
		[]saga.PublisherConfig{{Kind: "file", Dir: dir}},
		sampleData(),
	)
	if err == nil {
		t.Error("expected error for unknown report format")
	}
}

func TestRunUnknownPublisherErrors(t *testing.T) {
	err := Run(context.Background(),
		[]saga.ReportConfig{{Format: "json"}},
		[]saga.PublisherConfig{{Kind: "bogus"}},
		sampleData(),
	)
	if err == nil {
		t.Error("expected error for unknown publisher kind")
	}
}

func TestRunPublisherErrorSurfaced(t *testing.T) {
	// A file publisher pointed at a path that can't be created surfaces an error.
	bad := filepath.Join(t.TempDir(), "afile")
	if err := os.WriteFile(bad, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := Run(context.Background(),
		[]saga.ReportConfig{{Format: "json"}},
		[]saga.PublisherConfig{{Kind: "file", Dir: filepath.Join(bad, "sub")}}, // parent is a file
		sampleData(),
	)
	if err == nil {
		t.Error("expected a publish error when the output dir can't be created")
	}
}

func TestRunDeliversSBOMsAlongsideReports(t *testing.T) {
	// SBOMs are produced during the run rather than rendered from Data, so they are appended to
	// the artifact list rather than built. A publisher must see them the same as anything else.
	dir := t.TempDir()
	d := sampleData()
	d.Run.SBOMs = []sbom.Document{
		{Component: "web", Target: "https://git/web", Format: saga.SBOMSPDXJSON, Bytes: []byte(`{"spdxVersion":"SPDX-2.3"}`)},
		{Component: "api", Target: "api:1", Format: saga.SBOMCycloneDXJSON, Bytes: []byte(`{"bomFormat":"CycloneDX"}`)},
	}

	err := Run(context.Background(),
		[]saga.ReportConfig{{Format: "sarif"}},
		[]saga.PublisherConfig{{Kind: "file", Dir: dir}},
		d,
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{
		"results.sarif",
		"sbom-web-https-git-web.spdx.json",
		"sbom-api-api-1.cdx.json",
	} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("expected %s to be written: %v", f, err)
		}
	}
}

func TestRunDeliversSBOMsEvenWithNoReportsConfigured(t *testing.T) {
	// Enabling config.sbom without config.reports is a reasonable thing to want: the inventory
	// is the output. It must not require an unrelated report format to be configured too.
	dir := t.TempDir()
	d := sampleData()
	d.Run.SBOMs = []sbom.Document{{Component: "web", Target: "r", Format: saga.SBOMSPDXJSON, Bytes: []byte("{}")}}

	if err := Run(context.Background(), nil, []saga.PublisherConfig{{Kind: "file", Dir: dir}}, d); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "sbom-web-r.spdx.json")); err != nil {
		t.Errorf("expected the SBOM to be written: %v", err)
	}
}

// A publisher delivers the record, so it gets the whole record. GitHub code scanning resolves
// any alert absent from an upload as fixed — so if --min-priority reached a publisher, running
// a scan with the flag would quietly close every finding below the band, in the one place the
// filtering is invisible.
//
// This is the guard for that. It asserts on delivered bytes rather than on the flag, because the
// flag being cleared is an implementation detail and the alerts being closed is the harm.
func TestPublishersIgnoreMinPriority(t *testing.T) {
	data := sampleData()
	data.Run.Controls["images"] = plugin.ControlResult{
		Control: "images",
		Report: sarif.Report{Tool: "trivy", Results: []sarif.Result{
			{RuleID: "CVE-P1", Level: sarif.LevelError, Priority: "P1", Tool: "trivy"},
			{RuleID: "CVE-P4", Level: sarif.LevelNote, Priority: "P4", Tool: "trivy"},
		}},
	}
	data.MinPriority = "P1"

	dir := t.TempDir()
	if err := Run(context.Background(),
		[]saga.ReportConfig{{Format: "sarif"}},
		[]saga.PublisherConfig{{Kind: "file", Dir: dir}},
		data,
	); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "results.sarif")) //nolint:gosec // a fixed name under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"CVE-P1", "CVE-P4"} {
		if !strings.Contains(string(got), want) {
			t.Errorf("published SARIF is missing %s — a filtered upload resolves it as fixed:\n%s", want, got)
		}
	}
}

// Run takes Data by value, but a caller reusing it afterwards must still see its own flag.
func TestRunDoesNotClearTheCallersMinPriority(t *testing.T) {
	data := sampleData()
	data.MinPriority = "P2"
	if err := Run(context.Background(),
		[]saga.ReportConfig{{Format: "json"}},
		[]saga.PublisherConfig{{Kind: "file", Dir: t.TempDir()}},
		data,
	); err != nil {
		t.Fatal(err)
	}
	if data.MinPriority != "P2" {
		t.Errorf("Run mutated the caller's Data: MinPriority = %q", data.MinPriority)
	}
}

// One format that cannot render must not cost the ones that can.
//
// A scan that took four minutes used to produce no evidence at all because of a typo a descriptor
// check catches in milliseconds — Run returned on the first failed render, before any publisher saw
// anything. The destination loop has always tolerated one failure; this is the same reasoning one
// step earlier.
func TestRunDeliversTheReportsThatRendered(t *testing.T) {
	dir := t.TempDir()
	err := Run(context.Background(),
		[]saga.ReportConfig{{Format: "json"}, {Format: "no-such-format"}, {Format: "sarif"}},
		[]saga.PublisherConfig{{Kind: "file", Dir: dir}},
		sampleData())

	if err == nil {
		t.Fatal("the unrenderable format was not reported")
	}
	if !strings.Contains(err.Error(), "no-such-format") {
		t.Errorf("the error should name the format that failed: %v", err)
	}
	for _, name := range []string{"report.json", "results.sarif"} {
		if _, statErr := os.Stat(filepath.Join(dir, name)); statErr != nil {
			t.Errorf("%s was not delivered, so a good report was lost to a bad one: %v", name, statErr)
		}
	}
}

// Nothing rendered is a different situation: there is no partial delivery to make, and reporting
// only the first reason would hide the rest.
func TestRunReportsEveryFailureWhenNothingRendered(t *testing.T) {
	dir := t.TempDir()
	err := Run(context.Background(),
		[]saga.ReportConfig{{Format: "nope-one"}, {Format: "nope-two"}},
		[]saga.PublisherConfig{{Kind: "file", Dir: dir}},
		sampleData())

	if err == nil {
		t.Fatal("expected an error")
	}
	for _, want := range []string{"nope-one", "nope-two"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error should name %q: %v", want, err)
		}
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Errorf("nothing rendered, so nothing should have been written: %v", entries)
	}
}
