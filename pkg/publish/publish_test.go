package publish

import (
	"bytes"
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
	return report.Data{Release: saga.Release{Version: "1.0"}, Run: run, Verdict: verdict}
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

// A publisher delivers the record, so it gets the whole record. GitHub code scanning resolves any
// alert absent from an upload as fixed, so if --min-priority reached a publisher, running a scan
// with the flag would quietly close every finding below the band, in the one place the filtering is
// invisible.
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
			t.Errorf("published SARIF is missing %s, a filtered upload resolves it as fixed:\n%s", want, got)
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
// check catches in milliseconds. Run returned on the first failed render, before any publisher saw
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

// A publisher that needs a format and does not say so goes back to reporting it at delivery time,
// which is after every scanner has run. Nothing about that looks wrong until somebody spends a
// pipeline on it.
func TestEveryPublisherSaysWhatItNeeds(t *testing.T) {
	for _, kind := range Kinds() {
		if _, ok := requirements[kind]; !ok {
			t.Errorf("%s has no entry in requirements. Name the formats it cannot deliver "+
				"without, or nil if it takes whatever it is handed", kind)
		}
	}
	for kind := range requirements {
		if _, ok := builders[kind]; !ok {
			t.Errorf("requirements names %q, which is not a publisher this build has", kind)
		}
	}
	// Every named format must be one something renders, or the check built on this asks for a
	// report that cannot exist.
	rendered := map[string]bool{}
	for _, f := range report.Formats() {
		rendered[f] = true
	}
	for kind, formats := range requirements {
		for _, f := range formats {
			if !rendered[f] {
				t.Errorf("%s requires %q, which is not a format Draugr renders", kind, f)
			}
		}
	}
}

func TestRequiresIsQuietAboutAKindWeDoNotHave(t *testing.T) {
	if got := Requires("jira"); got != nil {
		t.Errorf("Requires of an unknown kind = %v, want nil", got)
	}
}

// A destination that says nothing about what tells it apart from another of its kind cannot be
// checked for being written twice, and a duplicate is written identically to a deliberate pair.
func TestEveryPublisherSaysWhatDistinguishesIt(t *testing.T) {
	for _, kind := range Kinds() {
		field, ok := distinguishes[kind]
		if !ok || field == "" {
			t.Errorf("%s has no entry in distinguishes. Name the field that makes a second entry "+
				"of this kind a second destination", kind)
		}
	}
	for kind := range distinguishes {
		if _, ok := builders[kind]; !ok {
			t.Errorf("distinguishes names %q, which is not a publisher this build has", kind)
		}
	}
	// Every named field has to be one DistinguishingValue can read, or the check compares two
	// empty strings and calls every pair a duplicate.
	for kind, field := range distinguishes {
		cfg := saga.PublisherConfig{Kind: kind}
		switch field {
		case "dir":
			cfg.Dir = "x"
		case "repo":
			cfg.Repo = "x"
		case "marker":
			cfg.Marker = "x"
		case "url":
			cfg.URL = "x"
		default:
			t.Errorf("%s is distinguished by %q, which DistinguishingValue cannot read", kind, field)
			continue
		}
		if got := DistinguishingValue(cfg); got != "x" {
			t.Errorf("%s: DistinguishingValue read %q from its %s", kind, got, field)
		}
	}
}

// The shape the two lists could not express: write HTML and JSON to a directory, post the markdown
// somewhere else. Every destination used to be handed everything and left to pick out what it
// recognized, so "this file is for the directory and that one is for the comment" had nowhere to be
// said.
func TestADestinationIsHandedWhatItAskedFor(t *testing.T) {
	full, narrowed := t.TempDir(), t.TempDir()
	err := Run(context.Background(),
		nil, // nothing at the project level: each destination says what it takes
		[]saga.PublisherConfig{
			{Kind: "file", Dir: full, Reports: []saga.ReportConfig{{Format: "html"}, {Format: "json"}}},
			{Kind: "file", Dir: narrowed, Reports: []saga.ReportConfig{{Format: "markdown"}}},
		},
		sampleData(),
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"report.html", "report.json"} {
		if _, err := os.Stat(filepath.Join(full, f)); err != nil {
			t.Errorf("the directory that asked for %s did not get it: %v", f, err)
		}
	}
	if _, err := os.Stat(filepath.Join(full, "report.md")); err == nil {
		t.Error("the directory asked for html and json and was given the markdown as well")
	}
	if _, err := os.Stat(filepath.Join(narrowed, "report.md")); err != nil {
		t.Errorf("the directory that asked for markdown did not get it: %v", err)
	}
	for _, f := range []string{"report.html", "report.json"} {
		if _, err := os.Stat(filepath.Join(narrowed, f)); err == nil {
			t.Errorf("the markdown-only directory was given %s", f)
		}
	}
}

// A destination that names no reports keeps taking every one, which is what a descriptor written
// before this meant and still means.
func TestADestinationThatNamesNothingTakesEverything(t *testing.T) {
	dir := t.TempDir()
	err := Run(context.Background(),
		[]saga.ReportConfig{{Format: "json"}, {Format: "markdown"}},
		[]saga.PublisherConfig{{Kind: "file", Dir: dir}},
		sampleData(),
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"report.json", "report.md"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("expected %s: %v", f, err)
		}
	}
}

// One document however many destinations ask for it. Rendering is the expensive half and the
// reason the split is worth keeping inside, now that the descriptor no longer makes an author hold
// it.
func TestOneReportIsRenderedOnceForEveryDestinationAskingForIt(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	data := sampleData()

	// Counting renders directly is not available from here, so the observable stands in: two
	// destinations asking for one format produce identical bytes, which a second render of a
	// report carrying a timestamp would not.
	err := Run(context.Background(), nil,
		[]saga.PublisherConfig{
			{Kind: "file", Dir: a, Reports: []saga.ReportConfig{{Format: "json"}}},
			{Kind: "file", Dir: b, Reports: []saga.ReportConfig{{Format: "json"}}},
		}, data)
	if err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(filepath.Join(a, "report.json")) // #nosec G304 -- a directory this test made
	if err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(filepath.Join(b, "report.json")) // #nosec G304 -- a directory this test made
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Error("two destinations asking for one report were given two different documents")
	}
}
