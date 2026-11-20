package publish

import (
	"bytes"
	"context"
	"log/slog"
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
)

// A run holding findings on an image and a host, beside one on a file, uploads with every location in
// a form code scanning accepts. Code scanning refuses a whole upload over one location it cannot
// parse, so a single image finding would otherwise keep every finding of the run, the file's
// included, out of the Security tab. results.sarif, written from the same render, keeps the image
// reference as the finding's location, because `draugr diff` reads a finding's identity from it.
func TestGithubPublisherUploadsNoLocationCodeScanningRefuses(t *testing.T) {
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	fake := &fakeCodeScanning{t: t}
	ghEnv(t, startFake(t, fake))
	dir := t.TempDir()
	const image = "python:3.8-slim"
	run := engine.Result{Controls: map[string]plugin.ControlResult{
		"images": {Control: "images", Report: sarif.Report{Tool: "trivy", Results: []sarif.Result{{
			RuleID: "CVE-2023-0464", Level: sarif.LevelError, Priority: "P2", Tool: "trivy", Control: "images",
			Message: "openssl: denial of service", Location: sarif.Location{URI: image}, Image: image,
		}}}},
		"tls": {Control: "tls", Report: sarif.Report{Tool: "testssl", Results: []sarif.Result{{
			RuleID: "TLS1", Level: sarif.LevelWarning, Priority: "P3", Tool: "testssl", Control: "tls",
			Message: "TLS 1.0 offered", Location: sarif.Location{URI: "https://example.com/login"},
		}}}},
		"sast": {Control: "sast", Report: sarif.Report{Tool: "semgrep", Results: []sarif.Result{{
			RuleID: "go.sqli", Level: sarif.LevelError, Priority: "P1", Tool: "semgrep", Control: "sast",
			Message: "SQL built from input", Location: sarif.Location{URI: "cmd/api/main.go", StartLine: 42},
		}}}},
	}}
	data := report.Data{Release: saga.Release{Version: "1.0"}, Run: run, Verdict: norn.Result{Verdict: norn.Fail}}
	if err := Run(context.Background(), []saga.PublisherConfig{
		{Kind: "file", Dir: dir, Reports: []saga.ReportConfig{{Format: "sarif"}}},
		{Kind: "github"},
	}, data); err != nil {
		t.Fatal(err)
	}

	refused, err := sarif.CodeScanningRefuses(fake.uploaded)
	if err != nil {
		t.Fatal(err)
	}
	if len(refused) > 0 {
		t.Errorf("the upload carries locations code scanning refuses: %q", refused)
	}
	if got := resultsOf(t, fake.uploaded); len(got) != 3 {
		t.Errorf("uploaded %d results, want all 3: a finding with no file is still uploaded", len(got))
	}
	if !strings.Contains(string(fake.uploaded), `"uri":"cmd/api/main.go"`) {
		t.Errorf("the file finding lost its location:\n%s", fake.uploaded)
	}
	if !strings.Contains(logs.String(), "findings=2") {
		t.Errorf("the publish does not say how many findings code scanning will not show:\n%s", logs.String())
	}

	onDisk, err := os.ReadFile(filepath.Join(dir, "results.sarif")) // #nosec G304 -- a fixed name under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	if kept, _ := sarif.CodeScanningRefuses(onDisk); !strings.Contains(strings.Join(kept, " "), image) {
		t.Errorf("results.sarif no longer holds the image reference as the finding's location: %q", kept)
	}
}

// A run that knows where its images are declared uploads a finding on one on that line, so code
// scanning can show it, and still uploads no location code scanning refuses. A finding on an image the
// run does not know a line for, and the host's, go up with none.
func TestGithubPublisherPlacesAnImageFindingOnItsDeclaration(t *testing.T) {
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	fake := &fakeCodeScanning{t: t}
	ghEnv(t, startFake(t, fake))
	finding := func(control, image, uri string) sarif.Result {
		return sarif.Result{RuleID: "R-" + uri, Level: sarif.LevelError, Priority: "P2", Tool: "trivy",
			Control: control, Component: "api", Message: "m", Location: sarif.Location{URI: uri}, Image: image}
	}
	run := engine.Result{Controls: map[string]plugin.ControlResult{
		"images": {Control: "images", Report: sarif.Report{Tool: "trivy", Results: []sarif.Result{
			finding("images", "debian:11", "debian:11"),
			finding("images", "nginx:1.25", "nginx:1.25"),
		}}},
		"tls": {Control: "tls", Report: sarif.Report{Tool: "testssl", Results: []sarif.Result{
			finding("tls", "", "https://example.com/login"),
		}}},
	}}
	data := report.Data{Release: saga.Release{Version: "1.0"}, Run: run, Verdict: norn.Result{Verdict: norn.Fail},
		Declared: sarif.Declarations{{Component: "api", Ref: "debian:11"}: {Path: "deploy/draugr.saga.yaml", Line: 14}}}
	if err := Run(context.Background(), []saga.PublisherConfig{{Kind: "github"}}, data); err != nil {
		t.Fatal(err)
	}
	if refused, _ := sarif.CodeScanningRefuses(fake.uploaded); len(refused) > 0 {
		t.Errorf("the upload carries locations code scanning refuses: %q", refused)
	}
	if !strings.Contains(string(fake.uploaded), `"artifactLocation":{"uri":"deploy/draugr.saga.yaml","uriBaseId":"%SRCROOT%"},"region":{"startLine":14}`) {
		t.Errorf("the finding on debian:11 is not on its declaration:\n%s", fake.uploaded)
	}
	if !strings.Contains(logs.String(), "findings=2") {
		t.Errorf("the publish should count the undeclared image's finding and the host's:\n%s", logs.String())
	}
}

// The copy refuses a report it cannot read rather than uploading it unchanged.
func TestGithubPublisherRefusesAReportItCannotHold(t *testing.T) {
	fake := &fakeCodeScanning{t: t}
	ghEnv(t, startFake(t, fake))
	p, err := For(saga.PublisherConfig{Kind: "github"})
	if err != nil {
		t.Fatal(err)
	}
	err = p.Publish(context.Background(), []report.Artifact{{Format: "sarif", Bytes: []byte(`{"runs":"x"}`)}})
	if err == nil || !strings.Contains(err.Error(), "github code scanning") {
		t.Errorf("err = %v, want one naming code scanning", err)
	}
	if fake.uploaded != nil {
		t.Error("an unreadable report was uploaded")
	}
}
