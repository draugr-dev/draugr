package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sbom"
)

func TestArtifactFilenames(t *testing.T) {
	docs := []sbom.Document{
		{Component: "web", Target: "https://github.com/acme/web", Format: saga.SBOMSPDXJSON, Bytes: []byte("a")},
		{Component: "API Gateway", Target: "python:3.8-slim@sha256:abc", Format: saga.SBOMCycloneDXJSON, Bytes: []byte("b")},
	}
	arts := SBOMArtifacts(docs)
	if len(arts) != 2 {
		t.Fatalf("artifacts = %d, want 2", len(arts))
	}
	want := []string{
		"sbom-web-https-github-com-acme-web.spdx.json",
		"sbom-api-gateway-python-3-8-slim-sha256-abc.cdx.json",
	}
	for i, a := range arts {
		if a.Filename != want[i] {
			t.Errorf("filename[%d] = %q, want %q", i, a.Filename, want[i])
		}
		if a.Format != "sbom" || a.ContentType != "application/json" {
			t.Errorf("artifact[%d] metadata wrong: %+v", i, a)
		}
	}
}

func TestArtifactFilenamesDoNotCollideAcrossImages(t *testing.T) {
	// Two images in one component is ordinary. If the slug dropped tags, both would land on the
	// same filename and the second would silently overwrite the first.
	arts := SBOMArtifacts([]sbom.Document{
		{Component: "api", Target: "python:3.8-slim", Format: saga.SBOMSPDXJSON},
		{Component: "api", Target: "python:3.12-slim", Format: saga.SBOMSPDXJSON},
	})
	if arts[0].Filename == arts[1].Filename {
		t.Fatalf("both images produced %q", arts[0].Filename)
	}
}

func TestArtifactsEmpty(t *testing.T) {
	if got := SBOMArtifacts(nil); len(got) != 0 {
		t.Errorf("want no artifacts, got %d", len(got))
	}
}

func TestSlug(t *testing.T) {
	for in, want := range map[string]string{
		"web":                       "web",
		"API Gateway":               "api-gateway",
		"python:3.8-slim":           "python-3-8-slim",
		"https://github.com/a/b":    "https-github-com-a-b",
		"ghcr.io/org/img@sha256:ab": "ghcr-io-org-img-sha256-ab",
		"---":                       "",
		"":                          "",
	} {
		if got := slug(in); got != want {
			t.Errorf("slug(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEveryFormatHasAFileExtension(t *testing.T) {
	// A format the Saga accepts but that has no extension here would silently produce
	// "sbom-x-y.json" — readable, but not what a consumer keying on the suffix expects.
	for _, f := range saga.SBOMFormats {
		if extensions[f] == "" {
			t.Errorf("format %q has no file extension mapped", f)
		}
	}
}

func TestConsoleReportsSBOMsWithoutMakingThemAControl(t *testing.T) {
	d := Data{
		Release: saga.Release{Name: "app", Version: "1"},
		Run: engine.Result{SBOMs: []sbom.Document{
			{Component: "web", Target: "https://git/web", Format: saga.SBOMSPDXJSON},
			{Component: "api", Target: "api:1", Format: saga.SBOMSPDXJSON},
		}},
		Verdict: norn.Result{Verdict: norn.Pass},
	}
	var buf bytes.Buffer
	if err := (consoleReporter{}).Render(&buf, d); err != nil {
		t.Fatalf("Render: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "SBOM: 2 documents (spdx-json)") {
		t.Errorf("want the SBOM summary line:\n%s", out)
	}
	// It must not appear in the Controls table: every row there means "checked, and here is the
	// verdict", and an inventory has no verdict to give.
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "SBOM") && (strings.Contains(line, "pass") || strings.Contains(line, "FAIL")) {
			t.Errorf("SBOM should not be rendered as a control row: %q", line)
		}
	}
}

func TestConsoleReportsSBOMsOnACleanRun(t *testing.T) {
	// The early return for "no findings" must not swallow the evidence line — a clean scan
	// still produced the inventory.
	d := Data{
		Release: saga.Release{Name: "app", Version: "1"},
		Run:     engine.Result{SBOMs: []sbom.Document{{Component: "web", Target: "r", Format: saga.SBOMSPDXJSON}}},
		Verdict: norn.Result{Verdict: norn.Pass},
	}
	var buf bytes.Buffer
	if err := (consoleReporter{}).Render(&buf, d); err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(buf.String(), "SBOM: 1 document (spdx-json)") {
		t.Errorf("want a singular summary line on a clean run:\n%s", buf.String())
	}
}

func TestConsoleOmitsTheSBOMLineWhenThereAreNone(t *testing.T) {
	var buf bytes.Buffer
	d := Data{Release: saga.Release{Name: "app", Version: "1"}, Verdict: norn.Result{Verdict: norn.Pass}}
	if err := (consoleReporter{}).Render(&buf, d); err != nil {
		t.Fatalf("Render: %v", err)
	}
	if strings.Contains(buf.String(), "SBOM") {
		t.Errorf("no SBOMs means no line at all:\n%s", buf.String())
	}
}
