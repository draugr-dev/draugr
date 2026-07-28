package report

import (
	"testing"

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
