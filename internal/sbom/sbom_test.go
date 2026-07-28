package sbom

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// recorder captures what Generate asked to run, so the argv is asserted exactly rather than
// approximately — a wrong flag here means a document in the wrong format, silently.
type recorder struct {
	argv     []string
	dir      string
	out      []byte
	err      error
	checkout int
}

func (r *recorder) run(_ context.Context, dir string, argv []string) ([]byte, error) {
	r.argv, r.dir = argv, dir
	return r.out, r.err
}

func (r *recorder) fakeCheckout(_ context.Context, _, _ string) (string, func(), error) {
	r.checkout++
	return "/tmp/checkout", func() {}, nil
}

func newTestGenerator(r *recorder) *Generator {
	return &Generator{run: r.run, checkout: r.fakeCheckout}
}

func TestGenerateRepositoryChecksOutAndScansTheTree(t *testing.T) {
	r := &recorder{out: []byte(`{"spdxVersion":"SPDX-2.3"}`)}
	g := newTestGenerator(r)

	doc, err := g.Generate(context.Background(), "web",
		plugin.RepositoryTarget{URL: "https://git/x", Revision: "abc"}, saga.SBOMSPDXJSON)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if r.checkout != 1 {
		t.Errorf("checkouts = %d, want 1", r.checkout)
	}
	want := []string{"syft", "scan", "dir:/tmp/checkout", "-o", "spdx-json", "-q"}
	if strings.Join(r.argv, " ") != strings.Join(want, " ") {
		t.Errorf("argv  = %v\nwant  = %v", r.argv, want)
	}
	if doc.Component != "web" || doc.Target != "https://git/x" || doc.Format != saga.SBOMSPDXJSON {
		t.Errorf("provenance wrong: %+v", doc)
	}
	if string(doc.Bytes) != `{"spdxVersion":"SPDX-2.3"}` {
		t.Errorf("bytes = %s", doc.Bytes)
	}
}

func TestGenerateImageDoesNotCheckOut(t *testing.T) {
	// Syft reads an image from the registry. Cloning anything here would be pure waste, and on
	// a component with several images it would be waste multiplied.
	r := &recorder{out: []byte(`{"bomFormat":"CycloneDX"}`)}
	g := newTestGenerator(r)

	doc, err := g.Generate(context.Background(), "api",
		plugin.ImageTarget{Ref: "python:3.8-slim", Digest: "sha256:abc"}, saga.SBOMCycloneDXJSON)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if r.checkout != 0 {
		t.Errorf("checkouts = %d, want 0 for an image", r.checkout)
	}
	// The digest is pinned so the inventory describes the bytes we named, not whatever the tag
	// points at by the time Syft resolves it.
	want := []string{"syft", "scan", "python:3.8-slim@sha256:abc", "-o", "cyclonedx-json", "-q"}
	if strings.Join(r.argv, " ") != strings.Join(want, " ") {
		t.Errorf("argv  = %v\nwant  = %v", r.argv, want)
	}
	if doc.Target != "python:3.8-slim@sha256:abc" {
		t.Errorf("target = %q", doc.Target)
	}
}

func TestGenerateDefaultsToSPDX(t *testing.T) {
	r := &recorder{out: []byte("{}")}
	doc, err := newTestGenerator(r).Generate(context.Background(), "c",
		plugin.ImageTarget{Ref: "alpine:3"}, "")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if doc.Format != saga.SBOMSPDXJSON {
		t.Errorf("format = %q, want %q", doc.Format, saga.SBOMSPDXJSON)
	}
	if !strings.Contains(strings.Join(r.argv, " "), "-o spdx-json") {
		t.Errorf("argv should request spdx-json: %v", r.argv)
	}
}

func TestGenerateRejectsAnUnknownFormat(t *testing.T) {
	_, err := newTestGenerator(&recorder{}).Generate(context.Background(), "c",
		plugin.ImageTarget{Ref: "alpine:3"}, "spdx-tag-value")
	if err == nil {
		t.Fatal("want an error for an unsupported format")
	}
	// The message has to name the alternatives; "unknown format" alone leaves the reader guessing.
	for _, want := range []string{"spdx-json", "cyclonedx-json"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should name %q: %v", want, err)
		}
	}
}

func TestGenerateRejectsTargetsWithNoInventory(t *testing.T) {
	// A host has no packages to enumerate. This must be an error, not an empty document that
	// looks like a successful scan of something with no dependencies.
	for _, target := range []plugin.Target{
		plugin.HostTarget{URL: "https://example.test"},
	} {
		if _, err := newTestGenerator(&recorder{}).Generate(context.Background(), "c", target, ""); err == nil {
			t.Errorf("want an error for a %s target", target.Kind())
		}
	}
}

func TestGenerateSurfacesToolFailure(t *testing.T) {
	r := &recorder{err: errors.New("exit status 1")}
	_, err := newTestGenerator(r).Generate(context.Background(), "c",
		plugin.ImageTarget{Ref: "alpine:3"}, "")
	if err == nil {
		t.Fatal("want an error when syft fails")
	}
	if !strings.Contains(err.Error(), "alpine:3") {
		t.Errorf("error should name the target: %v", err)
	}
}

func TestGenerateRejectsAnEmptyDocument(t *testing.T) {
	// Syft exiting 0 with no output would otherwise be recorded as a valid, empty SBOM — an
	// inventory claiming the component contains nothing.
	r := &recorder{out: nil}
	if _, err := newTestGenerator(r).Generate(context.Background(), "c",
		plugin.ImageTarget{Ref: "alpine:3"}, ""); err == nil {
		t.Fatal("want an error for empty output")
	}
}

func TestGenerateReportsACheckoutFailure(t *testing.T) {
	g := &Generator{
		run: (&recorder{}).run,
		checkout: func(context.Context, string, string) (string, func(), error) {
			return "", nil, errors.New("no such host")
		},
	}
	_, err := g.Generate(context.Background(), "c", plugin.RepositoryTarget{URL: "https://git/x"}, "")
	if err == nil || !strings.Contains(err.Error(), "https://git/x") {
		t.Errorf("want a checkout error naming the repo, got %v", err)
	}
}

func TestArtifactFilenames(t *testing.T) {
	docs := []Document{
		{Component: "web", Target: "https://github.com/acme/web", Format: saga.SBOMSPDXJSON, Bytes: []byte("a")},
		{Component: "API Gateway", Target: "python:3.8-slim@sha256:abc", Format: saga.SBOMCycloneDXJSON, Bytes: []byte("b")},
	}
	arts := Artifacts(docs)
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
	arts := Artifacts([]Document{
		{Component: "api", Target: "python:3.8-slim", Format: saga.SBOMSPDXJSON},
		{Component: "api", Target: "python:3.12-slim", Format: saga.SBOMSPDXJSON},
	})
	if arts[0].Filename == arts[1].Filename {
		t.Fatalf("both images produced %q", arts[0].Filename)
	}
}

func TestArtifactsEmpty(t *testing.T) {
	if got := Artifacts(nil); len(got) != 0 {
		t.Errorf("want no artifacts, got %d", len(got))
	}
}

func TestFormatVocabularyIsShared(t *testing.T) {
	// The format vocabulary lives in pkg/saga next to exposure and criticality, so the Saga's
	// validation and the generator can never disagree about what is accepted.
	for _, f := range saga.SBOMFormats {
		if !f.Valid() {
			t.Errorf("%q should be valid", f)
		}
		if extensions[f] == "" {
			t.Errorf("%q has no file extension mapped", f)
		}
	}
	if saga.SBOMFormat("").Valid() {
		t.Error("the empty format is not itself valid; Generate resolves it to the default")
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
