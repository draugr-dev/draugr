package sbom

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/git"
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

func (r *recorder) fakeCheckout(_ context.Context, _, _ string, _ git.Scope) (git.Tree, func(), error) {
	r.checkout++
	return git.Tree{Dir: "/tmp/checkout"}, func() {}, nil
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
	// --source-name is the difference between a document that names the repository and one that
	// names a temporary directory nobody will ever see again.
	want := []string{"syft", "scan", "dir:/tmp/checkout", "-o", "spdx-json", "-q",
		"--source-name", "https://git/x"}
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
	// No --source-name for an image: the reference is already stable and meaningful, so
	// overriding it would only risk disagreeing with what Syft resolved.
	want := []string{"syft", "scan", "python:3.8-slim@sha256:abc", "-o", "cyclonedx-json", "-q"}
	if strings.Join(r.argv, " ") != strings.Join(want, " ") {
		t.Errorf("argv  = %v\nwant  = %v", r.argv, want)
	}
	if doc.Target != "python:3.8-slim@sha256:abc" {
		t.Errorf("target = %q", doc.Target)
	}
}

func TestGenerateDefaultsToCycloneDX(t *testing.T) {
	r := &recorder{out: []byte("{}")}
	doc, err := newTestGenerator(r).Generate(context.Background(), "c",
		plugin.ImageTarget{Ref: "alpine:3"}, "")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if doc.Format != saga.SBOMCycloneDXJSON {
		t.Errorf("format = %q, want %q", doc.Format, saga.SBOMCycloneDXJSON)
	}
	if !strings.Contains(strings.Join(r.argv, " "), "-o cyclonedx-json") {
		t.Errorf("argv should request cyclonedx-json: %v", r.argv)
	}
}

func TestGenerateRejectsAnUnknownFormat(t *testing.T) {
	_, err := newTestGenerator(&recorder{}).Generate(context.Background(), "c",
		plugin.ImageTarget{Ref: "alpine:3"}, "syft-json")
	if err == nil {
		t.Fatal("want an error for an unsupported format")
	}
	// syft-json is a real Syft format, deliberately not offered: it is vendor-specific rather
	// than an interchange standard. Rejecting it has to be explicit, not an accident of typos.
	// The message must name the alternatives, or the reader is left guessing.
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
		checkout: func(context.Context, string, string, git.Scope) (git.Tree, func(), error) {
			return git.Tree{}, nil, errors.New("no such host")
		},
	}
	_, err := g.Generate(context.Background(), "c", plugin.RepositoryTarget{URL: "https://git/x"}, "")
	if err == nil || !strings.Contains(err.Error(), "https://git/x") {
		t.Errorf("want a checkout error naming the repo, got %v", err)
	}
}
