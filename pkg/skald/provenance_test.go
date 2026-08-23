package skald

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/ci"
	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// A scan driven entirely from flags has no descriptor. An empty block would claim it had one.
func TestNoDescriptorIsNoBlock(t *testing.T) {
	if got := DescriptorFrom(nil); got != nil {
		t.Errorf("DescriptorFrom(nil) = %+v, want nil", got)
	}
	if got := DescriptorFrom(&saga.Resolved{Model: &saga.Model{}}); got != nil {
		t.Errorf("a resolution with no sources produced %+v, want nil", got)
	}
}

// Every field a source carries has to survive the crossing, and a remote fragment's are the ones
// that make a run reproducible: a branch moves, so the resolved commit is the fact.
func TestRemoteFragmentKeepsWhatMakesItReproducible(t *testing.T) {
	got := DescriptorFrom(&saga.Resolved{
		Model: &saga.Model{Project: "p"},
		Sources: []saga.Source{
			{Path: "draugr.saga.yaml", Digest: "sha256:aa", Root: true},
			{
				Path: "platform.saga-fragment.yaml", URL: "https://example.com/platform.git",
				Revision: "main", Resolved: "abc123", Digest: "sha256:bb",
			},
		},
	})
	if got == nil {
		t.Fatal("DescriptorFrom returned nil")
	}
	if got.Digest == "" {
		t.Error("no effective digest")
	}
	if len(got.Sources) != 2 {
		t.Fatalf("got %d sources, want 2", len(got.Sources))
	}
	if !got.Sources[0].Root {
		t.Error("the root source lost its Root flag")
	}
	want := DescriptorSource{
		Path: "platform.saga-fragment.yaml", URL: "https://example.com/platform.git",
		Revision: "main", Resolved: "abc123", Digest: "sha256:bb",
	}
	if got.Sources[1] != want {
		t.Errorf("remote fragment\n got %+v\nwant %+v", got.Sources[1], want)
	}
}

func renderWith(t *testing.T, prov Provenance) map[string]any {
	t.Helper()
	var buf bytes.Buffer
	err := RenderJSONFor(&buf, "p", saga.Release{Version: "1"}, sampleRun(), norn.Result{},
		"", nil, sarif.MarshalOptions{}, prov)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("unreadable report: %v", err)
	}
	return doc
}

// Absent rather than null or empty: a consumer must be able to tell "not in CI" from "a platform
// that told us nothing", and both from a field somebody forgot to read.
func TestProvenanceIsAbsentWhenThereIsNone(t *testing.T) {
	doc := renderWith(t, Provenance{})
	for _, key := range []string{"descriptor", "ci"} {
		if _, ok := doc[key]; ok {
			t.Errorf("%q is present in a report that has none", key)
		}
	}
}

// And present, under the names the platform half reads, when there is.
func TestProvenanceTravelsInTheDocument(t *testing.T) {
	doc := renderWith(t, Provenance{
		Descriptor: &DescriptorRef{
			Digest:  "sha256:dd",
			Sources: []DescriptorSource{{Path: "draugr.saga.yaml", Digest: "sha256:aa", Root: true}},
		},
		CI: &ci.Context{System: "github-actions", RunID: "77", Attempt: "2"},
	})
	desc, ok := doc["descriptor"].(map[string]any)
	if !ok {
		t.Fatalf("descriptor missing or wrong shape: %#v", doc["descriptor"])
	}
	if desc["digest"] != "sha256:dd" {
		t.Errorf("digest = %v", desc["digest"])
	}
	got, ok := doc["ci"].(map[string]any)
	if !ok {
		t.Fatalf("ci missing or wrong shape: %#v", doc["ci"])
	}
	if got["system"] != "github-actions" || got["runId"] != "77" {
		t.Errorf("ci = %#v", got)
	}
}

// The deprecated renderers stay usable and simply carry no provenance.
func TestTheOlderRenderersStillWork(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderJSON(&buf, saga.Release{Name: "a", Version: "1"}, sampleRun(), norn.Result{}, ""); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), `"descriptor"`) {
		t.Error("RenderJSON emitted a descriptor block it was never given")
	}
}
