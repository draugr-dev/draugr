package scanners

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"gopkg.in/yaml.v3"
)

const specWithWrites = `
openapi: 3.0.0
info: { title: demo, version: "1.0" }
servers:
  - url: https://api.production.example.com
paths:
  /widgets:
    get: { responses: { "200": { description: ok } } }
    post: { responses: { "201": { description: made } } }
  /widgets/{id}:
    parameters:
      - { name: id, in: path, required: true, schema: { type: string } }
    get: { responses: { "200": { description: ok } } }
    delete: { responses: { "204": { description: gone } } }
`

func writeSpec(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "openapi.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func readPrepared(t *testing.T, path string) map[string]any {
	t.Helper()
	body, err := os.ReadFile(path) // #nosec G304 -- a path prepareSpec just created
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

// TestPreparedSpecCannotRedirectTheScan is the assertion that matters most here.
//
// A scanner handed a specification takes its targets from that document, so a spec whose servers
// block names production would send probe traffic at production while the descriptor said
// staging. The descriptor is the authority on what may be scanned; a file the API team publishes
// is not.
func TestPreparedSpecCannotRedirectTheScan(t *testing.T) {
	got, err := prepareSpec(writeSpec(t, specWithWrites), "https://staging.example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer got.Cleanup()

	doc := readPrepared(t, got.Path)
	servers, ok := doc["servers"].([]any)
	if !ok || len(servers) != 1 {
		t.Fatalf("servers = %v, want exactly the endpoint the descriptor declared", doc["servers"])
	}
	server, _ := servers[0].(map[string]any)
	if server["url"] != "https://staging.example.com" {
		t.Errorf("the scan would target %v, not the declared endpoint", server["url"])
	}
	if strings.Contains(strings.ToLower(mustMarshal(t, doc)), "production") {
		t.Error("the production host survived into the document handed to the scanner")
	}
}

func mustMarshal(t *testing.T, doc map[string]any) string {
	t.Helper()
	b, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestPreparedSpecIsReadOnlyByDefault covers the measured behavior this exists for: handed the
// whole document, a scan sent nine DELETE requests nobody asked for.
func TestPreparedSpecIsReadOnlyByDefault(t *testing.T) {
	got, err := prepareSpec(writeSpec(t, specWithWrites), "https://staging.example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer got.Cleanup()

	doc := readPrepared(t, got.Path)
	paths, _ := doc["paths"].(map[string]any)
	for path, raw := range paths {
		ops, _ := raw.(map[string]any)
		for _, write := range []string{"post", "put", "patch", "delete"} {
			if _, present := ops[write]; present {
				t.Errorf("%s %s survived a read-only preparation", strings.ToUpper(write), path)
			}
		}
	}
	if got.Kept != 2 {
		t.Errorf("kept %d operations, want the two GETs", got.Kept)
	}
	if got.Dropped["post"] != 1 || got.Dropped["delete"] != 1 {
		t.Errorf("dropped = %v, want one post and one delete", got.Dropped)
	}
}

func TestPreparedSpecKeepsTheMethodsNamed(t *testing.T) {
	got, err := prepareSpec(writeSpec(t, specWithWrites), "https://staging.example.com",
		[]string{"GET", "post"}) // mixed case, deliberately
	if err != nil {
		t.Fatal(err)
	}
	defer got.Cleanup()

	doc := readPrepared(t, got.Path)
	paths, _ := doc["paths"].(map[string]any)
	widgets, _ := paths["/widgets"].(map[string]any)
	if _, ok := widgets["post"]; !ok {
		t.Error("post was named and should have survived")
	}
	byID, _ := paths["/widgets/{id}"].(map[string]any)
	if _, ok := byID["delete"]; ok {
		t.Error("delete was not named and should have gone")
	}
	if got.Dropped["delete"] != 1 || got.Dropped["post"] != 0 {
		t.Errorf("dropped = %v", got.Dropped)
	}
}

// TestPreparedSpecSaysWhatItExcluded keeps lost coverage visible. A smaller scan that says nothing
// reads exactly like a complete one.
func TestPreparedSpecSaysWhatItExcluded(t *testing.T) {
	got, err := prepareSpec(writeSpec(t, specWithWrites), "https://staging.example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer got.Cleanup()

	summary := got.DroppedSummary()
	for _, want := range []string{"2 operations not scanned", "delete (1)", "post (1)"} {
		if !strings.Contains(summary, want) {
			t.Errorf("summary %q should mention %q", summary, want)
		}
	}
	if prepared := (preparedSpec{}); prepared.DroppedSummary() != "" {
		t.Error("nothing excluded should say nothing")
	}
}

// TestPreparedSpecCountsWhatTheScannerCannotFill covers the other half of lost coverage. Nuclei
// skips those requests silently once told to, so the count has to come from the document.
func TestPreparedSpecCountsWhatTheScannerCannotFill(t *testing.T) {
	got, err := prepareSpec(writeSpec(t, specWithWrites), "https://x.example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer got.Cleanup()
	// /widgets/{id} declares a required path parameter with no example: its GET cannot be filled.
	if got.Unfillable != 1 {
		t.Errorf("Unfillable = %d, want the one operation with an unsatisfiable parameter", got.Unfillable)
	}

	withExample := strings.Replace(specWithWrites,
		"schema: { type: string } }", "schema: { type: string, example: abc } }", 1)
	filled, err := prepareSpec(writeSpec(t, withExample), "https://x.example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer filled.Cleanup()
	if filled.Unfillable != 0 {
		t.Errorf("an example makes a parameter fillable, got %d unfilled", filled.Unfillable)
	}
}

func TestPrepareSpecRejectsWhatCannotBeScanned(t *testing.T) {
	for _, c := range []struct{ name, body, methods, want string }{
		{"no paths", "openapi: 3.0.0\ninfo: {}\n", "", "no paths"},
		{"empty", "", "", "empty"},
		{"nothing matches the methods", specWithWrites, "put", "no put operation"},
	} {
		t.Run(c.name, func(t *testing.T) {
			var methods []string
			if c.methods != "" {
				methods = []string{c.methods}
			}
			_, err := prepareSpec(writeSpec(t, c.body), "https://x.example.com", methods)
			if err == nil {
				t.Fatal("expected an error rather than a scan that sends nothing")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error = %v, want it to mention %q", err, c.want)
			}
		})
	}
	if _, err := prepareSpec(filepath.Join(t.TempDir(), "absent.yaml"), "https://x", nil); err == nil {
		t.Error("a missing specification should fail rather than scan nothing")
	}
}

func TestPluginNormalizeMethods(t *testing.T) {
	for _, c := range []struct {
		name string
		in   []string
		want []string
	}{
		{"absent means read-only", nil, []string{"get", "head"}},
		{"blank means read-only", []string{"", "  "}, []string{"get", "head"}},
		{"lower-cased and sorted", []string{"POST", "get"}, []string{"get", "post"}},
		{"deduplicated", []string{"get", "GET"}, []string{"get"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := plugin.NormalizeMethods(c.in); !slices.Equal(got, c.want) {
				t.Errorf("plugin.NormalizeMethods(%v) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

func TestEndpointForSpec(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"https://api.example.com", "https://api.example.com"},
		{"https://api.example.com/", "https://api.example.com"},
		{"https://api.example.com/v2", "https://api.example.com/v2"},
	} {
		got, err := endpointForSpec(c.in)
		if err != nil || got != c.want {
			t.Errorf("endpointForSpec(%q) = %q, %v; want %q", c.in, got, err, c.want)
		}
	}
	if _, err := endpointForSpec("api.example.com"); err == nil {
		t.Error("a bare host is not something a scan can be pointed at")
	}
}
