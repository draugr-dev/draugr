package sealed

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
)

// Cleared is what a normalized field is replaced with.
const Cleared = "<cleared>"

// Normalizer makes a report comparable across runs: it clears the fields that vary by machine or
// by moment, replaces run-specific strings wherever they appear, and sorts the arrays whose order
// depends on which job finished first.
//
// A path that matches nothing is an error rather than a no-op. A field that moved would otherwise
// stop being cleared without anybody noticing, and the golden would start pinning a value that
// changes on the next run, or would stop pinning anything at the old path.
type Normalizer struct {
	// Clear are paths to fields replaced with Cleared. "*" matches every element of an array or
	// every value of an object. Each path must match at least one field.
	Clear [][]string
	// Sort are paths to arrays sorted by their elements' JSON.
	Sort [][]string
	// Replace maps a string to what it becomes, in every string value.
	Replace map[string]string
}

// SARIFNormalizer is the normalizer for Draugr's results.sarif.
func SARIFNormalizer(replace map[string]string) Normalizer {
	return Normalizer{
		Clear: [][]string{
			{"runs", "*", "tool", "driver", "version"},
			{"runs", "*", "properties", "draugr/provenance", "*", "version"},
			{"runs", "*", "properties", "draugr/provenance", "*", "fields", "revision"},
			// A hash over the line's content, and one line in every scenario holds a secret
			// generated for the run.
			{"runs", "*", "results", "*", "partialFingerprints", "primaryLocationLineHash/v1"},
		},
		Sort: [][]string{
			{"runs", "*", "results"},
			{"runs", "*", "tool", "driver", "rules"},
			{"runs", "*", "properties", "draugr/provenance"},
		},
		Replace: replace,
	}
}

// ReportNormalizer is the normalizer for Draugr's report.json.
func ReportNormalizer(replace map[string]string) Normalizer {
	return Normalizer{
		Clear: [][]string{
			{"draugr", "version"},
			{"scanners", "*", "version"},
			{"repositories", "*", "revision"},
			// Both cover the effective descriptor, which names the run's own directory.
			{"descriptor", "digest"},
			{"descriptor", "effective"},
			{"stats", "durationMs"},
			{"stats", "byControlMs"},
			{"stats", "concurrency"},
		},
		Sort:    [][]string{{"scanners"}},
		Replace: replace,
	}
}

// Apply normalizes a JSON document and returns it indented, with a trailing newline.
func (n Normalizer) Apply(raw []byte) ([]byte, error) {
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	doc = n.replace(doc)
	for _, path := range n.Clear {
		if hits := visit(doc, path, func(parent map[string]any, key string) { parent[key] = Cleared }); hits == 0 {
			return nil, fmt.Errorf("normalize: nothing at %s; the field moved, so update the normalizer", strings.Join(path, "."))
		}
	}
	for _, path := range n.Sort {
		visit(doc, path, func(parent map[string]any, key string) {
			if arr, ok := parent[key].([]any); ok {
				sortByJSON(arr)
			}
		})
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (n Normalizer) replace(v any) any {
	switch t := v.(type) {
	case string:
		for from, to := range n.Replace {
			t = strings.ReplaceAll(t, from, to)
		}
		return t
	case []any:
		for i := range t {
			t[i] = n.replace(t[i])
		}
	case map[string]any:
		for k, e := range t {
			t[k] = n.replace(e)
		}
	}
	return v
}

// visit calls fn with the object and key of every field path reaches, and returns how many it
// reached.
func visit(v any, path []string, fn func(parent map[string]any, key string)) int {
	if len(path) == 0 {
		return 0
	}
	head, rest := path[0], path[1:]
	switch t := v.(type) {
	case map[string]any:
		keys := []string{head}
		if head == "*" {
			keys = keys[:0]
			for k := range t {
				keys = append(keys, k)
			}
		}
		hits := 0
		for _, k := range keys {
			child, ok := t[k]
			if !ok {
				continue
			}
			if len(rest) == 0 {
				fn(t, k)
				hits++
				continue
			}
			hits += visit(child, rest, fn)
		}
		return hits
	case []any:
		if head != "*" {
			return 0
		}
		hits := 0
		for _, e := range t {
			if len(rest) > 0 {
				hits += visit(e, rest, fn)
			}
		}
		return hits
	}
	return 0
}

func sortByJSON(arr []any) {
	keys := make([]string, len(arr))
	for i, e := range arr {
		b, _ := json.Marshal(e) // a value that came out of json.Unmarshal always marshals
		keys[i] = string(b)
	}
	idx := make([]int, len(arr))
	for i := range idx {
		idx[i] = i
	}
	sort.SliceStable(idx, func(a, b int) bool { return keys[idx[a]] < keys[idx[b]] })
	sorted := make([]any, len(arr))
	for i, j := range idx {
		sorted[i] = arr[j]
	}
	copy(arr, sorted)
}

// sarifSchema is the OASIS SARIF 2.1.0 schema, schema/sarif-schema-2.1.0.json.
//
//go:embed schema/sarif-schema-2.1.0.json
var sarifSchema []byte

var (
	sarifOnce     sync.Once
	sarifResolved *jsonschema.Resolved
	sarifErr      error
)

// ValidateSARIF checks a document against the SARIF 2.1.0 schema.
//
// The published schema declares JSON Schema draft-04, which the validator does not read. The two
// differences that matter are its "$schema" and its top-level "id", renamed "$id" in later drafts;
// the schema uses no other draft-04 construct, so both are rewritten on load and nothing else is.
func ValidateSARIF(raw []byte) error {
	sarifOnce.Do(func() {
		s := strings.Replace(string(sarifSchema), `"http://json-schema.org/draft-04/schema#"`, `"http://json-schema.org/draft-07/schema#"`, 1)
		s = strings.Replace(s, `"id": "https://docs.oasis-open.org/`, `"$id": "https://docs.oasis-open.org/`, 1)
		var schema jsonschema.Schema
		if sarifErr = json.Unmarshal([]byte(s), &schema); sarifErr != nil {
			return
		}
		sarifResolved, sarifErr = schema.Resolve(nil)
	})
	if sarifErr != nil {
		return sarifErr
	}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return err
	}
	return sarifResolved.Validate(doc)
}

// RunReplacements are the strings particular to one sealed run: its directory, in the form a path
// takes and the form a Semgrep rule id takes, and the dates the run could have stamped.
func RunReplacements(work string, start time.Time) map[string]string {
	dotted := strings.ReplaceAll(strings.TrimPrefix(work, "/"), "/", ".") + "."
	return map[string]string{
		work:                                   "<work>",
		dotted:                                 "",
		start.UTC().Format(time.DateOnly):      "<today>",
		time.Now().UTC().Format(time.DateOnly): "<today>",
	}
}

// Diff renders the lines that differ between two documents, a few lines of context around each
// run of changes.
func Diff(want, got string) string {
	w, g := strings.Split(want, "\n"), strings.Split(got, "\n")
	var b strings.Builder
	shown := 0
	for i := 0; i < len(w) || i < len(g); i++ {
		var wl, gl string
		if i < len(w) {
			wl = w[i]
		}
		if i < len(g) {
			gl = g[i]
		}
		if wl == gl {
			continue
		}
		fmt.Fprintf(&b, "line %d\n  - %s\n  + %s\n", i+1, wl, gl)
		if shown++; shown == 20 {
			b.WriteString("  … further differences not shown\n")
			break
		}
	}
	return b.String()
}
