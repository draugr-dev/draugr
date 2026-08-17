package scanners

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"gopkg.in/yaml.v3"
)

// specOperations is the set of HTTP methods an OpenAPI path item can describe. Anything else at
// that level — parameters, summary, servers — describes the path rather than an operation.
var specOperations = map[string]bool{
	"get": true, "head": true, "options": true, "trace": true,
	"post": true, "put": true, "patch": true, "delete": true,
}

// preparedSpec is a rewritten copy of a descriptor's OpenAPI document, plus what changed.
type preparedSpec struct {
	// Path is the rewritten document on disk.
	Path string
	// Kept counts the operations the scan will exercise; Dropped counts those removed, by method.
	Kept    int
	Dropped map[string]int
	// Unfillable counts kept operations declaring a required parameter with no example or default.
	//
	// Nuclei refuses a specification it cannot fill unless told to skip those requests, and told
	// to, it skips them silently. Counting them here is how the run can say that coverage was
	// lost rather than leaving a smaller scan looking like a complete one.
	Unfillable int
	// Cleanup removes the rewritten copy.
	Cleanup func()
}

// DroppedSummary describes what was excluded, most-numerous first, or "" when nothing was.
func (p preparedSpec) DroppedSummary() string {
	if len(p.Dropped) == 0 {
		return ""
	}
	methods := make([]string, 0, len(p.Dropped))
	for m := range p.Dropped {
		methods = append(methods, m)
	}
	sort.Slice(methods, func(i, j int) bool {
		if p.Dropped[methods[i]] != p.Dropped[methods[j]] {
			return p.Dropped[methods[i]] > p.Dropped[methods[j]]
		}
		return methods[i] < methods[j]
	})
	parts := make([]string, 0, len(methods))
	total := 0
	for _, m := range methods {
		parts = append(parts, fmt.Sprintf("%s (%d)", m, p.Dropped[m]))
		total += p.Dropped[m]
	}
	noun := "operations"
	if total == 1 {
		noun = "operation"
	}
	return fmt.Sprintf("%d %s not scanned: %s", total, noun, strings.Join(parts, ", "))
}

// prepareSpec rewrites a descriptor's OpenAPI document into the one the scanner is given.
//
// Two rewrites, and both are safety rather than tidiness:
//
//   - **servers is pinned to the declared endpoint.** A scanner handed a specification takes its
//     targets from that document, so a spec whose servers block names production would send
//     probe traffic at production while the descriptor said staging. The descriptor is the
//     authority on what may be scanned; a file the API team publishes is not.
//   - **Only the selected methods survive.** Filtering here rather than trusting the scanner
//     means the restriction holds whatever the tool later does with the document, and can be
//     proved by reading the file that was handed over.
func prepareSpec(specPath, endpoint string, methods []string) (preparedSpec, error) {
	raw, err := os.ReadFile(filepath.Clean(specPath)) // #nosec G304 -- a path the descriptor names
	if err != nil {
		return preparedSpec{}, fmt.Errorf("read %s: %w", specPath, err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return preparedSpec{}, fmt.Errorf("parse %s: %w", specPath, err)
	}
	if doc == nil {
		return preparedSpec{}, fmt.Errorf("%s is empty", specPath)
	}

	allowed := map[string]bool{}
	for _, m := range plugin.NormalizeMethods(methods) {
		allowed[m] = true
	}

	paths, _ := doc["paths"].(map[string]any)
	if len(paths) == 0 {
		return preparedSpec{}, fmt.Errorf("%s declares no paths, so there is nothing to scan", specPath)
	}
	kept, dropped := filterOperations(paths, allowed)
	unfillable := countUnfillable(paths)
	if kept == 0 {
		return preparedSpec{}, fmt.Errorf(
			"%s declares no %s operation, so this scan would send no requests — add the methods you "+
				"accept to spec.methods", specPath, strings.Join(plugin.NormalizeMethods(methods), " or "))
	}
	doc["servers"] = []any{map[string]any{"url": endpoint}}

	out, err := os.CreateTemp("", "draugr-openapi-*.yaml")
	if err != nil {
		return preparedSpec{}, err
	}
	cleanup := func() { _ = os.Remove(out.Name()) }
	body, err := yaml.Marshal(doc)
	if err != nil {
		cleanup()
		return preparedSpec{}, err
	}
	if _, err := out.Write(body); err != nil {
		_ = out.Close()
		cleanup()
		return preparedSpec{}, err
	}
	if err := out.Close(); err != nil {
		cleanup()
		return preparedSpec{}, err
	}
	return preparedSpec{
		Path: out.Name(), Kept: kept, Dropped: dropped, Unfillable: unfillable, Cleanup: cleanup,
	}, nil
}

// filterOperations removes every operation whose method is not allowed, reporting what went.
func filterOperations(paths map[string]any, allowed map[string]bool) (kept int, dropped map[string]int) {
	dropped = map[string]int{}
	for _, item := range paths {
		ops, ok := item.(map[string]any)
		if !ok {
			continue
		}
		for key := range ops {
			method := strings.ToLower(key)
			if !specOperations[method] {
				continue // describes the path, not an operation
			}
			if allowed[method] {
				kept++
				continue
			}
			delete(ops, key)
			dropped[method]++
		}
	}
	return kept, dropped
}

// countUnfillable counts operations with a required parameter the scanner has no value for.
//
// A parameter is fillable when the specification offers an example or a default. Nothing else in
// the document says what a valid value looks like, so anything else is a request the scanner will
// be told to skip.
func countUnfillable(paths map[string]any) int {
	n := 0
	for _, item := range paths {
		ops, ok := item.(map[string]any)
		if !ok {
			continue
		}
		shared := requiredUnfilled(ops["parameters"])
		for key, raw := range ops {
			if !specOperations[strings.ToLower(key)] {
				continue
			}
			op, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			if shared || requiredUnfilled(op["parameters"]) {
				n++
			}
		}
	}
	return n
}

// requiredUnfilled reports whether a parameter list has a required entry with nothing to fill it.
func requiredUnfilled(raw any) bool {
	list, ok := raw.([]any)
	if !ok {
		return false
	}
	for _, entry := range list {
		p, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		if req, _ := p["required"].(bool); !req {
			continue
		}
		if _, has := p["example"]; has {
			continue
		}
		schema, _ := p["schema"].(map[string]any)
		if schema != nil {
			if _, has := schema["example"]; has {
				continue
			}
			if _, has := schema["default"]; has {
				continue
			}
			if _, has := schema["enum"]; has {
				continue
			}
		}
		return true
	}
	return false
}

// endpointForSpec returns the URL a rewritten spec should point at.
//
// The declared endpoint, always. Its path is kept, because an API mounted at /v2 is reached there
// and a specification's own paths are relative to whatever its servers block said.
func endpointForSpec(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("%q is not a URL a scan can be pointed at", raw)
	}
	return strings.TrimSuffix(u.String(), "/"), nil
}
