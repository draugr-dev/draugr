package scanners

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// appendSARIFResults adds results, and the rules they name that the document lacks, to the first
// run of a tool's SARIF document. Every other field is carried through as it was read. A document
// with no run gains one, under driver as the tool's name.
//
// Rules go after the ones the document has, so a ruleIndex the tool wrote still names the rule it
// named.
func appendSARIFResults(doc []byte, driverName string, results, rules []any) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.UseNumber()
	var log map[string]any
	if err := dec.Decode(&log); err != nil {
		return nil, fmt.Errorf("read its SARIF: %w", err)
	}
	runs, _ := log["runs"].([]any)
	if len(runs) == 0 {
		runs = []any{map[string]any{}}
	}
	run, ok := runs[0].(map[string]any)
	if !ok {
		return nil, errors.New("read its SARIF: a run is not an object")
	}
	existing, _ := run["results"].([]any)
	run["results"] = append(existing, results...)

	tool, _ := run["tool"].(map[string]any)
	if tool == nil {
		tool = map[string]any{}
		run["tool"] = tool
	}
	driver, _ := tool["driver"].(map[string]any)
	if driver == nil {
		driver = map[string]any{"name": driverName}
		tool["driver"] = driver
	}
	have, _ := driver["rules"].([]any)
	ids := map[any]bool{}
	for _, r := range have {
		if m, ok := r.(map[string]any); ok {
			ids[m["id"]] = true
		}
	}
	for _, r := range rules {
		if m, ok := r.(map[string]any); ok && !ids[m["id"]] {
			ids[m["id"]] = true
			have = append(have, r)
		}
	}
	driver["rules"] = have
	runs[0] = run
	log["runs"] = runs
	return json.Marshal(log)
}
