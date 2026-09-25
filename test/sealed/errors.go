package sealed

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// CheckErrors compares the controls a report says could not run with the ones the scenario
// expects to fail, one line per difference. A control that errors unexpectedly is a difference, and
// so is an expected failure that ran, or failed for another reason.
func CheckErrors(exp []ErrorExpectation, report []byte) ([]string, error) {
	var doc struct {
		Controls []struct {
			Name       string   `json:"name"`
			Verdict    string   `json:"verdict"`
			ScanErrors []string `json:"scanErrors"`
		} `json:"controls"`
	}
	if err := json.Unmarshal(report, &doc); err != nil {
		return nil, fmt.Errorf("report.json: %w", err)
	}
	failed := map[string]string{}
	for _, c := range doc.Controls {
		if c.Verdict == "error" || len(c.ScanErrors) > 0 {
			failed[c.Name] = strings.Join(c.ScanErrors, "; ")
		}
	}
	var problems []string
	expected := map[string]bool{}
	for _, e := range exp {
		expected[e.Control] = true
		msg, ok := failed[e.Control]
		switch {
		case !ok:
			problems = append(problems, fmt.Sprintf("control %s ran; the scenario expects it to fail with %q", e.Control, e.Contains))
		case !strings.Contains(msg, e.Contains):
			problems = append(problems, fmt.Sprintf("control %s failed with %q; the scenario expects %q", e.Control, msg, e.Contains))
		}
	}
	for name, msg := range failed {
		if !expected[name] {
			problems = append(problems, fmt.Sprintf("control %s could not run: %s", name, msg))
		}
	}
	sort.Strings(problems)
	return problems, nil
}
