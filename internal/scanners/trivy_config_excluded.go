package scanners

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// `trivy config` drops a misconfiguration `.trivyignore` excludes and has no `--show-suppressed`,
// so an exclusion written in the repository and a check that passed look the same in the report.
// `trivy fs --scanners misconfig` runs the same checks and has the flag, but only its JSON carries
// what it excluded; its SARIF leaves the finding out as `trivy config` does.
//
// So the scan runs once, as JSON, and `trivy convert` writes the SARIF from that document. Convert
// reads a file and scans nothing, and the SARIF it writes is the one `trivy config` wrote, so every
// finding Trivy reports arrives exactly as it did. What the JSON lists as excluded is then added as
// suppressed results in the same shape.

// trivyConfigExclusionsArg marks a command line that asks Trivy for what it excluded. The command
// is built before the run, where the version is known, and the run reads the decision back from it.
const trivyConfigExclusionsArg = "--show-suppressed"

// trivyConfigRun wraps the run of a misconfiguration scan. A command asking for what Trivy excluded
// writes JSON, which is converted to SARIF with the exclusions added; any other command's output is
// returned as it was. Either way the Terraform modules Trivy's log says it could not load are
// returned beside it (see trivyUnloadedModules).
func trivyConfigRun(run func(ctx context.Context, dir string, argv []string) (stdout, stderr []byte, err error)) func(context.Context, string, []string) ([]byte, []sarif.Input, error) {
	return func(ctx context.Context, dir string, argv []string) ([]byte, []sarif.Input, error) {
		out, stderr, err := run(ctx, dir, argv)
		if err != nil {
			return nil, nil, err
		}
		unread := trivyUnloadedModules(stderr, dir)
		if !slices.Contains(argv, trivyConfigExclusionsArg) {
			return out, unread, nil
		}
		f, err := os.CreateTemp("", "draugr-trivy-config-*.json")
		if err != nil {
			return nil, nil, err
		}
		path := f.Name()
		defer func() { _ = os.Remove(path) }()
		if _, err := f.Write(out); err != nil {
			_ = f.Close()
			return nil, nil, err
		}
		if err := f.Close(); err != nil {
			return nil, nil, err
		}
		sarifOut, _, err := run(ctx, dir, []string{"trivy", "convert", "--quiet", "--format", "sarif", path})
		if err != nil {
			return nil, nil, fmt.Errorf("convert its JSON report to SARIF: %w", err)
		}
		out, err = withTrivyMisconfigExclusions(sarifOut, out)
		if err != nil {
			return nil, nil, err
		}
		return out, unread, nil
	}
}

// trivyMisconfigDoc is the slice of Trivy's JSON report that names what it excluded.
type trivyMisconfigDoc struct {
	Results []struct {
		Target   string `json:"Target"`
		Type     string `json:"Type"`
		Modified []struct {
			Type      string         `json:"Type"`
			Status    string         `json:"Status"`
			Statement string         `json:"Statement"`
			Source    string         `json:"Source"`
			Finding   trivyMisconfig `json:"Finding"`
		} `json:"ExperimentalModifiedFindings"`
	} `json:"Results"`
}

type trivyMisconfig struct {
	Type        string `json:"Type"`
	ID          string `json:"ID"`
	Title       string `json:"Title"`
	Description string `json:"Description"`
	Message     string `json:"Message"`
	Severity    string `json:"Severity"`
	PrimaryURL  string `json:"PrimaryURL"`
	// Status is FAIL for a check the file failed and PASS for one it passed.
	Status        string `json:"Status"`
	CauseMetadata struct {
		StartLine int `json:"StartLine"`
		EndLine   int `json:"EndLine"`
	} `json:"CauseMetadata"`
}

// withTrivyMisconfigExclusions adds each misconfiguration Trivy's JSON lists as excluded to its
// SARIF, as a result carrying a suppression with origin scanner. SARIF with nothing to add is
// returned unchanged.
//
// Only an exclusion, and only of a misconfiguration, for the reason trivySuppressedResultOf gives:
// a shape Trivy adds to that section later must not arrive as an acceptance nobody made. And only a
// check that failed: Trivy applies `.trivyignore` to the checks a file passed too, and lists those,
// and a passed check marked suppressed would record an acceptance of something that was never
// found.
func withTrivyMisconfigExclusions(sarifOut, jsonOut []byte) ([]byte, error) {
	var doc trivyMisconfigDoc
	if err := json.Unmarshal(jsonOut, &doc); err != nil {
		return nil, fmt.Errorf("read its JSON report: %w", err)
	}
	var results, rules []any
	seen := map[string]bool{}
	for _, res := range doc.Results {
		for _, m := range res.Modified {
			if m.Status != "ignored" || m.Type != "misconfiguration" || m.Finding.ID == "" || m.Finding.Status != "FAIL" {
				continue
			}
			start, end := trivyMisconfigLines(m.Finding)
			key := fmt.Sprint(m.Finding.ID, "\x00", res.Target, "\x00", start, "\x00", end)
			if seen[key] {
				continue
			}
			seen[key] = true
			result, rule := trivyMisconfigExcludedResult(res.Target, res.Type, m.Finding, start, end)
			suppression := map[string]any{"kind": "external", "properties": map[string]any{"origin": "scanner", "source": m.Source}}
			if m.Statement != "" {
				suppression["justification"] = m.Statement
			}
			result["suppressions"] = []any{suppression}
			results = append(results, result)
			rules = append(rules, rule)
		}
	}
	if len(results) == 0 {
		return sarifOut, nil
	}
	if len(sarifOut) == 0 {
		return nil, errors.New("convert wrote no SARIF")
	}
	return appendSARIFResults(sarifOut, "Trivy", results, rules)
}

// trivyMisconfigLines is the region Trivy's SARIF gives a misconfiguration: the cause's lines, or
// line 1 for a check about the file as a whole, which records none.
func trivyMisconfigLines(f trivyMisconfig) (start, end int) {
	start, end = f.CauseMetadata.StartLine, f.CauseMetadata.EndLine
	if start < 1 {
		start = 1
	}
	if end < start {
		end = start
	}
	return start, end
}

// trivyMisconfigExcludedResult writes one excluded misconfiguration as a SARIF result and its rule,
// in the shape Trivy's SARIF gives one it reports.
func trivyMisconfigExcludedResult(target, fileType string, f trivyMisconfig, start, end int) (result, rule map[string]any) {
	severity := strings.ToUpper(f.Severity)
	link := fmt.Sprintf("Link: [%s](%s)", f.ID, f.PrimaryURL)
	result = map[string]any{
		"ruleId": f.ID,
		"level":  trivyMisconfigLevel(severity),
		"message": map[string]any{"text": strings.Join([]string{
			"Artifact: " + target,
			"Type: " + fileType,
			"Vulnerability " + f.ID,
			"Severity: " + severity,
			"Message: " + f.Message,
			link,
		}, "\n")},
		"locations": []any{map[string]any{
			"physicalLocation": map[string]any{
				"artifactLocation": map[string]any{"uri": target, "uriBaseId": "ROOTPATH"},
				"region":           map[string]any{"startLine": start, "startColumn": 1, "endLine": end, "endColumn": 1},
			},
			"message": map[string]any{"text": target},
		}},
	}
	help := strings.Join([]string{
		"Misconfiguration " + f.ID,
		"Type: " + f.Type,
		"Severity: " + severity,
		"Check: " + f.Title,
		"Message: " + f.Message,
		link,
		f.Description,
	}, "\n")
	rule = map[string]any{
		"id":                   f.ID,
		"name":                 "Misconfiguration",
		"shortDescription":     map[string]any{"text": f.Title},
		"fullDescription":      map[string]any{"text": f.Description},
		"defaultConfiguration": map[string]any{"level": trivyMisconfigLevel(severity)},
		"helpUri":              f.PrimaryURL,
		"help":                 map[string]any{"text": help},
		"properties": map[string]any{
			"precision":         "very-high",
			"security-severity": trivyMisconfigScore(severity),
			"tags":              []string{"misconfiguration", "security", severity},
		},
	}
	return result, rule
}

// trivyMisconfigLevel maps a Trivy severity to the SARIF level Trivy writes for it.
func trivyMisconfigLevel(severity string) string {
	switch severity {
	case "CRITICAL", "HIGH":
		return "error"
	case "MEDIUM":
		return "warning"
	case "LOW", "UNKNOWN":
		return "note"
	}
	return "none"
}

// trivyMisconfigScore is the security-severity Trivy writes for a severity.
func trivyMisconfigScore(severity string) string {
	switch severity {
	case "CRITICAL":
		return "9.5"
	case "HIGH":
		return "8.0"
	case "MEDIUM":
		return "5.5"
	case "LOW":
		return "2.0"
	}
	return "0.0"
}
