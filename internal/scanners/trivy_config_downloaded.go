package scanners

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// A Terraform configuration that calls a registry or git module has Trivy download the module and
// check it with the configuration. Trivy reports what it finds in the module at the module's own
// path, `terraform-aws-modules/s3-bucket/aws/main.tf:25`, a file the repository does not hold, and
// the maintainer cannot change it: the fix, where there is one, is an input to the `module` block
// that called it, or another version of the module.
//
// Trivy's JSON report records the chain of module calls behind each such finding, innermost first,
// as the cause's occurrences. So a finding at a path the checkout does not hold is moved to the
// first call in that chain that the checkout does hold, the block that brought the module in, and
// carries the module's source, version, and its own file and line inside the module as Module.
//
// Moving them also keeps them apart. Two blocks calling the same module report the same rule at
// the same module path and line, and read as one finding where there are two.

// trivyModuleCall is where a finding inside a downloaded module is moved to.
type trivyModuleCall struct {
	file       string
	start, end int
	module     sarif.Module
}

// trivyModuleCallKey identifies a result of Trivy's SARIF by what convert writes from the JSON: the
// rule, the file and the first line.
func trivyModuleCallKey(rule, uri string, line int) string {
	return fmt.Sprint(rule, "\x00", uri, "\x00", line)
}

// trivyCauseOccurrence is one module call behind a finding, as Trivy's JSON report records it.
type trivyCauseOccurrence struct {
	Resource string `json:"Resource"`
	Filename string `json:"Filename"`
	Location struct {
		StartLine int `json:"StartLine"`
		EndLine   int `json:"EndLine"`
	} `json:"Location"`
}

// trivyDownloadedModuleCalls reads Trivy's JSON report for the failed checks whose file the
// checkout at dir does not hold and whose cause names a module call it does, and returns where each
// moves to, keyed as trivyModuleCallKey keys the SARIF result convert writes for it. Several
// findings can share a key, one per block calling the same module, and they are listed in the
// report's order, which is the order convert writes them in.
func trivyDownloadedModuleCalls(report []byte, dir string) (map[string][]trivyModuleCall, error) {
	var doc struct {
		Results []struct {
			Target            string `json:"Target"`
			Misconfigurations []struct {
				ID            string `json:"ID"`
				Status        string `json:"Status"`
				CauseMetadata struct {
					StartLine   int                    `json:"StartLine"`
					EndLine     int                    `json:"EndLine"`
					Occurrences []trivyCauseOccurrence `json:"Occurrences"`
				} `json:"CauseMetadata"`
			} `json:"Misconfigurations"`
		} `json:"Results"`
	}
	if err := json.Unmarshal(report, &doc); err != nil {
		return nil, fmt.Errorf("read its JSON report: %w", err)
	}
	calls := map[string][]trivyModuleCall{}
	held := map[string]bool{}
	holds := func(p string) bool {
		if v, ok := held[p]; ok {
			return v
		}
		_, err := os.Stat(filepath.Join(dir, filepath.FromSlash(p)))
		held[p] = filepath.IsLocal(filepath.FromSlash(p)) && err == nil
		return held[p]
	}
	for _, res := range doc.Results {
		if res.Target == "" || holds(res.Target) {
			continue
		}
		for _, m := range res.Misconfigurations {
			if m.Status != "FAIL" || len(m.CauseMetadata.Occurrences) == 0 {
				continue
			}
			for _, o := range m.CauseMetadata.Occurrences {
				if o.Filename == "" || o.Location.StartLine < 1 || !holds(o.Filename) {
					continue
				}
				start := m.CauseMetadata.StartLine
				if start < 1 {
					start = 1
				}
				call := trivyModuleCall{file: o.Filename, start: o.Location.StartLine, end: max(o.Location.EndLine, o.Location.StartLine)}
				call.module = moduleBlockSource(filepath.Join(dir, filepath.FromSlash(o.Filename)), call.start, call.end)
				call.module.File = strings.TrimPrefix(res.Target, call.module.Source+"/")
				call.module.Line = start
				key := trivyModuleCallKey(m.ID, res.Target, start)
				calls[key] = append(calls[key], call)
				break
			}
		}
	}
	return calls, nil
}

// terraformModuleArg matches a `source` or `version` argument of a module block, with its value.
var terraformModuleArg = regexp.MustCompile(`^\s*(source|version)\s*=\s*"([^"]*)"`)

// moduleBlockSource reads the source and version the module block on lines start to end of the file
// at p gives. Either is empty where the block does not say, or the file cannot be read.
func moduleBlockSource(p string, start, end int) sarif.Module {
	var m sarif.Module
	src, err := os.ReadFile(p) // #nosec G304 -- a file of the checkout that Trivy named as calling a module
	if err != nil {
		return m
	}
	lines := strings.Split(string(src), "\n")
	for i := start; i <= end && i <= len(lines); i++ {
		sub := terraformModuleArg.FindStringSubmatch(lines[i-1])
		if sub == nil {
			continue
		}
		switch sub[1] {
		case "source":
			if m.Source == "" {
				m.Source = sub[2]
			}
		case "version":
			if m.Version == "" {
				m.Version = sub[2]
			}
		}
	}
	return m
}

// relocateDownloadedModuleFindings moves each result of Trivy's SARIF that calls lists to the module
// call it names, with the module recorded in the result's properties. A result calls does not list
// is left as it was. SARIF with nothing to move is returned unchanged.
func relocateDownloadedModuleFindings(sarifOut []byte, calls map[string][]trivyModuleCall) ([]byte, error) {
	if len(calls) == 0 {
		return sarifOut, nil
	}
	var doc map[string]any
	if err := json.Unmarshal(sarifOut, &doc); err != nil {
		return nil, fmt.Errorf("read the SARIF convert wrote: %w", err)
	}
	runs, _ := doc["runs"].([]any)
	for _, run := range runs {
		results, _ := jsonObject(run)["results"].([]any)
		for _, r := range results {
			result := jsonObject(r)
			rule, _ := result["ruleId"].(string)
			locations, _ := result["locations"].([]any)
			if len(locations) == 0 {
				continue
			}
			physical := jsonObject(jsonObject(locations[0])["physicalLocation"])
			art := jsonObject(physical["artifactLocation"])
			region := jsonObject(physical["region"])
			uri, _ := art["uri"].(string)
			line, _ := region["startLine"].(float64)
			key := trivyModuleCallKey(rule, uri, int(line))
			queue := calls[key]
			if len(queue) == 0 {
				continue
			}
			call := queue[0]
			calls[key] = queue[1:]
			art["uri"] = path.Clean(call.file)
			physical["region"] = map[string]any{"startLine": call.start, "endLine": call.end}
			if msg := jsonObject(locations[0])["message"]; msg != nil {
				jsonObject(msg)["text"] = call.file
			}
			props := jsonObject(result["properties"])
			if props == nil {
				props = map[string]any{}
				result["properties"] = props
			}
			props["module"] = call.module
		}
	}
	return json.Marshal(doc)
}
