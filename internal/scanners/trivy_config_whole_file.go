package scanners

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Some of Trivy's Dockerfile checks are about the file as a whole: no HEALTHCHECK anywhere, no USER
// anywhere. Its JSON report gives such a finding no lines, and the SARIF `trivy convert` writes from
// it places the finding at line 1 alone, the same region it gives a check of an instruction that
// happens to be on line 1, such as a FROM naming a :latest tag. KICS reports the same missing
// setting at the stage's FROM line, which is line 1 only when the file has no comment or blank line
// above it, so the two copies of one check would land in different regions and both be counted.
//
// The JSON is what tells the two apart, so the region is set from it: a check the JSON reports with
// no lines is given the lines of the whole file, and the engine then finds KICS's copy wherever
// KICS placed it in that file (sameCheckGroups in pkg/engine). A check reported at an instruction
// keeps the lines Trivy gave it.

// trivyFileCheck is one of Trivy's checks in one file of its report.
type trivyFileCheck struct{ target, id string }

// readWholeFileChecks records, from one result of Trivy's JSON report, which checks a Dockerfile
// failed as a whole: a failed check whose cause gives no lines, reported or excluded. A check that
// the same file also failed at line 1 is recorded as not whole, because the SARIF gives both the same
// region and nothing there says which is which. A result about any other kind of file is ignored:
// a manifest holds several resources, and a check with no lines there is not known to be about all
// of them.
func (d *trivyMisconfigDoc) readWholeFileChecks(res map[string]json.RawMessage) error {
	var kind, target string
	if json.Unmarshal(res["Type"], &kind) != nil || kind != "dockerfile" {
		return nil
	}
	if json.Unmarshal(res["Target"], &target) != nil || target == "" {
		return nil
	}
	var r trivyMisconfigResult
	var reported []trivyMisconfig
	for _, f := range []struct {
		name string
		into any
	}{{"Misconfigurations", &reported}, {"ExperimentalModifiedFindings", &r.Modified}} {
		if raw := res[f.name]; len(raw) > 0 {
			if err := json.Unmarshal(raw, f.into); err != nil {
				return fmt.Errorf("read its JSON report: %w", err)
			}
		}
	}
	failed := reported
	for _, m := range r.Modified {
		if m.Status == "ignored" && m.Type == "misconfiguration" {
			failed = append(failed, m.Finding)
		}
	}
	for _, f := range failed {
		if f.Status != "FAIL" || f.ID == "" {
			continue
		}
		key := trivyFileCheck{target: target, id: f.ID}
		switch {
		case f.CauseMetadata.StartLine > 1:
		case f.CauseMetadata.StartLine == 1:
			d.ensureWholeFile()[key] = false
		default:
			if whole, seen := d.wholeFile[key]; whole || !seen {
				d.ensureWholeFile()[key] = true
			}
		}
	}
	return nil
}

// ensureWholeFile is d's record of whole-file checks, made on first use.
func (d *trivyMisconfigDoc) ensureWholeFile() map[trivyFileCheck]bool {
	if d.wholeFile == nil {
		d.wholeFile = map[trivyFileCheck]bool{}
	}
	return d.wholeFile
}

// withWholeFileRegions gives each result of Trivy's SARIF that doc records as a check of a Dockerfile
// as a whole the region of the whole file, from line 1 to the file's last line as read from the
// checkout at dir. A result placed anywhere but line 1 alone, and a file that cannot be read or holds
// a single line, keep the region Trivy gave them. SARIF with nothing to change is returned unchanged.
func withWholeFileRegions(sarifOut []byte, doc trivyMisconfigDoc, dir string) ([]byte, error) {
	whole := false
	for _, w := range doc.wholeFile {
		whole = whole || w
	}
	if !whole || len(sarifOut) == 0 {
		return sarifOut, nil
	}
	var log map[string]any
	if err := json.Unmarshal(sarifOut, &log); err != nil {
		return nil, fmt.Errorf("read the SARIF it wrote: %w", err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		// No checkout to read is no file to measure, and the findings keep Trivy's region.
		return sarifOut, nil
	}
	defer func() { _ = root.Close() }()
	lines := map[string]int{}
	changed := false
	runs, _ := log["runs"].([]any)
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
			uri, _ := jsonObject(physical["artifactLocation"])["uri"].(string)
			region := jsonObject(physical["region"])
			if !doc.wholeFile[trivyFileCheck{target: uri, id: rule}] || !lineOneAlone(region) {
				continue
			}
			file := checkoutRelative(dir, uri)
			if file == "" {
				continue
			}
			n, seen := lines[file]
			if !seen {
				n = fileLines(root, file)
				lines[file] = n
			}
			if n > 1 {
				region["endLine"] = n
				changed = true
			}
		}
	}
	if !changed {
		return sarifOut, nil
	}
	return json.Marshal(log)
}

// lineOneAlone reports whether a SARIF region is line 1 and nothing after it.
func lineOneAlone(region map[string]any) bool {
	start, _ := region["startLine"].(float64)
	end, ok := region["endLine"].(float64)
	return start == 1 && (!ok || end <= 1)
}

// fileLines is the number of lines in the file at name in root, a last line without a newline
// included, or 0 for a file that cannot be read.
func fileLines(root *os.Root, name string) int {
	src, ok := readBounded(root, name)
	if !ok {
		return 0
	}
	n := strings.Count(src, "\n")
	if src != "" && !strings.HasSuffix(src, "\n") {
		n++
	}
	return n
}
