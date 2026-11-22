package scanners

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// veracodePipeline is the name Veracode Pipeline Scan's findings are reported under.
const veracodePipeline = "veracode-pipeline-scan"

// errNotVeracodePipelineJSON is the error of a file that is not Pipeline Scan's results.json.
var errNotVeracodePipelineJSON = errors.New("not Veracode Pipeline Scan JSON. Run Pipeline Scan with -jo true and import its results.json")

// errVeracodeFlawIncomplete is the error of a flaw missing what Pipeline Scan writes for every one.
var errVeracodeFlawIncomplete = errors.New("a flaw names no CWE, severity or file, as Pipeline Scan writes every flaw. " +
	"Import the results.json it wrote, unedited")

// veracodePipelineDoc is the part of Pipeline Scan's results.json the import reads. The fields are
// the ones Veracode's own converter to SARIF reads (src/PipelineScanResult.d.ts in
// github.com/veracode/veracode-pipeline-scan-results-to-sarif).
type veracodePipelineDoc struct {
	ScanStatus   string            `json:"scan_status"`
	Message      string            `json:"message"`
	PipelineScan string            `json:"pipeline_scan"`
	Findings     []veracodeFinding `json:"findings"`
}

// veracodeFinding is one flaw Pipeline Scan reported.
type veracodeFinding struct {
	Title       string          `json:"title"`
	Severity    *int            `json:"severity"`
	IssueType   string          `json:"issue_type"`
	CWEID       json.RawMessage `json:"cwe_id"`
	DisplayText string          `json:"display_text"`
	Files       struct {
		SourceFile struct {
			File string `json:"file"`
			Line int    `json:"line"`
		} `json:"source_file"`
	} `json:"files"`
	FlawMatch map[string]json.RawMessage `json:"flaw_match"`
}

// veracodeSeverities are Veracode's severities, 0 to 5, by the names Veracode gives them, with the
// band each is read as. The names and the bands are those of Veracode's own converter to SARIF
// (mapVeracodeSeverityToCVSS in src/utils.ts, citing
// https://docs.veracode.com/r/review_severity_exploitability#veracode-finding-severities), which
// writes Very High as a critical score, High as high, Medium as medium, and Low and Very Low as low.
// It writes Informational as GitHub's "none", which Draugr has no band for, so it is low, the
// mildest band, with the rating's name saying it is Veracode's Informational.
var veracodeSeverities = []struct {
	name string
	band sarif.Severity
}{
	{"Informational", sarif.SeverityLow},
	{"Very Low", sarif.SeverityLow},
	{"Low", sarif.SeverityLow},
	{"Medium", sarif.SeverityMedium},
	{"High", sarif.SeverityHigh},
	{"Very High", sarif.SeverityCritical},
}

// readVeracodePipelineImport reads the results.json Veracode's Pipeline Scan writes with `-jo true`.
//
// A finding is a flaw at a file and line, under its CWE, rated by Veracode's severity, and
// fingerprinted by Veracode's flaw hash, its count and its ordinal, the keys Veracode's converter
// gives code scanning, so an alert keeps its identity across uploads from either. Its message is the
// flaw's type and the call Veracode flagged, and its detail Veracode's explanation without markup.
//
// Pipeline Scan analyzes a build, and names each file as the build recorded it: a path in the
// repository for JavaScript, a bare file name for Java's classes. A name that is not a file of the
// component's one local checkout is matched to the one file there whose path ends with it, as
// Veracode's converter does; where none or several do, the finding keeps the name as written.
//
// A scan that did not succeed is refused, since its file may hold some of the flaws or none.
func readVeracodePipelineImport(data []byte, ft plugin.FileTarget) (importRead, error) {
	// The key is matched exactly: Go's decoder matches field names without regard to case. A file
	// with no findings list, or an empty one with no scan status, would read as a clean scan.
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil || !bytes.HasPrefix(bytes.TrimSpace(top["findings"]), []byte("[")) {
		return importRead{}, errNotVeracodePipelineJSON
	}
	var doc veracodePipelineDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return importRead{}, errNotVeracodePipelineJSON
	}
	if _, stated := top["scan_status"]; !stated && len(doc.Findings) == 0 {
		return importRead{}, errNotVeracodePipelineJSON
	}
	if doc.ScanStatus != "" && doc.ScanStatus != "SUCCESS" {
		status := doc.ScanStatus
		if msg := strings.TrimSpace(doc.Message); msg != "" {
			status += ": " + strings.TrimSuffix(msg, ".")
		}
		return importRead{}, fmt.Errorf("scan status %s. Draugr reads a scan that succeeded. Run Pipeline Scan again", status)
	}

	root := importRoot(ft.Repositories)
	place := veracodePlacer(root)
	rep := sarif.Report{Tool: veracodePipeline, Rules: map[string]sarif.Rule{}}
	rated := make([]string, 0, len(doc.Findings))
	for _, f := range doc.Findings {
		found, rule, err := veracodeResult(f, place)
		if err != nil {
			return importRead{}, err
		}
		rep.Results = append(rep.Results, found)
		rated = append(rated, "Veracode's severity")
		if _, seen := rep.Rules[found.RuleID]; !seen {
			rep.Rules[found.RuleID] = rule
		}
	}
	outside := relativeToCheckouts(rep.Results, checkoutRoots(ft.Repositories))

	var run importRun
	run.Tool.Driver = importDriver{Name: "Veracode Pipeline Scan", Version: doc.PipelineScan}
	run.Results = make([]json.RawMessage, len(rep.Results))
	return importRead{rep: rep, outside: outside, meta: importLog{Runs: []importRun{run}}, rated: rated}, nil
}

// veracodeResult is the finding and the rule of one flaw.
func veracodeResult(f veracodeFinding, place func(string) string) (sarif.Result, sarif.Rule, error) {
	cwe := strings.Trim(strings.TrimSpace(string(f.CWEID)), `"`)
	if _, err := strconv.Atoi(cwe); err != nil || f.Severity == nil || f.Files.SourceFile.File == "" {
		return sarif.Result{}, sarif.Rule{}, errVeracodeFlawIncomplete
	}
	if *f.Severity < 0 || *f.Severity >= len(veracodeSeverities) {
		return sarif.Result{}, sarif.Rule{}, fmt.Errorf("severity %d; Veracode rates a flaw 0 to 5. Import the results.json "+
			"Pipeline Scan wrote, unedited", *f.Severity)
	}
	sev := veracodeSeverities[*f.Severity]
	id := "CWE-" + cwe
	found := sarif.Result{
		Tool:     veracodePipeline,
		RuleID:   id,
		Level:    osvLevel(sev.band),
		Message:  veracodeMessage(f),
		Detail:   veracodeText(f.DisplayText),
		Location: sarif.Location{URI: place(f.Files.SourceFile.File), StartLine: f.Files.SourceFile.Line},
		CWE:      []string{id},
		Rating: newRating(sev.band, map[string]string{"severity": strconv.Itoa(*f.Severity)},
			"Veracode "+sev.name),
	}
	found.PartialFingerprints = veracodeFingerprints(f.FlawMatch)
	rule := sarif.Rule{Name: id, ShortDescription: f.IssueType,
		HelpURI: "https://cwe.mitre.org/data/definitions/" + cwe + ".html"}
	return found, rule, nil
}

// veracodeFingerprintKeys are the flaw_match fields Veracode's converter writes as a result's
// partialFingerprints, by the key it writes each under (src/Converter.ts).
var veracodeFingerprintKeys = [][2]string{
	{"flaw_hash", "flawHash"}, {"flaw_hash_count", "flawHashCount"}, {"flaw_hash_ordinal", "flawHashOrdinal"},
	{"cause_hash", "causeHash"}, {"cause_hash_count", "causeHashCount"}, {"cause_hash_ordinal", "causeHashOrdinal"},
	{"procedure_hash", "procedureHash"}, {"prototype_hash", "prototypeHash"},
}

// veracodeFingerprints are a flaw's partialFingerprints, under the keys Veracode's converter gives
// code scanning, so an alert keeps its identity whichever of the two wrote the upload. Nil where the
// flaw states no flaw hash, which is the one that identifies it.
func veracodeFingerprints(match map[string]json.RawMessage) map[string]string {
	if len(match) == 0 {
		return nil
	}
	out := map[string]string{}
	for _, k := range veracodeFingerprintKeys {
		raw, ok := match[k[0]]
		if !ok {
			continue
		}
		if v := strings.Trim(strings.TrimSpace(string(raw)), `"`); v != "" && v != "null" {
			out[k[1]] = v
		}
	}
	if out["flawHash"] == "" {
		return nil
	}
	return out
}

// veracodeMessage is the flaw's type and the call Veracode flagged, as `SQL Injection … at
// java.sql.Statement.executeQuery`.
func veracodeMessage(f veracodeFinding) string {
	switch {
	case f.IssueType == "":
		return f.Title
	case f.Title == "":
		return f.IssueType
	}
	return f.IssueType + " at " + f.Title
}

// htmlTag is a tag of the markup Veracode writes its explanation in.
var htmlTag = regexp.MustCompile(`<[^>]*>`)

// veracodeReferences is the span of Veracode's explanation that lists its references, as links whose
// text alone ("CWE", "OWASP") says nothing once the links are gone.
var veracodeReferences = regexp.MustCompile(`(?s)<span>\s*References:.*?</span>`)

// veracodeText is Veracode's explanation as text: the flaw and how to fix it, without the list of
// references, its tags removed, its entities read, and its whitespace collapsed.
func veracodeText(s string) string {
	s = veracodeReferences.ReplaceAllString(s, " ")
	return strings.Join(strings.Fields(html.UnescapeString(htmlTag.ReplaceAllString(s, " "))), " ")
}

// veracodePlacer returns the path in the checkout at root that a file Pipeline Scan names is: the
// name itself where it is a file there, else the one file whose path ends with it, else the name as
// written. With no local checkout every name is kept as written.
func veracodePlacer(root string) func(string) string {
	if root == "" {
		return func(name string) string { return name }
	}
	var files []string
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // an unreadable directory is not a reason to fail the import
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if rel, err := filepath.Rel(root, p); err == nil {
			files = append(files, filepath.ToSlash(rel))
		}
		return nil
	})
	return func(name string) string {
		clean := strings.TrimPrefix(filepath.ToSlash(name), "/")
		if filepath.IsAbs(name) {
			return name
		}
		if info, err := os.Stat(filepath.Join(root, filepath.FromSlash(clean))); err == nil && !info.IsDir() {
			return clean
		}
		match := ""
		for _, f := range files {
			if strings.HasSuffix(f, "/"+clean) {
				if match != "" {
					return name
				}
				match = f
			}
		}
		if match == "" {
			return name
		}
		return match
	}
}
