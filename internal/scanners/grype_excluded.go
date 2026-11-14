package scanners

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// Grype drops a match its own configuration ignores from the SARIF it writes, with no suppression
// in its place, so an exclusion somebody wrote in `.grype.yaml` and a vulnerability nobody ever had
// look the same in the report. `--show-suppressed` does not help: it applies to the table output
// alone. The JSON report lists every ignored match, with the rules that ignored it, and Grype
// writes it in the same invocation as the SARIF when asked for a second output. So the scan runs
// once, as it did, and the ignored matches are added to the report as suppressed results as it is
// read. From there they travel the path every other scanner's suppressions do.

// grypeExclusionArgs has Grype write its JSON report to path, beside the SARIF on stdout.
func grypeExclusionArgs(path string) []string {
	return []string{"-o", "json=" + path}
}

// runGrypeRecordingExclusions runs a Grype command with the JSON report added, and returns the SARIF
// and the JSON as Grype wrote them, joined as grypeReports.bytes describes. parseGrypeSARIF reads
// both, adding every match Grype's configuration ignored as a suppressed result.
//
// A run that wrote no JSON is an error rather than a report with nothing set aside: an empty
// list claims the configuration excluded nothing, which Draugr cannot know.
func runGrypeRecordingExclusions(run func(argv []string) ([]byte, error), argv []string) ([]byte, error) {
	f, err := os.CreateTemp("", "draugr-grype-*.json")
	if err != nil {
		return nil, err
	}
	path := f.Name()
	if err := f.Close(); err != nil {
		return nil, err
	}
	defer func() { _ = os.Remove(path) }()

	out, err := run(append(slices.Clone(argv), grypeExclusionArgs(path)...))
	if err != nil {
		return nil, err
	}
	doc, err := os.ReadFile(path) // #nosec G304 -- a path this function just created
	if err != nil {
		return nil, err
	}
	if len(doc) == 0 {
		return nil, errors.New("wrote no JSON report, so what its configuration ignored cannot be reported")
	}
	return grypeReports{SARIF: out, JSON: doc}.bytes(), nil
}

// grypeReports are the two reports one Grype invocation writes: the SARIF on stdout and the JSON
// report beside it, each as Grype wrote it.
type grypeReports struct {
	SARIF []byte
	JSON  []byte
}

// grypeReportsHead opens the output runGrypeRecordingExclusions returns. The SARIF's length in bytes
// and a newline follow it, then the SARIF and the JSON.
//
// Joined end to end and read once each, rather than the JSON's facts written into the SARIF and the
// SARIF read back: each report grows with the findings, and every rewrite of one is a decode and an
// encode of all of it.
const grypeReportsHead = "draugr-grype-reports "

// bytes is the reports joined as grypeReportsHead describes.
func (r grypeReports) bytes() []byte {
	head := grypeReportsHead + strconv.Itoa(len(r.SARIF)) + "\n"
	out := make([]byte, 0, len(head)+len(r.SARIF)+len(r.JSON))
	return append(append(append(out, head...), r.SARIF...), r.JSON...)
}

// readGrypeReports splits output runGrypeRecordingExclusions returned into the two reports, each
// sharing out's memory rather than copied from it.
func readGrypeReports(out []byte) (grypeReports, error) {
	rest, ok := bytes.CutPrefix(out, []byte(grypeReportsHead))
	size, rest, found := bytes.Cut(rest, []byte("\n"))
	n, err := strconv.Atoi(string(size))
	if !ok || !found || err != nil || n < 0 || n > len(rest) {
		return grypeReports{}, errors.New("not the reports a Grype run returns")
	}
	return grypeReports{SARIF: rest[:n:n], JSON: rest[n:]}, nil
}

// grypeDoc is the slice of Grype's JSON report Draugr reads: each match it reported, each it
// ignored, and what it scanned.
type grypeDoc struct {
	Matches        []grypeMatch `json:"matches"`
	IgnoredMatches []grypeMatch `json:"ignoredMatches"`
	Source         struct {
		Type string `json:"type"`
		// Target is the directory for a directory scan and an object for an image, whose userInput
		// is the reference Grype was given.
		Target json.RawMessage `json:"target"`
	} `json:"source"`
}

type grypeMatch struct {
	Vulnerability          grypeVulnerability   `json:"vulnerability"`
	RelatedVulnerabilities []grypeVulnerability `json:"relatedVulnerabilities"`
	MatchDetails           []struct {
		Type    string `json:"type"`
		Matcher string `json:"matcher"`
	} `json:"matchDetails"`
	Artifact struct {
		Name      string `json:"name"`
		Version   string `json:"version"`
		Type      string `json:"type"`
		PURL      string `json:"purl"`
		Locations []struct {
			Path       string `json:"path"`
			AccessPath string `json:"accessPath"`
		} `json:"locations"`
	} `json:"artifact"`
	AppliedIgnoreRules []grypeIgnoreRule `json:"appliedIgnoreRules"`
}

type grypeVulnerability struct {
	ID          string `json:"id"`
	DataSource  string `json:"dataSource"`
	Namespace   string `json:"namespace"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	CVSS        []struct {
		Metrics struct {
			BaseScore float64 `json:"baseScore"`
		} `json:"metrics"`
	} `json:"cvss"`
	Fix struct {
		Versions []string `json:"versions"`
	} `json:"fix"`
}

// grypeIgnoreRule is one entry of Grype's `ignore:` list, in the shape both its configuration file
// and its JSON report write it. include-aliases is left out: the report omits it when false, and it
// changes which identifiers a rule matches rather than which rule it is.
type grypeIgnoreRule struct {
	Vulnerability    string             `json:"vulnerability" yaml:"vulnerability"`
	Reason           string             `json:"reason" yaml:"reason"`
	Namespace        string             `json:"namespace" yaml:"namespace"`
	FixState         string             `json:"fix-state" yaml:"fix-state"`
	VexStatus        string             `json:"vex-status" yaml:"vex-status"`
	VexJustification string             `json:"vex-justification" yaml:"vex-justification"`
	MatchType        string             `json:"match-type" yaml:"match-type"`
	Package          grypeIgnorePackage `json:"package" yaml:"package"`
}

type grypeIgnorePackage struct {
	Name         string `json:"name" yaml:"name"`
	Version      string `json:"version" yaml:"version"`
	Language     string `json:"language" yaml:"language"`
	Type         string `json:"type" yaml:"type"`
	Location     string `json:"location" yaml:"location"`
	UpstreamName string `json:"upstream-name" yaml:"upstream-name"`
}

// grypeDefaultRules are the rules Grype applies with no configuration at all: a kernel headers
// package matched only through its upstream kernel. They are the tool's own matching policy, and
// reported as exclusions they would read as a decision somebody made about every image with a
// kernel headers package in it.
var grypeDefaultRules = []grypeIgnoreRule{
	{MatchType: "exact-indirect-match", Package: grypeIgnorePackage{Name: "kernel-headers", Type: "rpm", UpstreamName: "kernel"}},
	{MatchType: "exact-indirect-match", Package: grypeIgnorePackage{Name: "linux(-.*)?-headers-.*", Type: "deb", UpstreamName: "linux.*"}},
	{MatchType: "exact-indirect-match", Package: grypeIgnorePackage{Name: "linux-libc-dev", Type: "deb", UpstreamName: "linux"}},
	{MatchType: "exact-indirect-match", Package: grypeIgnorePackage{Name: "linux-kbuild-.*", Type: "deb", UpstreamName: "linux.*"}},
}

// grypeConfigFiles are the files Grype reads its configuration from in the directory it runs in,
// in the order it looks for them.
var grypeConfigFiles = []string{".grype.yaml", filepath.Join(".grype", "config.yaml")}

// grypeRuleFile is one configuration file in the directory Grype ran in, and the rules it holds.
type grypeRuleFile struct {
	name  string
	rules []grypeIgnoreRule
}

// grypeConfigRules reads the ignore rules from each configuration file in dir.
//
// The JSON report says which rules ignored a match and not which file they came from, and Grype
// merges the file here with the one in the user's home directory. So the file is named only where
// it holds the rule, and a rule found in none of these files is reported with no file rather than
// attributed to one that might not hold it. A file that does not parse names nothing; Grype itself
// refuses to run with it, so the scan has already failed with Grype's own message.
func grypeConfigRules(dir string) []grypeRuleFile {
	var out []grypeRuleFile
	for _, name := range grypeConfigFiles {
		data, err := os.ReadFile(filepath.Join(dir, name)) // #nosec G304 -- a fixed name under the scanned directory
		if err != nil {
			continue
		}
		var cfg struct {
			Ignore []grypeIgnoreRule `yaml:"ignore"`
		}
		if yaml.Unmarshal(data, &cfg) != nil {
			continue
		}
		out = append(out, grypeRuleFile{name: filepath.ToSlash(name), rules: cfg.Ignore})
	}
	return out
}

// withGrypeExclusions adds each match Grype's configuration ignored to report, as a result carrying
// a suppression with origin scanner, and its rule where report has none of that id. dir is the
// directory Grype ran in, where it looks for `.grype.yaml`, and so where the rule that ignored a
// match is looked for. Empty means the working directory.
//
// The ignored matches are written as a SARIF document of their own and read by the SARIF reader, so
// they arrive as Grype's reported results do, and only that document is encoded and decoded.
func withGrypeExclusions(report *sarif.Report, doc grypeDoc, dir string) error {
	image := grypeImageRef(doc)
	var results, rules []any
	var aliases [][]string
	var files []grypeRuleFile
	read, ruled := false, map[any]bool{}
	for _, m := range doc.IgnoredMatches {
		applied := slices.DeleteFunc(slices.Clone(m.AppliedIgnoreRules), func(r grypeIgnoreRule) bool {
			return slices.Contains(grypeDefaultRules, r)
		})
		if len(applied) == 0 || m.Vulnerability.ID == "" || m.Artifact.Name == "" {
			continue
		}
		if !read {
			files, read = grypeConfigRules(dir), true
		}
		result, rule := grypeExcludedResult(m, applied, image, files)
		results = append(results, result)
		aliases = append(aliases, grypeMatchAliases(m))
		// One rule per id, the first, as Grype writes one per advisory and package name.
		if !ruled[rule["id"]] {
			ruled[rule["id"]] = true
			rules = append(rules, rule)
		}
	}
	if len(results) == 0 {
		return nil
	}
	out, err := json.Marshal(map[string]any{"version": "2.1.0", "runs": []any{map[string]any{
		"tool":    map[string]any{"driver": map[string]any{"name": "grype", "rules": rules}},
		"results": results,
	}}})
	if err != nil {
		return err
	}
	ignored, err := sarif.FromSARIF(out)
	if err != nil {
		return err
	}
	for i := range ignored.Results {
		ignored.Results[i].Aliases = aliases[i]
	}
	if report.Tool == "" {
		report.Tool = ignored.Tool
	}
	for id, rule := range ignored.Rules {
		if _, ok := report.Rules[id]; ok {
			continue
		}
		if report.Rules == nil {
			report.Rules = map[string]sarif.Rule{}
		}
		report.Rules[id] = rule
	}
	report.Results = append(report.Results, ignored.Results...)
	return nil
}

// grypeImageRef is the reference an image scan was given, or "" for a directory.
func grypeImageRef(doc grypeDoc) string {
	if doc.Source.Type != "image" {
		return ""
	}
	var target struct {
		UserInput string `json:"userInput"`
	}
	if json.Unmarshal(doc.Source.Target, &target) != nil {
		return ""
	}
	return target.UserInput
}

// grypeExcludedResult writes one ignored match as a SARIF result and its rule, in the shape Grype
// gives a match it reports, so everything that reads Grype's SARIF reads this the same way: the
// score from security-severity, the package from the rule's help text and purl. The result also
// carries its own match's package, as a reported one does, because an ignored match can share its
// rule with others at other versions.
func grypeExcludedResult(m grypeMatch, applied []grypeIgnoreRule, image string, files []grypeRuleFile) (result, rule map[string]any) {
	v := m.Vulnerability
	severity := strings.ToLower(v.Severity)
	ruleID := v.ID + "-" + m.Artifact.Name
	var path string
	if len(m.Artifact.Locations) > 0 {
		path = m.Artifact.Locations[0].Path
	}
	message := fmt.Sprintf("A %s vulnerability in %s package: %s, version %s was found at: %s",
		severity, m.Artifact.Type, m.Artifact.Name, m.Artifact.Version, path)
	if image != "" {
		message = fmt.Sprintf("A %s vulnerability in %s package: %s, version %s was found in image %s at: %s",
			severity, m.Artifact.Type, m.Artifact.Name, m.Artifact.Version, image, path)
	}

	suppression := map[string]any{"kind": "external", "properties": grypeSuppressionProperties(applied, files)}
	if reason := grypeReason(applied); reason != "" {
		suppression["justification"] = reason
	}
	result = map[string]any{
		"ruleId":  ruleID,
		"level":   grypeLevel(severity),
		"message": map[string]any{"text": message},
		"locations": []any{map[string]any{"physicalLocation": map[string]any{
			"artifactLocation": map[string]any{"uri": path},
			"region":           map[string]any{"startLine": 1, "startColumn": 1, "endLine": 1, "endColumn": 1},
		}}},
		"suppressions": []any{suppression},
		"properties":   map[string]any{"package": grypeMatchPackage(m)},
	}

	help := strings.Join([]string{
		"Vulnerability " + v.ID,
		"Severity: " + severity,
		"Package: " + m.Artifact.Name,
		"Version: " + m.Artifact.Version,
		"Fix Version: " + grypeMatchPackage(m).FixedVersion,
		"Type: " + m.Artifact.Type,
		"Location: " + path,
		"Data Namespace: " + v.Namespace,
		fmt.Sprintf("Link: [%s](%s)", v.ID, v.DataSource),
	}, "\n")
	properties := map[string]any{}
	if m.Artifact.PURL != "" {
		properties["purls"] = []string{m.Artifact.PURL}
	}
	if score := grypeScore(m, severity); score != "" {
		properties["security-severity"] = score
	}
	rule = map[string]any{
		"id":               ruleID,
		"name":             grypeMatcherName(m),
		"shortDescription": map[string]any{"text": fmt.Sprintf("%s %s vulnerability for %s package", v.ID, severity, m.Artifact.Name)},
		"helpUri":          v.DataSource,
		"help":             map[string]any{"text": help},
		"properties":       properties,
	}
	if d := grypeDescription(m); d != "" {
		rule["fullDescription"] = map[string]any{"text": d}
	}
	return result, rule
}

// grypeSuppressionProperties records the suppression as the scanner's own, with the configuration
// file that holds the rule where one of the files Grype read here does.
func grypeSuppressionProperties(applied []grypeIgnoreRule, files []grypeRuleFile) map[string]any {
	props := map[string]any{"origin": "scanner"}
	for _, f := range files {
		for _, r := range applied {
			if slices.Contains(f.rules, r) {
				props["source"] = f.name
				return props
			}
		}
	}
	return props
}

// grypeReason is the reason the rules that ignored a match gave, each once, in the order Grype
// applied them.
func grypeReason(applied []grypeIgnoreRule) string {
	var reasons []string
	for _, r := range applied {
		if r.Reason != "" && !slices.Contains(reasons, r.Reason) {
			reasons = append(reasons, r.Reason)
		}
	}
	return strings.Join(reasons, "; ")
}

// grypeLevel maps a Grype severity to the SARIF level Grype writes for it.
func grypeLevel(severity string) string {
	switch severity {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	}
	return "note"
}

// grypeScore is the score Grype writes as security-severity: the highest CVSS base score the
// vulnerability carries, or the related advisory's where it carries none. With no score at all,
// the lowest score of the band the severity names, so the finding lands in the band Grype gave it
// rather than in none.
func grypeScore(m grypeMatch, severity string) string {
	best := 0.0
	for _, vulns := range [][]grypeVulnerability{{m.Vulnerability}, m.RelatedVulnerabilities} {
		for _, v := range vulns {
			for _, c := range v.CVSS {
				best = max(best, c.Metrics.BaseScore)
			}
		}
		if best > 0 {
			return fmt.Sprintf("%.1f", best)
		}
	}
	return map[string]string{"critical": "9.0", "high": "7.0", "medium": "4.0", "low": "0.1"}[severity]
}

// grypeMatcherName is the rule name Grype writes: its matcher and the kind of match, run together,
// PythonMatcherExactDirectMatch.
func grypeMatcherName(m grypeMatch) string {
	if len(m.MatchDetails) == 0 {
		return ""
	}
	var b strings.Builder
	for _, part := range []string{m.MatchDetails[0].Matcher, m.MatchDetails[0].Type} {
		for _, word := range strings.Split(part, "-") {
			if word != "" {
				b.WriteString(strings.ToUpper(word[:1]) + word[1:])
			}
		}
	}
	return b.String()
}

// grypeDescription is the vulnerability's description, or its related advisory's where Grype's
// record for the identifier it reported carries none.
func grypeDescription(m grypeMatch) string {
	if m.Vulnerability.Description != "" {
		return m.Vulnerability.Description
	}
	for _, v := range m.RelatedVulnerabilities {
		if v.Description != "" {
			return v.Description
		}
	}
	return ""
}
