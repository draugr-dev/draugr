package sarif

import (
	"encoding/json"
	"sort"
	"strconv"
)

// Version is the SARIF specification version Draugr emits.
const Version = "2.1.0"

const schemaURL = "https://json.schemastore.org/sarif-2.1.0.json"

// The types below mirror the subset of the SARIF 2.1.0 JSON structure that Draugr
// produces and consumes.

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name  string      `json:"name"`
	Rules []sarifRule `json:"rules,omitempty"`
}

type sarifRule struct {
	ID                   string           `json:"id"`
	DefaultConfiguration *sarifRuleConfig `json:"defaultConfiguration,omitempty"`
	Properties           *sarifProperties `json:"properties,omitempty"`
}

type sarifRuleConfig struct {
	Level string `json:"level"`
}

// sarifProperties carries the property-bag fields Draugr reads/writes. "security-severity"
// is the SARIF/GitHub convention for a numeric CVSS-style score, serialized as a string;
// "priority" is Draugr's computed action band.
type sarifProperties struct {
	SecuritySeverity string `json:"security-severity,omitempty"`
	Priority         string `json:"priority,omitempty"`
	// Tool is the originating scanner (e.g. "trivy", "semgrep"). Draugr reports as a single
	// "Draugr" SARIF tool; this preserves per-finding attribution to the scanner that found it.
	Tool string `json:"tool,omitempty"`
	// Tags are rule-level labels. Draugr tags each rule with "scanner:<name>" so consumers
	// (e.g. GitHub code scanning) surface which underlying scanner produced a finding.
	Tags []string `json:"tags,omitempty"`
}

type sarifResult struct {
	RuleID       string             `json:"ruleId,omitempty"`
	Level        string             `json:"level,omitempty"`
	Message      sarifMessage       `json:"message"`
	Locations    []sarifLocation    `json:"locations,omitempty"`
	Suppressions []sarifSuppression `json:"suppressions,omitempty"`
	Properties   *sarifProperties   `json:"properties,omitempty"`
}

// sarifSuppression marks a result the author or tool has suppressed (e.g. Semgrep's
// in-source `nosem` comments). A result with any suppression is not an active finding.
type sarifSuppression struct {
	Kind string `json:"kind"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           *sarifRegion  `json:"region,omitempty"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine,omitempty"`
}

// driverName is the single SARIF tool Draugr reports as. Draugr is an orchestrator that
// normalizes many scanners into one report, so it presents as one tool; each finding keeps its
// originating scanner in properties.tool. This gives consumers (e.g. GitHub code scanning) a
// single "Draugr" analysis tool instead of one per underlying scanner.
const driverName = "Draugr"

// MarshalSARIF serializes the report to standard SARIF 2.1.0 JSON as a single "Draugr" run,
// with each result's originating scanner recorded in its property bag ("tool").
func (r Report) MarshalSARIF() ([]byte, error) {
	run := sarifRun{Tool: sarifTool{Driver: sarifDriver{Name: driverName}}, Results: []sarifResult{}}
	// Track which scanner(s) produced each ruleId so the emitted rules[] can carry a
	// "scanner:<name>" tag — the only place GitHub code scanning surfaces the underlying tool.
	ruleScanners := map[string]map[string]bool{}
	var ruleOrder []string
	for _, res := range r.Results {
		tool := res.Tool
		if tool == "" {
			tool = r.Tool
		}
		if res.RuleID != "" && tool != "" {
			if ruleScanners[res.RuleID] == nil {
				ruleScanners[res.RuleID] = map[string]bool{}
				ruleOrder = append(ruleOrder, res.RuleID)
			}
			ruleScanners[res.RuleID][tool] = true
		}
		sr := sarifResult{
			RuleID:  res.RuleID,
			Level:   string(res.Level),
			Message: sarifMessage{Text: res.Message},
		}
		if res.Location.URI != "" {
			loc := sarifLocation{PhysicalLocation: sarifPhysical{
				ArtifactLocation: sarifArtifact{URI: res.Location.URI},
			}}
			if res.Location.StartLine > 0 {
				loc.PhysicalLocation.Region = &sarifRegion{StartLine: res.Location.StartLine}
			}
			sr.Locations = append(sr.Locations, loc)
		}
		if tool != "" || res.HasScore || res.Priority != "" {
			sr.Properties = &sarifProperties{Tool: tool, Priority: res.Priority}
			if res.HasScore {
				sr.Properties.SecuritySeverity = strconv.FormatFloat(res.Score, 'f', -1, 64)
			}
		}
		run.Results = append(run.Results, sr)
	}
	// Emit one rule per ruleId, tagged with its originating scanner(s). GitHub matches a
	// result to its rule by ruleId and shows the rule's tags on the alert.
	for _, id := range ruleOrder {
		scanners := make([]string, 0, len(ruleScanners[id]))
		for s := range ruleScanners[id] {
			scanners = append(scanners, s)
		}
		sort.Strings(scanners)
		tags := make([]string, 0, len(scanners))
		for _, s := range scanners {
			tags = append(tags, "scanner:"+s)
		}
		run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, sarifRule{
			ID:         id,
			Properties: &sarifProperties{Tags: tags},
		})
	}
	return json.MarshalIndent(sarifLog{Schema: schemaURL, Version: Version, Runs: []sarifRun{run}}, "", "  ")
}

// parseSecuritySeverity reads the numeric "security-severity" score (a string per SARIF)
// from a property bag, reporting whether a valid score was present.
func parseSecuritySeverity(p *sarifProperties) (float64, bool) {
	if p == nil || p.SecuritySeverity == "" {
		return 0, false
	}
	score, err := strconv.ParseFloat(p.SecuritySeverity, 64)
	if err != nil {
		return 0, false
	}
	return score, true
}

// FromSARIF parses standard SARIF 2.1.0 JSON into a Report, flattening all runs and
// setting each result's Tool from its run's driver name.
func FromSARIF(data []byte) (Report, error) {
	var log sarifLog
	if err := json.Unmarshal(data, &log); err != nil {
		return Report{}, err
	}
	var out Report
	for i, run := range log.Runs {
		if i == 0 {
			out.Tool = run.Tool.Driver.Name
		}
		// SARIF lets a result omit its level and inherit it from the rule's
		// defaultConfiguration. Some tools (e.g. Semgrep) rely on this. Index the rules so
		// we can resolve a result's severity from its ruleId.
		ruleLevel := make(map[string]Level, len(run.Tool.Driver.Rules))
		// Rules also carry a numeric "security-severity" (CVSS-style) that results inherit
		// by ruleId, the way many tools (e.g. Trivy) express severity.
		ruleScore := make(map[string]float64, len(run.Tool.Driver.Rules))
		for _, rule := range run.Tool.Driver.Rules {
			if rule.DefaultConfiguration != nil && rule.DefaultConfiguration.Level != "" {
				ruleLevel[rule.ID] = Level(rule.DefaultConfiguration.Level)
			}
			if score, ok := parseSecuritySeverity(rule.Properties); ok {
				ruleScore[rule.ID] = score
			}
		}
		for _, sr := range run.Results {
			// Skip results the tool reports as suppressed (e.g. Semgrep in-source `nosem`
			// comments). Per SARIF, a result with any suppression is not an active finding.
			if len(sr.Suppressions) > 0 {
				continue
			}
			level := Level(sr.Level)
			if level == "" {
				// Resolution order per SARIF 2.1.0: the result's own level, then its rule's
				// defaultConfiguration.level, then "warning". Some tools (e.g. Gitleaks) omit
				// it entirely and fall through to the default.
				if rl, ok := ruleLevel[sr.RuleID]; ok {
					level = rl
				} else {
					level = LevelWarning
				}
			}
			// Prefer the per-result originating tool (properties.tool, written when Draugr
			// emits a single "Draugr" run) over the run's driver name, so round-tripping
			// Draugr's own SARIF preserves each finding's scanner.
			tool := run.Tool.Driver.Name
			if sr.Properties != nil && sr.Properties.Tool != "" {
				tool = sr.Properties.Tool
			}
			res := Result{
				Tool:    tool,
				RuleID:  sr.RuleID,
				Level:   level,
				Message: sr.Message.Text,
			}
			if len(sr.Locations) > 0 {
				res.Location.URI = sr.Locations[0].PhysicalLocation.ArtifactLocation.URI
				if region := sr.Locations[0].PhysicalLocation.Region; region != nil {
					res.Location.StartLine = region.StartLine
				}
			}
			// A numeric score on the result overrides the rule's; otherwise inherit it.
			if score, ok := parseSecuritySeverity(sr.Properties); ok {
				res.Score, res.HasScore = score, true
			} else if score, ok := ruleScore[sr.RuleID]; ok {
				res.Score, res.HasScore = score, true
			}
			if sr.Properties != nil && sr.Properties.Priority != "" {
				res.Priority = sr.Properties.Priority
			}
			out.Results = append(out.Results, res)
		}
	}
	return out, nil
}
