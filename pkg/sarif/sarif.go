package sarif

import "encoding/json"

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
}

type sarifRuleConfig struct {
	Level string `json:"level"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId,omitempty"`
	Level     string          `json:"level,omitempty"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
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

// MarshalSARIF serializes the report to standard SARIF 2.1.0 JSON. Results are grouped
// into one run per tool.
func (r Report) MarshalSARIF() ([]byte, error) {
	byTool := make(map[string][]Result)
	var order []string
	for _, res := range r.Results {
		tool := res.Tool
		if tool == "" {
			tool = r.Tool
		}
		if _, ok := byTool[tool]; !ok {
			order = append(order, tool)
		}
		byTool[tool] = append(byTool[tool], res)
	}

	log := sarifLog{Schema: schemaURL, Version: Version, Runs: []sarifRun{}}
	for _, tool := range order {
		run := sarifRun{Tool: sarifTool{Driver: sarifDriver{Name: tool}}, Results: []sarifResult{}}
		for _, res := range byTool[tool] {
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
			run.Results = append(run.Results, sr)
		}
		log.Runs = append(log.Runs, run)
	}
	return json.MarshalIndent(log, "", "  ")
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
		for _, rule := range run.Tool.Driver.Rules {
			if rule.DefaultConfiguration != nil && rule.DefaultConfiguration.Level != "" {
				ruleLevel[rule.ID] = Level(rule.DefaultConfiguration.Level)
			}
		}
		for _, sr := range run.Results {
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
			res := Result{
				Tool:    run.Tool.Driver.Name,
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
			out.Results = append(out.Results, res)
		}
	}
	return out, nil
}
