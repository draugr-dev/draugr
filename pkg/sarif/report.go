package sarif

// This is a v0 placeholder sufficient for the plugin contract. The full SARIF 2.1.0
// model plus merge/deduplication logic land with the SARIF core work.

// Level is the severity of a result, mirroring SARIF's result.level.
type Level string

// The SARIF result levels.
const (
	LevelError   Level = "error"
	LevelWarning Level = "warning"
	LevelNote    Level = "note"
	LevelNone    Level = "none"
)

// Report is a set of findings produced by a scanner, normalized to SARIF semantics.
type Report struct {
	// Tool is the name of the scanner that produced the report.
	Tool string `json:"tool"`
	// Results are the individual findings.
	Results []Result `json:"results"`
}

// Result is a single finding.
type Result struct {
	RuleID   string   `json:"ruleId"`
	Level    Level    `json:"level"`
	Message  string   `json:"message"`
	Location Location `json:"location,omitempty"`
}

// Location points at where a finding was observed.
type Location struct {
	URI       string `json:"uri,omitempty"`
	StartLine int    `json:"startLine,omitempty"`
}
