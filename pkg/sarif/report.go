// Package sarif provides Draugr's result currency: a pragmatic model of SARIF 2.1.0
// findings, plus merge and deduplication. Every scanner normalizes its output to a
// Report; the engine merges reports and the result can be serialized to standard SARIF
// JSON for GitHub / Azure DevOps / GitLab.
package sarif

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
)

// Level is the severity of a result, mirroring SARIF's result.level.
type Level string

// The SARIF result levels.
const (
	LevelError   Level = "error"
	LevelWarning Level = "warning"
	LevelNote    Level = "note"
	LevelNone    Level = "none"
)

// Rank orders levels from most to least severe (higher is worse): error=3,
// warning=2, note=1, none/unknown=0.
func (l Level) Rank() int {
	switch l {
	case LevelError:
		return 3
	case LevelWarning:
		return 2
	case LevelNote:
		return 1
	default:
		return 0
	}
}

// AtLeast reports whether l is at least as severe as other.
func (l Level) AtLeast(other Level) bool { return l.Rank() >= other.Rank() }

// Location points at where a finding was observed.
type Location struct {
	URI       string `json:"uri,omitempty"`
	StartLine int    `json:"startLine,omitempty"`
}

// Result is a single finding.
type Result struct {
	// Tool is the scanner that produced the finding.
	Tool     string   `json:"tool,omitempty"`
	RuleID   string   `json:"ruleId"`
	Level    Level    `json:"level"`
	Message  string   `json:"message"`
	Location Location `json:"location,omitempty"`
	// Score is the finding's numeric CVSS-style severity (0–10), sourced from the SARIF
	// "security-severity" property. HasScore reports whether a score was present; without
	// one, normalized Severity falls back to Level.
	Score    float64 `json:"score,omitempty"`
	HasScore bool    `json:"-"`
}

// Fingerprint is a stable identifier for deduplication: two results with the same
// fingerprint are considered the same finding.
func (r Result) Fingerprint() string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		r.Tool, r.RuleID, string(r.Level), r.Message,
		r.Location.URI, strconv.Itoa(r.Location.StartLine),
	}, "\x00")))
	return hex.EncodeToString(sum[:])
}

// Report is a set of findings, normalized to SARIF semantics. Tool names the primary
// scanner; when a report carries results from several tools (after Merge), each Result
// keeps its own Tool.
type Report struct {
	Tool    string   `json:"tool,omitempty"`
	Results []Result `json:"results"`
}

// Counts tallies results by severity.
type Counts struct {
	Error   int
	Warning int
	Note    int
	None    int
}

// Total returns the sum of all counts.
func (c Counts) Total() int { return c.Error + c.Warning + c.Note + c.None }

// Counts tallies the report's results by severity.
func (r Report) Counts() Counts {
	var c Counts
	for _, res := range r.Results {
		switch res.Level {
		case LevelError:
			c.Error++
		case LevelWarning:
			c.Warning++
		case LevelNote:
			c.Note++
		default:
			c.None++
		}
	}
	return c
}

// Highest returns the most severe level present, or LevelNone when there are no results.
func (r Report) Highest() Level {
	highest := LevelNone
	for _, res := range r.Results {
		if res.Level.Rank() > highest.Rank() {
			highest = res.Level
		}
	}
	return highest
}

// Dedup returns a copy with exact-duplicate results removed, preserving first-seen order.
func (r Report) Dedup() Report {
	return Merge(r)
}

// Merge combines reports into one, deduplicating results by fingerprint and preserving
// first-seen order. Each result's Tool is backfilled from its source report when unset.
func Merge(reports ...Report) Report {
	out := Report{}
	seen := make(map[string]bool)
	for _, rep := range reports {
		if out.Tool == "" {
			out.Tool = rep.Tool
		}
		for _, res := range rep.Results {
			if res.Tool == "" {
				res.Tool = rep.Tool
			}
			fp := res.Fingerprint()
			if seen[fp] {
				continue
			}
			seen[fp] = true
			out.Results = append(out.Results, res)
		}
	}
	return out
}
