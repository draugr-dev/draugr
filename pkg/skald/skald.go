// Package skald renders scan results and verdicts into evidence: a JSON summary and
// merged SARIF. A skald is the poet who records deeds — here, the record of a scan.
package skald

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/prioritization"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// jsonReport is the JSON evidence document.
type jsonReport struct {
	Release    releaseInfo     `json:"release"`
	Verdict    string          `json:"verdict"`
	Controls   []controlReport `json:"controls"`
	Priorities *priorityCounts `json:"priorities,omitempty"`
	Findings   []findingReport `json:"findings,omitempty"`
	Stats      statsInfo       `json:"stats"`
}

// priorityCounts tallies findings by priority band (present when prioritization ran).
type priorityCounts struct {
	P1 int `json:"p1"`
	P2 int `json:"p2"`
	P3 int `json:"p3"`
	P4 int `json:"p4"`
}

// findingReport is one ranked finding, emitted when a minimum priority filter is set.
type findingReport struct {
	Priority string  `json:"priority,omitempty"`
	Level    string  `json:"level"`
	Score    float64 `json:"score,omitempty"`
	Control  string  `json:"control"`
	Tool     string  `json:"tool,omitempty"`
	RuleID   string  `json:"ruleId,omitempty"`
	Message  string  `json:"message,omitempty"`
	Location string  `json:"location,omitempty"`
}

type releaseInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type controlReport struct {
	Name            string `json:"name"`
	Verdict         string `json:"verdict"`
	Highest         string `json:"highest"`
	HighestPriority string `json:"highestPriority,omitempty"`
	Threshold       string `json:"threshold"`
	Errors          int    `json:"errors"`
	Warnings        int    `json:"warnings"`
	Notes           int    `json:"notes"`
	Total           int    `json:"total"`
}

type statsInfo struct {
	Jobs      int `json:"jobs"`
	Scans     int `json:"scans"`
	CacheHits int `json:"cacheHits"`
}

// RenderJSON writes a JSON evidence summary combining the run result and the verdict.
// Controls are emitted in name order for stable output. When minPriority is non-empty (e.g.
// "P2"), a ranked `findings` list of findings at or above that band is included; priority
// counts are always included when the run was prioritized.
func RenderJSON(w io.Writer, release saga.Release, run engine.Result, verdict norn.Result, minPriority string) error {
	doc := jsonReport{
		Release: releaseInfo{Name: release.Name, Version: release.Version},
		Verdict: string(verdict.Verdict),
		Stats:   statsInfo{Jobs: run.Stats.Jobs, Scans: run.Stats.Scans, CacheHits: run.Stats.CacheHits},
	}
	for _, oc := range verdict.Controls {
		doc.Controls = append(doc.Controls, controlReport{
			Name:            oc.Control,
			Verdict:         string(oc.Verdict),
			Highest:         string(oc.Highest),
			HighestPriority: oc.HighestPriority,
			Threshold:       string(oc.Threshold),
			Errors:          oc.Counts.Error,
			Warnings:        oc.Counts.Warning,
			Notes:           oc.Counts.Note,
			Total:           oc.Counts.Total(),
		})
	}
	sort.Slice(doc.Controls, func(i, j int) bool { return doc.Controls[i].Name < doc.Controls[j].Name })

	doc.Priorities, doc.Findings = summarizePriorities(run, minPriority)

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

// summarizePriorities tallies findings by priority band and, when minPriority is set, builds
// a ranked list of findings at or above it. Returns nil counts when the run was not
// prioritized (no finding carries a priority).
func summarizePriorities(run engine.Result, minPriority string) (*priorityCounts, []findingReport) {
	var counts priorityCounts
	var findings []findingReport
	prioritized := false
	minRank := prioritization.Priority(minPriority).Rank()

	for _, name := range sortedControlNames(run) {
		for _, res := range run.Controls[name].Report.Results {
			if res.Priority == "" {
				continue
			}
			prioritized = true
			switch prioritization.Priority(res.Priority) {
			case prioritization.P1:
				counts.P1++
			case prioritization.P2:
				counts.P2++
			case prioritization.P3:
				counts.P3++
			case prioritization.P4:
				counts.P4++
			}
			if minRank > 0 && prioritization.Priority(res.Priority).Rank() >= minRank {
				findings = append(findings, toFinding(name, res))
			}
		}
	}
	if !prioritized {
		return nil, nil
	}
	sortFindings(findings)
	return &counts, findings
}

func toFinding(control string, res sarif.Result) findingReport {
	loc := res.Location.URI
	if loc != "" && res.Location.StartLine > 0 {
		loc = fmt.Sprintf("%s:%d", loc, res.Location.StartLine)
	}
	return findingReport{
		Priority: res.Priority,
		Level:    string(res.Level),
		Score:    res.Score,
		Control:  control,
		Tool:     res.Tool,
		RuleID:   res.RuleID,
		Message:  res.Message,
		Location: loc,
	}
}

// sortFindings orders most-urgent first: by priority, then numeric score, then SARIF level,
// then rule id for stability.
func sortFindings(fs []findingReport) {
	sort.Slice(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if ra, rb := prioritization.Priority(a.Priority).Rank(), prioritization.Priority(b.Priority).Rank(); ra != rb {
			return ra > rb
		}
		if a.Score != b.Score {
			return a.Score > b.Score
		}
		if la, lb := sarif.Level(a.Level).Rank(), sarif.Level(b.Level).Rank(); la != lb {
			return la > lb
		}
		return a.RuleID < b.RuleID
	})
}

func sortedControlNames(run engine.Result) []string {
	names := make([]string, 0, len(run.Controls))
	for name := range run.Controls {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// MergedSARIF combines all controls' reports into one SARIF report.
func MergedSARIF(run engine.Result) sarif.Report {
	names := sortedControlNames(run)
	reports := make([]sarif.Report, 0, len(names))
	for _, name := range names {
		reports = append(reports, run.Controls[name].Report)
	}
	return sarif.Merge(reports...)
}

// WriteSARIF writes the merged run results as SARIF 2.1.0 JSON.
func WriteSARIF(w io.Writer, run engine.Result) error {
	data, err := MergedSARIF(run).MarshalSARIF()
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}
