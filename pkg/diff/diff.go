// Package diff compares two Draugr scan results and classifies every finding as new, fixed, or
// unchanged — the security delta of a change (typically a PR's head vs the base branch). It
// powers `draugr diff` and its differential gate ("fail only on findings this change introduces").
//
// Inputs are SARIF reports (the results.sarif that `draugr scan -o` writes): SARIF is Draugr's
// complete, structured result currency, whereas the JSON summary can be trimmed by --min-priority.
package diff

import (
	"sort"
	"strings"

	"github.com/draugr-dev/draugr/pkg/prioritization"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// Result is the classified delta between a base and a head report.
type Result struct {
	New       []sarif.Result // present in head, absent in base
	Fixed     []sarif.Result // present in base, absent in head
	Unchanged []sarif.Result // present in both (head copy)
}

// Compare classifies every finding across the two reports by stable identity.
func Compare(base, head sarif.Report) Result {
	baseIdx := index(base.Results)
	headIdx := index(head.Results)

	var r Result
	for k, res := range headIdx {
		if _, ok := baseIdx[k]; ok {
			r.Unchanged = append(r.Unchanged, res)
		} else {
			r.New = append(r.New, res)
		}
	}
	for k, res := range baseIdx {
		if _, ok := headIdx[k]; !ok {
			r.Fixed = append(r.Fixed, res)
		}
	}

	sortResults(r.New)
	sortResults(r.Fixed)
	sortResults(r.Unchanged)
	return r
}

// index maps each result to its identity. Later results with the same identity overwrite
// earlier ones (they are indistinguishable for diffing).
func index(results []sarif.Result) map[string]sarif.Result {
	m := make(map[string]sarif.Result, len(results))
	for _, res := range results {
		m[identity(res)] = res
	}
	return m
}

// identity is a stable, line-insensitive key for cross-scan comparison. It deliberately
// excludes the start line (line numbers drift as code moves, which would otherwise report an
// unchanged finding as fixed+new) and the severity level (a re-scored finding is still the same
// underlying issue). For CVE findings (SCA/images) the ruleID is the CVE and the URI is the
// package/image, so this is stable; for SAST it keys on rule + file + message.
func identity(r sarif.Result) string {
	return strings.Join([]string{r.Tool, r.RuleID, r.Location.URI, r.Message}, "\x00")
}

// sortResults orders most-urgent first: by priority, then numeric score, then SARIF level, then
// ruleID for a stable tie-break.
func sortResults(rs []sarif.Result) {
	sort.SliceStable(rs, func(i, j int) bool {
		a, b := rs[i], rs[j]
		if ra, rb := prioritization.Priority(a.Priority).Rank(), prioritization.Priority(b.Priority).Rank(); ra != rb {
			return ra > rb
		}
		if a.Score != b.Score {
			return a.Score > b.Score
		}
		if a.Level.Rank() != b.Level.Rank() {
			return a.Level.Rank() > b.Level.Rank()
		}
		return a.RuleID < b.RuleID
	})
}

// LevelCounts tallies findings by SARIF level.
type LevelCounts struct {
	Error   int `json:"error"`
	Warning int `json:"warning"`
	Note    int `json:"note"`
}

// countLevels tallies a finding slice by level.
func countLevels(rs []sarif.Result) LevelCounts {
	var c LevelCounts
	for _, r := range rs {
		switch r.Level {
		case sarif.LevelError:
			c.Error++
		case sarif.LevelWarning:
			c.Warning++
		case sarif.LevelNote:
			c.Note++
		}
	}
	return c
}

// PriorityCounts tallies findings by action band. Unprioritized findings are not counted here.
type PriorityCounts struct {
	P1 int `json:"p1"`
	P2 int `json:"p2"`
	P3 int `json:"p3"`
	P4 int `json:"p4"`
}

// countPriorities tallies a finding slice by priority band.
func countPriorities(rs []sarif.Result) PriorityCounts {
	var c PriorityCounts
	for _, r := range rs {
		switch prioritization.Priority(r.Priority) {
		case prioritization.P1:
			c.P1++
		case prioritization.P2:
			c.P2++
		case prioritization.P3:
			c.P3++
		case prioritization.P4:
			c.P4++
		}
	}
	return c
}

// GateNew returns the new findings that meet the differential gate: level at or above failOn
// (when set) OR priority at or above failOnPriority (when set). An empty threshold disables
// that dimension. With both empty, nothing is returned.
func (r Result) GateNew(failOn sarif.Level, failOnPriority string) []sarif.Result {
	var tripped []sarif.Result
	wantLevel := failOn != ""
	wantPriority := failOnPriority != ""
	prioRank := prioritization.Priority(failOnPriority).Rank()
	for _, f := range r.New {
		if wantLevel && f.Level.AtLeast(failOn) {
			tripped = append(tripped, f)
			continue
		}
		if wantPriority && prioritization.Priority(f.Priority).Rank() >= prioRank && prioRank > 0 {
			tripped = append(tripped, f)
		}
	}
	return tripped
}
