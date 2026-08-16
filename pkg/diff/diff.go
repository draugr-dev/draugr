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
	// Rules is what the scanners said about the rules these findings cite, carried over from the
	// reports being compared.
	//
	// A diff that keeps only results keeps only identifiers. `CVE-2018-1000656` in a table is a
	// string to copy into a search box, and the same id uploaded to code scanning arrives with no
	// description and whatever link can be guessed from its shape — while the scanner that found
	// it published both. Keeping the rules is what lets a reader click the finding instead of
	// looking it up.
	Rules map[string]sarif.Rule
}

// HelpURI is where a reader can look up a rule: what the scanner published, or a URL derived from
// a well-known identifier scheme. Empty when neither applies — a wrong link is worse than none.
func (r Result) HelpURI(ruleID string) string {
	return sarif.Report{Rules: r.Rules}.HelpURI(ruleID)
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
	// Head first, so a rule the change updated is described as it is now; base fills in whatever
	// only the old scan saw, which is every fixed finding's rule.
	r.Rules = map[string]sarif.Rule{}
	for _, src := range []map[string]sarif.Rule{base.Rules, head.Rules} {
		for id, rule := range src {
			r.Rules[id] = rule
		}
	}
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
	// Component and repository are included for the opposite reason line and level are not: they
	// do not drift, they are the subject. The same flaw at the same line in two components is two
	// findings carrying two classifications, so one can be P1 and the other P4; the same file in
	// two repositories is two projects to fix. Keyed without them, a diff keeps whichever it saw
	// first and reports the other as neither new nor fixed — it simply is not there.
	return strings.Join([]string{
		r.Tool, r.RuleID, r.Location.URI, r.Message, r.Component, r.Repository,
	}, "\x00")
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

// SeverityCounts tallies findings by Draugr's normalized severity band.
//
// Bands rather than SARIF levels, because a diff is read next to the scan report it came from
// and the two have to agree. error/warning/note is the wire vocabulary of the file; a reader
// deciding whether a pull request made things worse is thinking in critical/high/medium/low.
type SeverityCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

// countSeverities tallies a finding slice by severity band.
func countSeverities(rs []sarif.Result) SeverityCounts {
	var c SeverityCounts
	for _, r := range rs {
		switch r.Severity("") {
		case sarif.SeverityCritical:
			c.Critical++
		case sarif.SeverityHigh:
			c.High++
		case sarif.SeverityMedium:
			c.Medium++
		case sarif.SeverityLow:
			c.Low++
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

// NarrowNew drops new findings below a priority band, leaving fixed and unchanged alone.
//
// Only the new ones, because they are what the diff is reporting and what a reviewer is asked to
// act on; fixed and unchanged are context, and a count of them that moved with a threshold would
// mean something different on every run.
//
// A finding the scanner never prioritized is kept. An empty Priority means prioritization did not
// run for it, not that it ranked low — dropping it would hide a finding for the reason it was
// hardest to judge.
func (r Result) NarrowNew(band string) Result {
	if band == "" {
		return r
	}
	want := prioritization.Priority(band).Rank()
	if want == 0 {
		return r
	}
	kept := make([]sarif.Result, 0, len(r.New))
	for _, f := range r.New {
		if f.Priority == "" || prioritization.Priority(f.Priority).Rank() >= want {
			kept = append(kept, f)
		}
	}
	r.New = kept
	return r
}

// OnlyRepository keeps the new findings a given repository's checkout can actually anchor.
//
// Paths are repository-relative, so a finding from another repository uploaded against this one
// resolves to a same-named file here — an annotation on a line that does not have that problem.
// That is wrong rather than merely noisy, and there is no case where it is wanted, so this is not
// offered as a preference.
//
// A finding with no repository is kept. Not everything Draugr reports comes from a checkout: an
// image finding is located at an image reference and belongs to no repository, and dropping those
// would remove most of a container scan from the surface a reviewer reads.
func (r Result) OnlyRepository(ref string) Result {
	if ref == "" {
		return r
	}
	kept := make([]sarif.Result, 0, len(r.New))
	for _, f := range r.New {
		if f.Repository == "" || sarif.SameRepository(f.Repository, ref) {
			kept = append(kept, f)
		}
	}
	r.New = kept
	return r
}

// GateNew returns the new findings that meet the differential gate: level at or above failOn
// (when set) OR priority at or above failOnPriority (when set). An empty threshold disables
// that dimension. With both empty, nothing is returned.
func (r Result) GateNew(failOn sarif.Severity, failOnPriority string) []sarif.Result {
	var tripped []sarif.Result
	wantSeverity := failOn != ""
	wantPriority := failOnPriority != ""
	prioRank := prioritization.Priority(failOnPriority).Rank()
	for _, f := range r.New {
		if wantSeverity && f.Severity("").AtLeast(failOn) {
			tripped = append(tripped, f)
			continue
		}
		if wantPriority && prioritization.Priority(f.Priority).Rank() >= prioRank && prioRank > 0 {
			tripped = append(tripped, f)
		}
	}
	return tripped
}
