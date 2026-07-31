// Package sarif provides Draugr's result currency: a pragmatic model of SARIF 2.1.0
// findings, plus merge and deduplication. Every scanner normalizes its output to a
// Report; the engine merges reports and the result can be serialized to standard SARIF
// JSON for GitHub / Azure DevOps / GitLab.
package sarif

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
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
	// Priority is the computed action band (P1–P4) for this finding, stamped by the engine
	// from the component's risk classification. Empty when prioritization is not configured.
	Priority string `json:"priority,omitempty"`
	// Suppression is set when a Saga exclusion matched this finding. A suppressed result is
	// reported but not counted: it does not reach Counts, the verdict, or the fix-first list.
	// Nil for an active finding.
	Suppression *Suppression `json:"suppression,omitempty"`
}

// Suppression records that a finding was excluded, and why.
type Suppression struct {
	// Kind is the SARIF suppression kind. Draugr writes "external": the decision came from the
	// Saga, not from an annotation in the source.
	Kind string `json:"kind"`
	// Justification is the reason the Saga gave. Required by Draugr even though SARIF allows
	// it to be absent.
	Justification string `json:"justification"`
}

// Suppressed reports whether this finding was excluded by a Saga rule.
func (r Result) Suppressed() bool { return r.Suppression != nil }

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
	// Rules is the metadata the scanner published about the rules it applied, keyed by rule id.
	// A result names its rule; the rule is what explains it. Carrying this through is what lets
	// a reader — in a terminal, an editor, or a pull request — find out what "DS-0002" means.
	// Not every scanner publishes it, so entries may be missing.
	Rules map[string]Rule `json:"rules,omitempty"`
	// Provenance is what the scanners said about the run itself, as opposed to what they found:
	// which standard was applied, how much of it could be decided, what the scan was scoped to.
	//
	// A finding answers "what is wrong". Evidence also has to answer "what was measured, and
	// against what" — and that was not recorded anywhere, so a compliance report could not say
	// which benchmark produced it. One entry per tool run; see Provenance.
	Provenance []Provenance `json:"provenance,omitempty"`
}

// Provenance is one scanner's account of a run it performed.
//
// A slice on Report rather than a map of fields, because a control can be served by more than
// one scanner and each has its own answer — two scanners auditing a cluster apply two different
// benchmarks. Flattening them into one map keeps whichever was written last, silently, which is
// the failure this type exists to prevent.
type Provenance struct {
	// Tool is the scanner that produced this account.
	Tool string `json:"tool"`
	// Version is the scanner's version as the engine resolved it — the same value that goes into
	// its cache key, so the evidence and the cache cannot disagree about what ran. Empty when the
	// scanner does not report one.
	Version string `json:"version,omitempty"`
	// Fields are the scanner's own statements about the run, in the order it considers useful.
	//
	// Untyped, because the interesting ones are domain knowledge — "benchmark", "coverage",
	// "scope" — and this package is the finding currency for every scanner Draugr will ever
	// have. It should not learn what a CIS benchmark is to carry the fact that one was applied.
	Fields []Field `json:"fields,omitempty"`
}

// Field is one statement in a Provenance entry.
//
// A slice of pairs rather than a map: rendering needs a stable order, and alphabetical is the
// wrong one — it puts "coverage" before "benchmark". The scanner knows which matters most to a
// reader, so it decides.
type Field struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// Describe returns the fields as "key value" pairs, for a reporter with one line to spend.
func (p Provenance) Describe() string {
	parts := make([]string, 0, len(p.Fields))
	for _, f := range p.Fields {
		parts = append(parts, f.Key+" "+f.Value)
	}
	return strings.Join(parts, " · ")
}

// Rule is what a scanner says about one of its rules, beyond the bare id. Every field is
// optional: scanners vary widely in how much they publish, and an absent field is normal.
type Rule struct {
	// Name is a human-readable identifier (SARIF reportingDescriptor.name), where the id
	// itself is opaque.
	Name string `json:"name,omitempty"`
	// ShortDescription is a single sentence; FullDescription is a paragraph.
	ShortDescription string `json:"shortDescription,omitempty"`
	FullDescription  string `json:"fullDescription,omitempty"`
	// Help is remediation guidance, often Markdown.
	Help string `json:"help,omitempty"`
	// HelpURI points at the rule's documentation or advisory.
	HelpURI string `json:"helpUri,omitempty"`
}

// empty reports whether the rule carries no information at all, in which case there's nothing
// worth storing or emitting for it.
func (r Rule) empty() bool {
	return r.Name == "" && r.ShortDescription == "" && r.FullDescription == "" &&
		r.Help == "" && r.HelpURI == ""
}

// HelpURI returns where a reader can look up ruleID: what the scanner published, or a URL
// derived from a well-known identifier scheme when it published nothing. Empty when we can't
// say — a wrong link is worse than none.
func (r Report) HelpURI(ruleID string) string {
	if u := r.Rules[ruleID].HelpURI; u != "" {
		return u
	}
	return DerivedHelpURI(ruleID)
}

// DerivedHelpURI maps identifiers with a stable, publicly resolvable home to their advisory.
// It's the fallback for scanners that publish no rule metadata; anything unrecognized gets "".
func DerivedHelpURI(ruleID string) string {
	switch {
	case strings.HasPrefix(ruleID, "CVE-"):
		return "https://nvd.nist.gov/vuln/detail/" + ruleID
	case strings.HasPrefix(ruleID, "GHSA-"):
		return "https://github.com/advisories/" + ruleID
	default:
		return ""
	}
}

// addRule records metadata for ruleID, keeping what's already known: the first scanner to
// describe a rule wins, and a later report missing a field never blanks it.
func (r *Report) addRule(ruleID string, rule Rule) {
	if ruleID == "" || rule.empty() {
		return
	}
	if r.Rules == nil {
		r.Rules = map[string]Rule{}
	}
	cur := r.Rules[ruleID]
	if cur.Name == "" {
		cur.Name = rule.Name
	}
	if cur.ShortDescription == "" {
		cur.ShortDescription = rule.ShortDescription
	}
	if cur.FullDescription == "" {
		cur.FullDescription = rule.FullDescription
	}
	if cur.Help == "" {
		cur.Help = rule.Help
	}
	if cur.HelpURI == "" {
		cur.HelpURI = rule.HelpURI
	}
	r.Rules[ruleID] = cur
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
		// A suppressed finding is evidence, not a count. Including it here would put it back
		// into the verdict through the summary, which is the whole thing an exclusion prevents.
		if res.Suppressed() {
			continue
		}
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
		// Suppressed findings are reported but not judged. Missing this is how a Saga
		// exclusion appears to work — the count drops to zero — while the gate still fails on
		// the finding it was supposed to set aside.
		if res.Suppressed() {
			continue
		}
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
		for id, rule := range rep.Rules {
			out.addRule(id, rule)
		}
		out.addProvenance(rep.Provenance)
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

// addProvenance appends entries that are not already present.
//
// Appends rather than replaces, because two scanners serving one control each have their own
// account and both belong in the evidence. Deduplicated so that merging a report with itself —
// which aggregation does — does not double every entry.
func (r *Report) addProvenance(entries []Provenance) {
	for _, p := range entries {
		if len(p.Fields) == 0 && p.Version == "" {
			continue // nothing said
		}
		if slices.ContainsFunc(r.Provenance, func(existing Provenance) bool {
			return existing.Tool == p.Tool && existing.Version == p.Version &&
				slices.Equal(existing.Fields, p.Fields)
		}) {
			continue
		}
		r.Provenance = append(r.Provenance, p)
	}
}
