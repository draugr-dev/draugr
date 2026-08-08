// Package sarif provides Draugr's result currency: a pragmatic model of SARIF 2.1.0
// findings, plus merge and deduplication. Every scanner normalizes its output to a
// Report; the engine merges reports and the result can be serialized to standard SARIF
// JSON for GitHub / Azure DevOps / GitLab.
package sarif

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
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
	// Historical marks a finding that describes a commit rather than the current tree.
	//
	// A history scan reports the path a secret had in the commit that introduced it, and after a
	// rename that path no longer exists. Unmarked, the finding reads as something already cleaned
	// up — which is exactly backwards, because a credential in history is still fetchable by
	// anyone who can clone and still needs rotating, whatever the tree looks like now.
	Historical bool `json:"historical,omitempty"`
	// PriorityFloor explains a band the component's classification alone does not account for.
	//
	// Some findings are not bounded by where the component sits. A leaked credential is valid
	// wherever it is valid — a cloud account, a registry, an artifact store — and git history is
	// often readable by more people than the service is reachable by, so an `internal` component
	// can understate who can obtain the thing. Where a control says so, the band it produces is
	// not damped below a floor.
	//
	// Set only when the floor actually raised the band, so a reader asking "why is this P2 on a
	// supporting internal component" has the answer in the report rather than in the source.
	PriorityFloor string `json:"priorityFloor,omitempty"`
	// Component names the part of the application this finding belongs to, stamped by the engine
	// from the component whose scan produced it. Empty for a project-scoped control, which has
	// no one component to attribute to.
	//
	// A location alone is ambiguous the moment a descriptor has two components: three components
	// have three go.mod files, and two can carry the same path. It is also what makes the
	// priority checkable — the band is computed from the component's declared exposure and
	// criticality, so a report showing the band without naming the component states a conclusion
	// and withholds its premise.
	Component string `json:"component,omitempty"`
	// Suppression is set when a Saga exclusion matched this finding. A suppressed result is
	// reported but not counted: it does not reach Counts, the verdict, or the fix-first list.
	// Nil for an active finding.
	Suppression *Suppression `json:"suppression,omitempty"`
	// Escalation is set when exploitability enrichment raised this finding's severity, and says
	// which signal did it. Nil when nothing moved it.
	//
	// Suppression's twin: one records a decision to count a finding for less, this one records
	// evidence that it deserves more. Both answer the same question — a report that states a
	// conclusion and withholds its premise is a hint rather than evidence, and "critical because
	// CISA observed this being exploited, as of a date you can check" is the premise.
	Escalation *Escalation `json:"escalation,omitempty"`
}

// Escalation records that exploitability data raised a finding's severity, and on what grounds.
//
// Deliberately not part of Fingerprint: a finding is the same finding whether or not a feed
// moved it, and folding this in would make every diff churn on the day EPSS reprices a CVE.
type Escalation struct {
	// From is the severity before enrichment — the scanner's own rating, and the one the report
	// still displays, because it is what the scanner actually said.
	From Severity `json:"from"`
	// To is the severity the finding was *ranked* as. Enrichment feeds the priority matrix
	// rather than rewriting what the scanner reported, so this is the value the band was
	// computed from and the one that explains a P1 sitting on a "high" row.
	To Severity `json:"to"`
	// Signal names the dataset that fired: "kev" or "epss".
	Signal string `json:"signal"`
	// Detail is the specific fact, e.g. "on KEV" or "EPSS 0.87".
	Detail string `json:"detail"`
	// AsOf is the day the data was fetched, as YYYY-MM-DD. Without it the claim is "KEV said
	// so", which is not something a reader can check or reproduce.
	AsOf string `json:"asOf,omitempty"`
}

// Suppression records that a finding was excluded, and why.
type Suppression struct {
	// Kind is the SARIF suppression kind. Draugr writes "external": the decision came from the
	// Saga, not from an annotation in the source.
	Kind string `json:"kind"`
	// Justification is the reason the Saga gave. Required by Draugr even though SARIF allows
	// it to be absent.
	Justification string `json:"justification"`
	// AcceptedBy is who decided this was acceptable, when the exclusion said. Empty means the
	// suppression is unattributed — reported as such, because "who decided" is half the question
	// an auditor is asking and a blank is an answer worth seeing.
	AcceptedBy string `json:"acceptedBy,omitempty"`
	// Expires is when the acceptance lapses, as YYYY-MM-DD. Empty means it does not.
	Expires string `json:"expires,omitempty"`
	// VEXStatus is what the exclusion declared this suppression means as a claim about the
	// product: not_affected, affected, or fixed. Empty when the exclusion said nothing, which
	// is the common case and reports as affected — the reading that is never an overstatement.
	VEXStatus string `json:"vexStatus,omitempty"`
	// VEXJustification is why the product is not affected, from VEX's fixed vocabulary. Set
	// only alongside a not_affected status.
	VEXJustification string `json:"vexJustification,omitempty"`
	// Source is the descriptor or fragment the exclusion was written in. Empty when the whole
	// descriptor is one file, where naming it would be noise.
	//
	// Splitting exclusions across files is only safe if the report can still say which file
	// authorised each one — otherwise composition trades a long descriptor for an unanswerable
	// one, which is the worse of the two.
	Source string `json:"source,omitempty"`
}

// Suppressed reports whether this finding was excluded by a Saga rule.
func (r Result) Suppressed() bool { return r.Suppression != nil }

// Fingerprint is a stable identifier for deduplication: two results with the same
// fingerprint are considered the same finding.
func (r Result) Fingerprint() string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		r.Tool, r.RuleID, string(r.Level), r.Message,
		r.Location.URI, strconv.Itoa(r.Location.StartLine),
		// The component is part of the identity, not decoration. Two components sharing a
		// repository produce the same flaw at the same line, and it is not the same finding:
		// each carries its component's exposure and criticality, so one can be P1 and the other
		// P4. Collapsing them keeps whichever merged first and silently discards the other —
		// which can be the urgent one, and contradicts the whole claim that context decides
		// priority.
		r.Component,
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
	// Decided are the classifications this run reached a verdict on, whether or not a finding
	// resulted. A taxon here with no finding means the scanner looked and found nothing wrong.
	//
	// The distinction this exists for: a scanner that reports nothing about a control has either
	// examined it and been satisfied, or never examined it at all, and those mean opposite
	// things. Without this, a report that says "1 of 2 scanners found it" is guessing that the
	// other dissented — when far more often the other simply does not check that control.
	//
	// "Decided" rather than "examined" on purpose: a check a scanner looked at and could not
	// settle — a CIS control that requires human judgement — is not a dissent either.
	Decided []Taxon `json:"decided,omitempty"`
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
	// Taxa are the shared classifications this rule implements — a CIS benchmark control, a
	// CWE. Empty when the scanner claims none.
	//
	// This is what makes two tools' findings recognisable as being about the same thing, and it
	// is deliberately not the rule id. An id belongs to whoever emitted it: `draugr/cis/5.1.1`
	// and `kube-bench/cis/5.1.1` are two tools' accounts, and collapsing them into one id — as
	// they were — makes provenance unrecoverable. A taxon is the vocabulary both are speaking,
	// so the correspondence is stated rather than inferred from a string collision.
	//
	// SARIF models exactly this with `taxonomies` and `taxa`, so a consumer that has never heard
	// of Draugr can group by CIS control, and a third-party scanner can participate by emitting
	// the same references.
	Taxa []Taxon `json:"taxa,omitempty"`
}

// Taxon is a classification a rule implements, in some published taxonomy.
type Taxon struct {
	// Taxonomy names the scheme, e.g. "CIS-Kubernetes" or "CWE".
	Taxonomy string `json:"taxonomy"`
	// ID is the identifier within it, e.g. "5.1.1" or "79".
	ID string `json:"id"`
	// Name is a short human label, when the scanner supplies one.
	Name string `json:"name,omitempty"`
	// Version is the taxonomy revision the id belongs to, e.g. "cis-1.12". A check number means
	// a different thing between benchmark revisions, so an id without one is ambiguous.
	Version string `json:"version,omitempty"`
}

// Key renders a taxon as a stable correlation key: two observations carrying the same key are
// about the same underlying check, whichever tool reported them.
func (t Taxon) Key() string {
	if t.Version == "" {
		return t.Taxonomy + "/" + t.ID
	}
	return t.Taxonomy + "@" + t.Version + "/" + t.ID
}

// empty reports whether the rule carries no information at all, in which case there's nothing
// worth storing or emitting for it.
func (r Rule) empty() bool {
	return r.Name == "" && r.ShortDescription == "" && r.FullDescription == "" &&
		r.Help == "" && r.HelpURI == "" && len(r.Taxa) == 0
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
	if len(cur.Taxa) == 0 {
		cur.Taxa = rule.Taxa
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
		out.addDecided(rep.Decided)
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

// addDecided unions what each report settled, so a merged report knows which classifications
// were reached by any scanner and by which.
//
// Deduplicated on the taxon key rather than the whole value: two scanners naming the same control
// may label it differently, and the label is not what makes it the same control.
func (r *Report) addDecided(taxa []Taxon) {
	for _, t := range taxa {
		if t.Taxonomy == "" || t.ID == "" {
			continue
		}
		if slices.ContainsFunc(r.Decided, func(existing Taxon) bool {
			return existing.Key() == t.Key()
		}) {
			continue
		}
		r.Decided = append(r.Decided, t)
	}
}

// ParseLevel converts a user-supplied gate level, rejecting anything it does not recognize.
//
// Rejecting matters more than it looks. An unknown level ranks 0, and every finding is at least
// 0 — so a typo, or a plausible-sounding value like "high", silently turns a gate into "fail on
// anything at all" rather than failing to parse. A flag either does something or says why not.
func ParseLevel(s string) (Level, error) {
	switch l := Level(strings.ToLower(strings.TrimSpace(s))); l {
	case LevelError, LevelWarning, LevelNote:
		return l, nil
	default:
		// Severity bands are what the reports print, so they are the likely mistake. Say where
		// the two vocabularies differ instead of only listing the valid words.
		switch Severity(strings.ToLower(strings.TrimSpace(s))) {
		case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow:
			return "", fmt.Errorf("%q is a severity band, and the gate takes a SARIF level: "+
				"error, warning or note (critical and high map to error, medium to warning, "+
				"low to note)", s)
		}
		return "", fmt.Errorf("unknown level %q: want error, warning or note", s)
	}
}

// RepositoryRef is the repository a scan read, and the commit it read.
//
// Recorded by repository scanners as Provenance fields rather than as a typed member of Report,
// because Provenance is already the channel for "what this scanner says about its own run" and
// this package should not grow a field per domain fact. Parsed back out here so every consumer —
// console, markdown, HTML, JSON — reads it the same way instead of each learning the key names.
type RepositoryRef struct {
	// URL is the repository as the descriptor named it.
	URL string `json:"url"`
	// Revision is the commit that was scanned. Empty when git could not be asked.
	Revision string `json:"revision,omitempty"`
	// Uncommitted counts files in the working copy. Not part of what was scanned unless
	// WorkingTree is set, in which case they are precisely what was.
	Uncommitted int `json:"uncommitted,omitempty"`
	// WorkingTree reports that the scan read the checkout on disk rather than a commit, so the
	// result is not reproducible from the revision alone.
	WorkingTree bool `json:"workingTree,omitempty"`
}

// Short renders the revision the way a human refers to a commit, with git's own "+" for a tree
// that has moved past it.
func (r RepositoryRef) Short() string {
	s := r.Revision
	if len(s) > 8 {
		s = s[:8]
	}
	if r.WorkingTree && s != "" && r.Uncommitted > 0 {
		s += "+"
	}
	return s
}

// Repository extracts the repository this provenance entry describes, if it describes one.
func (p Provenance) Repository() (RepositoryRef, bool) {
	var r RepositoryRef
	for _, f := range p.Fields {
		switch f.Key {
		case "repository":
			r.URL = f.Value
		case "revision":
			r.Revision = f.Value
		case "uncommitted":
			r.Uncommitted, _ = strconv.Atoi(f.Value)
		case "workingTree":
			r.WorkingTree = f.Value == "true"
		}
	}
	// A scanner that recorded no repository is describing something else — a cluster, a benchmark
	// — and belongs in the per-control provenance rather than here.
	return r, r.URL != ""
}

// RepositoriesIn collects the distinct repository/revision pairs the reports recorded.
//
// Keyed on the pair rather than the scanner: five controls reading one commit is one fact. When
// two controls disagree, both are kept — each repository scanner checks out independently, so on
// a branch that moves mid-scan they can genuinely read different commits, and collapsing that
// would be an assumption presented as evidence.
func RepositoriesIn(reports []Report) []RepositoryRef {
	type key struct{ url, rev string }
	seen := map[key]bool{}
	var out []RepositoryRef
	for _, rep := range reports {
		for _, p := range rep.Provenance {
			r, ok := p.Repository()
			if !ok {
				continue
			}
			k := key{r.URL, r.Revision}
			if seen[k] {
				continue
			}
			seen[k] = true
			out = append(out, r)
		}
	}
	return out
}
