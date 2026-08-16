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
	// Repository is the repository this finding was found in, for a component that has more than
	// one — or a fragment that contributed one from somewhere else.
	//
	// Paths are rewritten repository-relative so a finding can be anchored to a file, which means
	// two repositories that share a path share everything else about a finding. Without this they
	// are one finding, and the second repository's copy is discarded on the way in.
	Repository string `json:"repository,omitempty"`
	// Package identifies the dependency a finding is about, when it is about one.
	//
	// Nil for a finding that is not: a SAST rule is about a line of code, an IaC check about a
	// resource. Set by the scanners that know, which is those reading a package manifest or an
	// image's installed set.
	Package *Package `json:"package,omitempty"`
	// Image is the container image a finding is about, for the scanners that scan one.
	//
	// It travels on the finding rather than being recovered from the component afterwards,
	// because a component may hold several images: recovering it later can only produce one
	// answer for all of them, which would be right whenever there is one image and silently
	// wrong the moment there are two.
	Image string `json:"image,omitempty"`
	// OperatingSystem is the OS whose package set contains the finding, e.g. "debian 12".
	//
	// Set only for findings in an image's OS layer, which is what distinguishes a vulnerable
	// system package from a vulnerable application dependency sitting on top of it. Empty for a
	// finding in a language ecosystem, where there is no OS answer to give.
	OperatingSystem string `json:"operatingSystem,omitempty"`
	// OSEndOfLife marks a finding whose operating system release no longer receives security
	// updates from its vendor — Trivy's EOSL, End Of Service Life.
	//
	// It changes what the finding means. On a supported release, "no fix available" is a state
	// that will end when the vendor publishes one; on a release past end of life, no fix is ever
	// coming, and upgrading the release is the only action that resolves it. That is usually the
	// highest-leverage move available, because it resolves every finding in the OS layer at once.
	OSEndOfLife bool `json:"osEndOfLife,omitempty"`
	// ProviderOperated marks a finding about a surface somebody else runs — the control plane of
	// a managed Kubernetes cluster being the case it exists for.
	//
	// Set from what the descriptor declares, never guessed: whether a cluster is managed is a
	// fact about a contract, not something visible in what a scanner reads. It is the same
	// argument that puts exposure and criticality in the descriptor.
	ProviderOperated bool `json:"providerOperated,omitempty"`
	// ImageBuiltUpstream marks a finding inside an image somebody else publishes.
	//
	// It changes the action rather than the severity. A vulnerable library in an image this team
	// builds is theirs to upgrade; the same library in an image they only run is fixed by taking
	// a newer image, and telling them to upgrade the library is advice they cannot act on.
	ImageBuiltUpstream bool `json:"imageBuiltUpstream,omitempty"`
	// Layer is the image layer the finding's package arrived in. Nil for anything that is not an
	// image finding, and for an image whose scanner did not report one.
	//
	// It is the only reliable answer to "is this mine or inherited". An image records nothing
	// about what it was built FROM — the name is not in there — so a base image cannot be named,
	// and where a multi-layer base ends is not knowable either. The layer, and the build step
	// that created it, are facts; anything further is inference and has to be labelled as such.
	Layer *Layer `json:"layer,omitempty"`
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

// Remediation says who can resolve a finding and by what kind of action. It is the answer to
// "can I do something about this", which is the question a reader has after the severity.
type Remediation string

// The kinds of remediation, most actionable first.
const (
	// RemediationUpgrade: a version that fixes it exists, in something the reader controls.
	RemediationUpgrade Remediation = "upgrade"
	// RemediationUpstream: nothing fixes it where it is, but the thing underneath can move —
	// an operating system release past end of service life, whose successor is the fix. One
	// action, and it resolves everything in that layer at once.
	RemediationUpstream Remediation = "upstream"
	// RemediationExternal: the surface is operated by somebody else. Still found, still
	// reported, still counted — never presented as something to go and fix, because telling a
	// reader to change a file on a control plane they cannot reach is worse than saying nothing.
	RemediationExternal Remediation = "external"
	// RemediationNone: no fix is published anywhere, and the thing it is in is the reader's.
	// Mitigation or acceptance, rather than an upgrade.
	RemediationNone Remediation = "none"
)

// Remediation classifies what can be done about the finding.
//
// Computed rather than stored, from facts each recorded by whoever knows them: the scanner
// reports a fixed version, the scanner reports end of service life, the descriptor declares who
// operates the surface. Storing the conclusion as well would let it disagree with its premises.
func (r Result) Remediation() Remediation {
	switch {
	case r.ProviderOperated:
		return RemediationExternal
	case r.Package != nil && r.Package.FixedVersion != "":
		return RemediationUpgrade
	case r.OSEndOfLife:
		return RemediationUpstream
	default:
		return RemediationNone
	}
}

// Layer identifies the image layer a finding's package came from, and the build step that made it.
//
// Index is the layer's position in the image, counting from the bottom, and Of is how many layers
// there are — "3 of 9" is interpretable where a bare digest is not, and the low indices are the
// inherited ones.
type Layer struct {
	// DiffID is the layer's content digest, as the image records it.
	DiffID string `json:"diffId,omitempty"`
	// Index is the layer's position from the bottom of the image, starting at 0.
	Index int `json:"index"`
	// Of is the number of layers in the image.
	Of int `json:"of,omitempty"`
	// CreatedBy is the build instruction that produced the layer, verbatim from the image's own
	// history — "RUN /bin/sh -c apt-get install …". It names the line to change, which is more
	// use than a layer digest and more honest than a guessed base image.
	CreatedBy string `json:"createdBy,omitempty"`
}

// Package is the dependency a finding is about.
//
// Scanners have always known this and only ever said it in prose — Trivy's message reads
// "Package: flask\nFixed Version: 0.12.3", which is a fact formatted for a human and unavailable
// to anything else. Three things wanted it and could not have it: GitLab's dependency and
// container reports, which require a structured name and version; correlating a run's findings
// with the SBOM it produced alongside them; and a VEX statement that can say which package within
// a product carries a vulnerability rather than only that the product does.
//
// Deliberately not part of Fingerprint. The same flaw in the same package at the same location is
// the same finding whether or not the scanner told us which package — so adding this must not
// split a finding in two the day a scanner starts reporting it.
type Package struct {
	// Name is the package as its ecosystem names it, e.g. "flask".
	Name string `json:"name"`
	// Version is what is installed.
	Version string `json:"version,omitempty"`
	// FixedVersion is the first release that resolves the finding. Empty when there is none —
	// which is a different and more alarming answer than "unknown", and the reason this is
	// reported rather than inferred from the absence of a fix.
	FixedVersion string `json:"fixedVersion,omitempty"`
	// PURL is the package URL, e.g. "pkg:pypi/flask@0.12.2". The one identifier that is portable
	// across ecosystems and the one every consumer of this asked for first.
	PURL string `json:"purl,omitempty"`
	// Ecosystem is the package manager the name belongs to, as the ecosystem calls itself:
	// "pip", "npm", "gem". A name alone is ambiguous — there is a `request` on npm and a
	// `requests` on PyPI, and neither is the other.
	Ecosystem string `json:"ecosystem,omitempty"`
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
		// And the repository, for the same reason one level down: a component may hold several,
		// and a fragment may contribute one from another project entirely. Two of them with the
		// same file at the same line are two findings — one leaked credential per repository, not
		// one between them.
		r.Repository,
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

// HighestSeverity returns the most severe band present, or an empty severity when there are no
// results to judge.
//
// This is what the gate compares, and it is deliberately the same number the report prints. The
// SARIF level and the severity band are two different ladders: a finding carrying a CVSS score
// takes its band from the score, so a scanner that reports a 7.8 as `warning` still shows as
// `high`. Judging the level instead lets a finding the report calls high pass a gate the reader
// believes is set to catch it — the verdict and the page disagreeing about the same finding.
func (r Report) HighestSeverity() Severity {
	highest := Severity("")
	for _, res := range r.Results {
		// Suppressed findings are reported but not judged, exactly as in Highest.
		if res.Suppressed() {
			continue
		}
		if sev := res.Severity(""); sev.Rank() > highest.Rank() {
			highest = sev
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

// SameRepository reports whether two repository references name the same repository.
//
// Tolerant on purpose: a descriptor may say `https://host/org/repo.git`, `git@host:org/repo.git`
// or `.`, and a CI environment says `org/repo`. Comparing them literally would answer "different"
// for the same repository and quietly drop its findings, which is worse than the problem this is
// used to solve.
//
// Each reference is reduced to its path, case-insensitively, without scheme, credentials, port or
// `.git`. Two match when they are equal, or when the shorter is a trailing run of whole segments
// of the longer — so a CI variable saying `org/repo` still matches a descriptor's clone URL.
//
// The whole path, not its last two segments. A forge may nest groups arbitrarily, and keeping only
// the tail makes `payments/backend/api` and `platform/backend/api` the same repository. Nothing
// errors when that happens: the two sets of findings merge, and whichever is processed last
// decides what the report says about a file both of them contain.
//
// Two segments is the floor for a suffix match. A bare `api` does not say which `api`, and
// accepting it would re-open the same collapse from the other end.
func SameRepository(a, b string) bool {
	na, nb := normalizeRepository(a), normalizeRepository(b)
	if na == "" || nb == "" {
		return false
	}
	return na == nb || pathSuffix(na, nb) || pathSuffix(nb, na)
}

// pathSuffix reports whether short is a trailing run of whole segments of long.
func pathSuffix(long, short string) bool {
	if !strings.Contains(short, "/") {
		return false
	}
	return strings.HasSuffix(long, "/"+short)
}

// normalizeRepository reduces a repository reference to its lowercased path.
func normalizeRepository(ref string) string {
	s := strings.TrimSuffix(strings.TrimSpace(ref), ".git")
	// Whether a host is present has to be known rather than guessed: a group may legally be named
	// with a dot in it, so "looks like a hostname" would strip a real path segment from a bare
	// reference and make two of them collide.
	hadHost := false
	if i := strings.Index(s, "://"); i >= 0 {
		s, hadHost = s[i+3:], true
	}
	// Credentials in a URL, and the transport user of an scp-style remote: git@host:org/repo.
	if i := strings.LastIndex(s, "@"); i >= 0 {
		s, hadHost = s[i+1:], true
	}
	s = strings.ReplaceAll(stripPort(s), ":", "/")
	parts := []string{}
	for _, p := range strings.Split(s, "/") {
		if p != "" {
			parts = append(parts, p)
		}
	}
	if hadHost && len(parts) > 1 {
		parts = parts[1:]
	}
	return strings.ToLower(strings.Join(parts, "/"))
}

// stripPort removes a :port, leaving an scp-style colon alone.
//
// Both spellings put a colon after the host — `host:8443/org/repo` separates a port and
// `host:org/repo` separates the path — and only the port is all digits. Without the distinction a
// port becomes a path segment, and the repository is named `8443/org/repo`.
func stripPort(s string) string {
	i := strings.Index(s, ":")
	if i < 0 {
		return s
	}
	rest := s[i+1:]
	end := strings.Index(rest, "/")
	if end < 0 {
		end = len(rest)
	}
	if port := rest[:end]; port == "" || strings.TrimLeft(port, "0123456789") != "" {
		return s
	}
	return s[:i] + rest[end:]
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
