// Package sarif provides Draugr's result currency: a pragmatic model of SARIF 2.1.0
// findings, plus merge and deduplication. Every scanner normalizes its output to a
// Report; the engine merges reports and the result can be serialized to standard SARIF
// JSON for GitHub / Azure DevOps / GitLab.
package sarif

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
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
	// Control names the check this finding came from — sca, sast, secrets — stamped when a run's
	// per-control reports are merged into one document.
	//
	// The merged file is the only thing a downstream consumer sees, and until a finding carries
	// its control that consumer cannot tell two controls apart: one rule id reported by two
	// checks is two separate things to do, and grouping by rule id alone silently makes it one.
	// The control is also what a reader is being asked to act on ("your dependency scan found
	// this"), which no other field states.
	Control string `json:"control,omitempty"`
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
	// PartialFingerprints are SARIF's own mechanism for identity across runs, keyed by name.
	//
	// Distinct from Fingerprint, and the difference is what each is for. Fingerprint deduplicates
	// *within* a run and hashes the line number to do it, which is exactly right there and useless
	// across runs: adding an import at the top of a file changes the line of every finding below
	// it. These hash what the code says rather than where it sits.
	//
	// Empty for a finding with no file and line — a vulnerable dependency is identified by its
	// package, which is already on the finding. Absent means "no content-based identity", and a
	// fabricated one would be worse than none.
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
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
	// that created it, are facts; anything further is inference and has to be labeled as such.
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
	// Reachability is set when a reachability analyzer covered this finding's dependency, and
	// says whether this project's code can actually reach the vulnerable code. Nil when no
	// analyzer ran; ReachabilityUnknown when one ran but could not tell.
	//
	// Only ever set on a finding about a dependency, so it is nil wherever Package is.
	Reachability *Reachability `json:"reachability,omitempty"`
	// Correlation is set when more than one scanner reported this same flaw: on the finding that
	// is counted it names who else found it, and on the others it names the one they are counted
	// under. Nil when only one scanner reported it.
	Correlation *Correlation `json:"correlation,omitempty"`
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

// ReachabilityState says whether this project's own code can reach a dependency's vulnerable
// code. Three values rather than two, because the third is the one that keeps the other two
// honest.
type ReachabilityState string

const (
	// ReachabilityReachable means analysis found a route from this project's code to the
	// vulnerable code, and the route is recorded in Paths.
	ReachabilityReachable ReachabilityState = "reachable"
	// ReachabilityUnreachable means analysis covered this dependency and found no such route.
	//
	// It is a statement about how the code is called today, not a claim that the flaw is
	// harmless: reflection, dynamic dispatch and code generation all defeat a call graph, and
	// the route appears the day somebody writes the call. That is why this ranks a finding
	// lower and never removes it.
	ReachabilityUnreachable ReachabilityState = "unreachable"
	// ReachabilityUnknown means no analysis covered this dependency.
	//
	// The whole reason the state is explicit. An analyzer that never looked at a dependency
	// produces exactly the same silence as one that looked and found nothing, and treating the
	// two alike turns "we did not check" into "you are fine" — which is the failure this
	// codebase refuses everywhere else. A tool that cannot say which of the two it means may
	// only report this.
	ReachabilityUnknown ReachabilityState = "unknown"
)

// Reachability records whether this project's code can reach a dependency's vulnerable code,
// and on what evidence.
//
// The third member of a family, and it inherits both of the family's rules. Suppression records
// that a person decided to count a finding for less; Escalation records evidence that it deserves
// more; this records evidence about whether the code can be reached at all. Like Escalation it
// feeds the priority matrix and never rewrites the severity the scanner reported, and like
// Escalation it is deliberately not part of Fingerprint — a finding is the same finding whether
// or not analysis moved it, and folding this in would churn every diff on the day a call is added
// or removed.
//
// Unlike Suppression it never excuses a finding. An inference is not a decision, and a finding
// that disappears because a call graph did not find a path has no author to ask about it.
type Reachability struct {
	// State is the verdict: reachable, unreachable, or unknown.
	State ReachabilityState `json:"state"`
	// Analyzer names the tool that decided, e.g. "govulncheck".
	Analyzer string `json:"analyzer"`
	// Method is how it decided, e.g. "call-graph". Buyers are told to reject reachability
	// claims that do not say how they were reached, and they are right to: a call graph and a
	// framework heuristic are both called reachability and are not the same evidence.
	Method string `json:"method,omitempty"`
	// Symbols are the vulnerable functions the advisory names, whether or not they are called.
	// Reported for both reachable and unreachable, because "which functions would have to be
	// called" is what makes an unreachable verdict checkable by hand.
	Symbols []string `json:"symbols,omitempty"`
	// Paths are the routes found from this project's code to the vulnerable code, each ordered
	// caller first. Empty unless State is reachable.
	Paths []CallPath `json:"paths,omitempty"`
	// RankedAs is the severity the priority band was computed from, set only when the state
	// moved it. The report still displays the scanner's own severity; this explains a P3 sitting
	// on a "high" row, the way Escalation.To explains a P1 on a "medium" one.
	RankedAs Severity `json:"rankedAs,omitempty"`
	// AsOf is the day the analysis ran, as YYYY-MM-DD. A reachability verdict describes one
	// revision of the code and stops being true when the code changes, so a claim without a date
	// is not one a reader can check.
	AsOf string `json:"asOf,omitempty"`
}

// CallPath is one route from this project's code to a vulnerable symbol, ordered caller first
// so it reads the way a stack trace is read.
type CallPath struct {
	// Frames are the calls making up the route, starting in this project's own code.
	Frames []CallFrame `json:"frames"`
}

// CallFrame is one call in a CallPath.
type CallFrame struct {
	// Function is the function called, qualified as its language qualifies it.
	Function string `json:"function"`
	// Package is the package the function belongs to, when the analyzer reports one.
	Package string `json:"package,omitempty"`
	// Module is the module the package belongs to, when the analyzer reports one.
	Module string `json:"module,omitempty"`
	// File and Line locate the call. Relative to the module root, as the analyzer reported it.
	File string `json:"file,omitempty"`
	Line int    `json:"line,omitempty"`
}

// Correlation records that more than one scanner reported the same flaw.
//
// A relationship rather than a merge, and for the reason the rest of this model is: nothing is
// deleted. Both scanners' findings stay in the report with their own rule ids, their own severity
// and their own account of what they saw — because the disagreement between two scanners is the
// reason to run two, and a merge that keeps one opinion throws away the thing you were paying
// for.
//
// What changes is the counting. One finding of the group is counted; the others are evidence.
// Reporting four vulnerabilities as eight is the failure this exists to fix, and it is the test
// buyers are told to run: point several scanners at one target and count the tickets.
//
// Deliberately not part of Fingerprint. Which finding of a group happens to be counted is a fact
// about this run's scanner selection, not about the finding, and folding it in would make a diff
// churn on the day somebody adds a second scanner.
type Correlation struct {
	// AlsoFoundBy is what the other scanners said about this same flaw, ordered by tool name.
	// Set on the finding that is counted, and empty on the ones that are not.
	AlsoFoundBy []Observation `json:"alsoFoundBy,omitempty"`
	// CountedUnder names the scanner whose finding this one is counted under, and is what makes
	// this finding evidence rather than a count. Empty on the finding that is counted.
	CountedUnder string `json:"countedUnder,omitempty"`
}

// Observation is another scanner's account of a flaw already counted.
//
// Complete rather than a name, because the interesting case is disagreement. Two scanners rating
// the same CVE medium and low have said something neither says alone — they draw on different
// advisory sources, and the gap is a statement about coverage. A reader who only learns that a
// second tool "also found it" cannot see that, and the console has nothing to show them.
type Observation struct {
	// Tool is the scanner that made this observation.
	Tool string `json:"tool"`
	// RuleID is what that scanner called it, which is not always what the counted finding is
	// called — and is the id an exclusion may already be written against.
	RuleID string `json:"ruleId,omitempty"`
	// Severity and Score are that scanner's own rating, kept whether or not it agrees. The
	// report decides what is worth showing; the record does not get to be selective.
	Severity Severity `json:"severity,omitempty"`
	Score    float64  `json:"score,omitempty"`
}

// Correlated reports whether another scanner's finding is the one being counted for this flaw.
//
// True only on the copies that are not counted. The finding that is counted has a Correlation
// too — naming who else found it — and is very much still a finding.
func (r Result) Correlated() bool {
	return r.Correlation != nil && r.Correlation.CountedUnder != ""
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
	// Origin says who decided. Empty or "saga" is a rule in the descriptor; "vex" is a statement
	// somebody else made and this project chose to accept.
	//
	// The distinction is the whole point of reading a supplier's document rather than retyping it.
	// A `not_affected` you copied into `config.exclude` becomes indistinguishable from a decision
	// you made and are answerable for; kept apart, the report can say the analysis was theirs, and
	// an auditor can ask them rather than you.
	Origin string `json:"origin,omitempty"`
	// Author is who asserted an imported claim — the VEX document's author. Empty for a
	// descriptor rule, where AcceptedBy already answers "who decided".
	Author string `json:"author,omitempty"`
	// Asserted is when an imported claim was made, as the document wrote it. A supplier's
	// statement is made on a date they chose, and a year-old `not_affected` about a package that
	// has moved on is worth seeing as old rather than reading as current.
	Asserted string `json:"asserted,omitempty"`
	// Source is the descriptor or fragment the exclusion was written in, or the document an
	// imported claim came from. Empty when the whole descriptor is one file, where naming it
	// would be noise.
	//
	// Splitting exclusions across files is only safe if the report can still say which file
	// authorized each one — otherwise composition trades a long descriptor for an unanswerable
	// one, which is the worse of the two.
	Source string `json:"source,omitempty"`
}

// Where a suppression's decision came from, for Suppression.Origin.
const (
	// OriginSaga is a rule in this project's own descriptor. The default reading of an empty
	// Origin, so a report written before imported claims existed still means what it said.
	OriginSaga = "saga"
	// OriginVEX is a statement imported from a document somebody else wrote.
	OriginVEX = "vex"
	// OriginTool is a suppression the author wrote into the source and the scanner honored — a
	// Semgrep `nosem`, a `# noqa`, a linter's inline pragma.
	//
	// The weakest of the three, and kept apart for that reason. A descriptor rule was reviewed by
	// whoever owns the descriptor and a supplier's claim is answerable by the supplier; this one
	// was written by whoever was editing the file, possibly to get a build green, and nothing
	// about it went past a second person. Counting it with the others would let the weakest form
	// of acceptance hide inside the strongest.
	OriginTool = "tool"
)

// Suppressed reports whether this finding was excluded — by a Saga rule or by an imported claim.
func (r Result) Suppressed() bool { return r.Suppression != nil }

// SilencedInSource reports whether a suppression came from a comment in the code rather than from
// a decision anybody recorded.
func (r Result) SilencedInSource() bool {
	return r.Suppression != nil && r.Suppression.Origin == OriginTool
}

// Imported reports whether the decision to suppress came from outside this project.
//
// Worth asking separately from Suppressed: the two are counted apart in the report, because "we
// accepted this" and "our supplier says it does not apply" are different answers to the auditor's
// question, and a total that merges them can only answer the weaker one.
func (r Result) Imported() bool {
	return r.Suppression != nil && r.Suppression.Origin == OriginVEX
}

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
	// This is what makes two tools' findings recognizable as being about the same thing, and it
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
		// The same for a second scanner's copy of a flaw already counted. Counting it again
		// reports one vulnerability as two, which is the arithmetic that makes a wall of
		// findings look worse than the system is.
		if res.Correlated() {
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

// RankAt returns the severity a finding's priority band should be computed from, given what
// reachability analysis concluded.
//
// Only an unreachable verdict moves anything. Reachable does not raise: severity already assumes
// the vulnerable code runs, so treating a confirmed call as an escalation would count the same
// assumption twice. Unknown moves nothing by definition — it is the absence of a finding, not one.
func (r *Reachability) RankAt(base Severity) Severity {
	if r == nil || r.State != ReachabilityUnreachable {
		return base
	}
	return base.Deescalate()
}

// vulnerabilityID matches a vulnerability identifier at the start of a rule id, allowing whatever
// a scanner appends to it.
//
// Anchored at the front and not at the back, deliberately. Grype reports `CVE-2019-1010083-flask`
// — the identifier plus the package it found it in — because one advisory can affect several
// packages in one scan, and collapsing those would merge two real findings into one. So the
// decoration stays on the rule id, which is what the scanner said, and everything that needs to
// know *which vulnerability this is* asks here instead of matching the string.
var vulnerabilityID = regexp.MustCompile(
	`^(CVE-\d{4}-\d{4,}` +
		`|GHSA-[2-9cfghjmpqrvwx]{4}-[2-9cfghjmpqrvwx]{4}-[2-9cfghjmpqrvwx]{4}` +
		`|OSV-\d{4}-\d+` +
		`|RUSTSEC-\d{4}-\d{4}` +
		`|GO-\d{4}-\d{4,})`)

// VulnerabilityID is the vulnerability this finding is about, or "" when it is not about one.
//
// A rule id belongs to whoever emitted it, and two scanners reporting the same advisory do not
// spell it the same way. Anything asking "which vulnerability is this" — matching a supplier's
// VEX statement, writing one, recognizing the same flaw found twice — has to ask that question
// rather than compare rule ids, or it silently answers for one scanner and not the other.
//
// Empty for a finding that is not a vulnerability at all. A leaked credential and a misconfigured
// security group are real findings with no advisory to be un-affected by.
func (r Result) VulnerabilityID() string {
	return vulnerabilityID.FindString(r.RuleID)
}
