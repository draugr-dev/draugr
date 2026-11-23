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
	// EndLine is the last line of the region the scanner reported, where it reported one that spans
	// more than StartLine: Trivy gives a Kubernetes container's check the lines of the whole container.
	// Zero where the scanner gave no end. Not part of Fingerprint, which has always keyed on the start.
	//
	// Read so that a finding another scanner reports at one line inside that region can be recognized
	// as the same setting on the same resource (see SameCheckAs). Draugr's own SARIF does not write it.
	EndLine int `json:"endLine,omitempty"`
}

// Result is a single finding.
type Result struct {
	// Tool is the scanner that produced the finding, as the tool names itself: the SARIF driver name,
	// such as `Trivy` or `Semgrep OSS`, or the name the scanner's parser writes. It is part of
	// Fingerprint, so it never changes for a finding that already exists.
	Tool string `json:"tool,omitempty"`
	// Scanner is the name of the Draugr scanner whose job reported the finding, such as
	// `trivy-config` or `trivy-fs`, as `draugr controls` lists it. Stamped by the engine, and left
	// out of Fingerprint. Two scanners can run one tool, as `trivy-fs` and `trivy-config` both run
	// Trivy, and only this tells them apart.
	Scanner string `json:"scanner,omitempty"`
	RuleID  string `json:"ruleId"`
	Level   Level  `json:"level"`
	Message string `json:"message"`
	// Detail is what the scanner wrote about this one occurrence, where Message is the rule's title
	// because the scanner's message was a list of fields. It stays out of Fingerprint: Message is what a
	// finding has always been identified by, and a sentence naming a pod would make every finding read
	// as new the first time it appeared.
	Detail   string   `json:"detail,omitempty"`
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
	// rename that path no longer exists. Unmarked, the finding reads as something already cleaned up.
	// Which is exactly backwards, because a credential in history is still fetchable by anyone who
	// can clone and still needs rotating, whatever the tree looks like now.
	Historical bool `json:"historical,omitempty"`
	// NonShipping is the kind of directory the finding's file sits under where that directory holds
	// documentation, examples or tests rather than shipped code: "docs", "example" or "test", and
	// "test" for a Go test file wherever it sits. Empty for a finding in shipped code, and for every
	// control that does not mark one.
	//
	// Stamped by the engine on the controls that report a location in a repository's own files, so
	// a reader can tell a flaw in what ships from the same flaw in a test fixture. Whether a marked
	// finding counts is the control's nonShippingPaths setting, where it has one; the mark is there
	// either way, and secrets, which has none, counts every one.
	NonShipping string `json:"nonShipping,omitempty"`
	// Aside is what makes a finding in shipped code, or in a repository's own dependency files, one
	// to fix after the rest while it still counts at its priority: AsideGenerated, AsideTooling or
	// AsidePinned. Empty for every other finding.
	//
	// Apart from NonShipping because what it marks may ship, as generated code does, so no
	// nonShippingPaths setting reaches it. A report lists these findings after the rest and names
	// the reason beside each.
	Aside string `json:"aside,omitempty"`
	// Uses is the `uses:` reference a GitHub Actions mutable-tag finding is on, as the workflow wrote
	// it, such as `codecov/codecov-action@v5`. Empty for every other finding, and where the line could
	// not be read.
	//
	// Held for the run and never written: a row standing for several such findings shows one whose
	// action somebody outside GitHub publishes, and nothing else reads it.
	Uses string `json:"-"`
	// ImportedRepository is, on a finding read from another tool's SARIF file, the repository of its
	// component that the file is about, in the form Repository takes on a native finding: the one
	// repository the component declares, or the one of several that the file's
	// versionControlProvenance names. Empty where neither says, and on every native finding.
	//
	// Held for the run and never written. Repository stays empty on an imported finding, because the
	// file names none, and its fingerprint and every report read it that way; correlation reads this
	// to join the finding to the native copy in the same repository.
	ImportedRepository string `json:"-"`
	// ImportFormat is, on a finding read from a tool's own JSON rather than its SARIF, the format the
	// import named, such as trivy-json. Empty on a finding from a SARIF file and on every native one.
	//
	// Held for the run and never written, as ImportedRepository is: Reporter names it beside the tool,
	// so a row that counts a native copy says which file the other copy came from.
	ImportFormat string `json:"-"`
	// ImportedTool is, on a finding read from GitHub's code-scanning alerts that Draugr itself
	// uploaded, the tool the alert's rule names in the one `scanner:` tag Draugr's SARIF writes, such
	// as gosec. Tool stays Draugr, the tool GitHub names. Empty on every other finding.
	//
	// Held for the run and never written. The engine reads it to find the native finding of that tool
	// at the same line, whose suppression in the code at this commit then applies to the alert.
	ImportedTool string `json:"-"`
	// Platforms are the platforms, as GOOS/GOARCH, whose build alone holds the code a finding lies
	// in, where a Go analyzer found it in a run for a platform beside the machine's own: a gosec
	// finding in a file behind `//go:build windows`, read on Linux by a run for windows/amd64. Empty
	// for a finding in code the machine's own build holds, and for every analyzer that reads source
	// without building it.
	Platforms []string `json:"platforms,omitempty"`
	// DetectSecretsBaseline marks a secrets finding on a `hashed_secret` field of a detect-secrets
	// baseline, a `.secrets.baseline` file, where the value is the 40-character SHA-1 detect-secrets
	// recorded in place of what it found. The value is a digest, not a credential, and whether such a
	// finding counts is the secrets control's detectSecretsBaselines setting; the mark is there
	// either way.
	DetectSecretsBaseline bool `json:"detectSecretsBaseline,omitempty"`
	// Undecided marks a benchmark check the scanner could not settle and refers to a person, such as
	// one the benchmark scores as a manual check. It is a check left to review rather than something
	// the run found: nothing was seen to fail.
	//
	// Where two scanners report one check, a copy that reached a verdict is counted in preference to
	// one that did not, so a check one scanner decided is not ranked by another's referral of it.
	Undecided bool `json:"undecided,omitempty"`
	// PriorityFloor explains a band the component's classification alone does not account for.
	//
	// Some findings are not bounded by where the component sits. A leaked credential is valid
	// wherever it is valid, a cloud account, a registry, an artifact store. And git history is often
	// readable by more people than the service is reachable by, so an `internal` component can
	// understate who can obtain the thing. Where a control says so, the band it produces is not
	// damped below a floor.
	//
	// Set only when the floor actually raised the band, so a reader asking "why is this P2 on a
	// supporting internal component" has the answer in the report rather than in the source.
	PriorityFloor string `json:"priorityFloor,omitempty"`
	// PriorityCap is why a band is lower than the finding's severity and context would make it: a
	// GitHub Actions mutable-tag finding on a reference `.github/workflows/actions.lock` pins to a
	// commit, held at P3. Set only when the cap lowered the band, so a reader asking why a P3 sits
	// under a critical component has the answer in the report.
	PriorityCap string `json:"priorityCap,omitempty"`
	// SeverityFloor is the minimum severity the finding's control holds its findings at, recorded
	// only where it raised the rating the band was computed from. A `secrets` finding its scanner
	// rated medium carries `high` here; one the scanner already rated high or critical carries
	// nothing, because the floor moved nothing.
	//
	// Recorded on the finding so RankedSeverity can be computed from the finding alone. A report
	// read back from results.sarif, by `draugr diff` or a gate on new findings, has no control
	// table to consult, and judging it without the floor gives a different verdict from the run
	// that wrote it.
	SeverityFloor Severity `json:"severityFloor,omitempty"`
	// Control names the check this finding came from, sca, sast, secrets. Stamped when a run's
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
	// A location alone is ambiguous the moment a descriptor has two components: three components have
	// three go.mod files, and two can carry the same path. It is also what makes the priority
	// checkable. The band is computed from the component's declared exposure and criticality, so a
	// report showing the band without naming the component states a conclusion and withholds its
	// premise.
	Component string `json:"component,omitempty"`
	// Exposure and Criticality are that component's declared classification. How reachable it is to
	// an attacker, and how much depends on it. The half of the priority calculation that comes from
	// the descriptor rather than from the scanner.
	//
	// Carried on the finding because naming the component is not the same as stating its premise.
	// Every other input to a band already travels with it: the scanner's score, the dataset that
	// raised it and the day that copy was obtained, the analyzer that ranked it down and how. A
	// report that records all of those and then requires a descriptor to be fetched before the two
	// remaining inputs can be read is one an auditor cannot settle from the evidence in front of
	// them. And the descriptor they would fetch is the one in the repository today, not necessarily
	// the one that produced this band.
	//
	// Empty for a project-scoped finding, which belongs to no one component, and for a component that
	// declares neither. Which Draugr reads as public and critical, so that an unclassified component
	// surfaces rather than hides.
	//
	// Strings rather than the descriptor's own types: `saga` imports this package, so the
	// dependency cannot run the other way. These carry `saga.Exposure` and `saga.Criticality`
	// values.
	Exposure    string `json:"exposure,omitempty"`
	Criticality string `json:"criticality,omitempty"`
	// UpgradePolicy is the largest version step the fix list may propose for this finding's
	// package, `patch` or `minor`, from the component's fixes.upgrade. Empty means major, the
	// default. Carried for the reason Exposure is: a report read back without the descriptor gives
	// the same advice.
	UpgradePolicy string `json:"upgradePolicy,omitempty"`
	// UpgradePolicyFrom is the descriptor key that set UpgradePolicy, `config.fixes.upgrade` or
	// `components["web"].fixes.upgrade`, so the fix list names the setting a reader would change.
	UpgradePolicyFrom string `json:"upgradePolicyFrom,omitempty"`
	// Labels are the component's own metadata, carried so a consumer holding many components can
	// narrow to the ones somebody is answerable for.
	//
	// The organization's vocabulary rather than Draugr's: nothing here reads a key or attaches a
	// meaning to one, and no key is privileged. A team that files by squad, by tier, by regime or
	// by all three is describing its own shape, and a tool that decided what `team` meant would be
	// describing a different one.
	//
	// They never reach a verdict, and never reach the console, the markdown report or a
	// pull-request comment. Those answer what to fix for somebody who already knows the work is
	// theirs. Filtering a fleet is a question asked where there is a fleet.
	Labels map[string]string `json:"labels,omitempty"`
	// Repository is the repository this finding was found in, for a component that has more than one,
	// or a fragment that contributed one from somewhere else.
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
	// Empty for a finding with no file and line. A vulnerable dependency is identified by its
	// package, which is already on the finding. Absent means "no content-based identity", and a
	// fabricated one would be worse than none.
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	// Package identifies the dependency a finding is about, when it is about one.
	//
	// Nil for a finding that is not: a SAST rule is about a line of code, an IaC check about a
	// resource. Set by the scanners that know, which is those reading a package manifest or an
	// image's installed set.
	Package *Package `json:"package,omitempty"`
	// Module is the downloaded Terraform module a finding lies in, when it lies in one. Its Location
	// is then the `module` block in the repository that brought the module in, the one line the
	// repository holds and its maintainer can change, and Module says where in the module the
	// setting is.
	Module *Module `json:"module,omitempty"`
	// PrivilegeDrop is where the entrypoint script of an image a finding says runs as root starts the
	// application as another user instead. Nil wherever that was not read in the script, which is
	// every finding but a Dockerfile's "image user should not be root".
	//
	// Evidence, never a verdict: the band and the counts stay as they are, and the finding is listed
	// after the others in its band. Not part of Fingerprint, for the reason Escalation is not.
	PrivilegeDrop *PrivilegeDrop `json:"privilegeDrop,omitempty"`
	// Aliases are the other identifiers the scanner reported for this same finding, beside the one
	// its rule id carries. retire.js names an advisory's CVEs and its GitHub advisory id together,
	// and a rule id holds one of them; govulncheck names the Go advisory id beside the CVE or GitHub
	// advisory id it reports; Grype names the vulnerabilities it relates to the match; Trivy names a
	// language package's other advisory ids, such as the GitHub advisory id, beside the CVE.
	//
	// Correlation reads them, so the finding is counted once with another scanner's copy of the flaw
	// keyed on any of them, and so does the fold of a reachability verdict onto that copy. Only what
	// the scanner said about this one finding, never an identifier looked up afterwards: two
	// advisories a database links are not always one flaw, and only the scanner reporting the
	// finding is asserting that its identifiers are.
	//
	// One exception, in correlation alone: a finding that names no CVE joins another scanner's copy
	// keyed on the CVE its CVELookup holds, where that lookup answered from one record and the record
	// lists exactly one CVE among its aliases, the Go vulnerability database's statement that the two
	// ids are one vulnerability. The copies must still share the component, the repository or image, and
	// the package and its version, and come from two scanners. The reachability fold reads Aliases alone.
	//
	// Not part of Fingerprint, for the reason Package is not. Kept in the cache, so a cached scan
	// correlates as a fresh one does, and not written to results.sarif, which carries the
	// correlation they decided.
	Aliases []string `json:"aliases,omitempty"`
	// CVELookup is the CVEs Draugr found for this finding in an advisory database, where neither its
	// rule id nor its Aliases name one, and the record that lists them. KEV and EPSS are keyed on a
	// CVE, so a finding named only by its Go advisory id is otherwise one neither can raise.
	//
	// Apart from Aliases, which are only what the scanner stated: a reader, and correlation, can tell
	// an identifier the scanner asserted from one looked up afterwards. Set only where exactly one
	// record answers, and never from a record other than the one the finding names.
	CVELookup *CVELookup `json:"cveLookup,omitempty"`
	// Objects are the things at fault, each named as the message names it, for a finding that
	// stands for every object failing one check: a Kubernetes check reported once per cluster with
	// its offending pods listed in the message.
	//
	// The message of such a finding changes whenever one object joins or leaves the list, so a
	// comparison keyed on the message alone takes a check that still fails for a check that was
	// fixed and a new one. `draugr diff` reads these instead, to tell a check that gained an object
	// from one nothing changed in. Every object, never the shortened list a message may print.
	//
	// Not part of Fingerprint: the message already carries what they add within one run.
	Objects []string `json:"objects,omitempty"`
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
	// OSEndOfLife marks a finding whose operating system release no longer receives security updates
	// from its vendor, Trivy's EOSL, End Of Service Life.
	//
	// It changes what the finding means. On a supported release, "no fix available" is a state
	// that will end when the vendor publishes one; on a release past end of life, no fix is ever
	// coming, and upgrading the release is the only action that resolves it. That is usually the
	// highest-leverage move available, because it resolves every finding in the OS layer at once.
	OSEndOfLife bool `json:"osEndOfLife,omitempty"`
	// ProviderOperated marks a finding about a surface somebody else runs, the control plane of a
	// managed Kubernetes cluster being the case it exists for.
	//
	// Set from what the descriptor declares, never guessed: whether a cluster is managed is a
	// fact about a contract, not something visible in what a scanner reads. It is the same
	// argument that puts exposure and criticality in the descriptor.
	ProviderOperated bool `json:"providerOperated,omitempty"`
	// BuiltUpstream marks a finding inside something somebody else publishes, an image this team only
	// runs, or a repository it uses and does not maintain.
	//
	// It changes the action rather than the severity. A vulnerable library in an image this team
	// builds is theirs to upgrade; the same library in an image they only run is fixed by taking
	// a newer image, and telling them to upgrade the library is advice they cannot act on. A
	// denied license in the dependency tree of a repository they do not publish is the same
	// shape: not a license they chose, and not one they can swap out.
	//
	// Stamped by the engine from what the job's target declares, so a scanner cannot forget it.
	BuiltUpstream bool `json:"builtUpstream,omitempty"`
	// Layer is the image layer the finding's package arrived in. Nil for anything that is not an
	// image finding, and for an image whose scanner did not report one.
	//
	// It is the only reliable answer to "is this mine or inherited". An image records nothing about
	// what it was built FROM. The name is not in there, so a base image cannot be named, and where a
	// multi-layer base ends is not knowable either. The layer, and the build step that created it,
	// are facts; anything further is inference and has to be labeled as such.
	Layer *Layer `json:"layer,omitempty"`
	// Suppression is set when a Saga exclusion matched this finding. A suppressed result is
	// reported but not counted: it does not reach Counts, the verdict, or the fix-first list.
	// Nil for an active finding.
	Suppression *Suppression `json:"suppression,omitempty"`
	// Rating is set when the scanner published its own rating of this finding beside the SARIF
	// level, and that rating decided the severity. Nil where the level or a numeric score did.
	Rating *Rating `json:"rating,omitempty"`
	// Escalation is set when exploitability enrichment raised this finding's severity, and says
	// which signal did it. Nil when nothing moved it.
	//
	// Suppression's twin: one records a decision to count a finding for less, this one records
	// evidence that it deserves more. Both answer the same question, a report that states a
	// conclusion and withholds its premise is a hint rather than evidence, and "critical because CISA
	// observed this being exploited, as of a date you can check" is the premise.
	Escalation *Escalation `json:"escalation,omitempty"`
	// Exploited is the catalog of observed exploitation that lists this finding's CVE, CISA's KEV,
	// with the day it was fetched. Set whether or not the listing moved the severity. Nil where the
	// CVE is not listed or no catalog was consulted.
	//
	// Kept apart from Escalation, which records that a band moved. A finding the scanner already
	// rated critical is listed and moves nothing, and the fix list still orders the action that
	// clears it first in its band.
	Exploited *Match `json:"exploited,omitempty"`
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
	// CWE are the CWE ids of the flaw, such as CWE-79, where a converter that may set them stated
	// them, or a tool's own file names them, as Veracode Pipeline Scan's does. Empty on every other
	// finding.
	CWE []string `json:"cwe,omitempty"`
	// Converter is set on every finding read from a converter's file, and says which converter wrote
	// it, under which contract, from which file, and which of Draugr's properties it set. Nil on
	// every other finding.
	//
	// A converter's properties are trusted because the descriptor declared it, and the stamp is what
	// lets a reader see which properties rest on that trust rather than on a scanner's own output.
	Converter *Converter `json:"converter,omitempty"`
}

// Converter records that a declared converter wrote a finding, and what it set on it.
type Converter struct {
	// Name is the converter's name, as the descriptor declares it and the file states it.
	Name string `json:"name"`
	// Version is the converter's own version, where the file states one.
	Version string `json:"version,omitempty"`
	// Contract is the contract version the file follows.
	Contract int `json:"contract"`
	// SHA256 is the SHA-256 of the file Draugr read.
	SHA256 string `json:"sha256"`
	// Set are the properties the converter set on this finding, such as package and cwe. Empty where
	// it set none, and the finding is only what the tool reported.
	Set []string `json:"set,omitempty"`
	// Raise is the band the converter asked the finding be ranked at least at, nil where it asked
	// none. The priority's floor says whether it moved the band.
	Raise *Raise `json:"raise,omitempty"`
}

// RaiseNote is what a finding's PriorityFloor says where the converter's raise moved its band:
// "raised to P1 by converter acme-deps, on the internal exploited list". Empty where it asked none.
func (c *Converter) RaiseNote() string {
	if c == nil || c.Raise == nil {
		return ""
	}
	return "raised to " + c.Raise.Priority + " by converter " + c.Name + ", " + c.Raise.Reason
}

// RaisedByConverter reports whether the finding's band is where it is because a declared
// converter's raise moved it, rather than a control's floor.
func (r Result) RaisedByConverter() bool {
	return r.PriorityFloor != "" && r.PriorityFloor == r.Converter.RaiseNote()
}

// Raise is a band a converter asked a finding be ranked at least at, and why.
type Raise struct {
	// Priority is the band, P1 to P4.
	Priority string `json:"priority"`
	// Reason is why, in the converter's words.
	Reason string `json:"reason"`
}

// Remediation says who can resolve a finding and by what kind of action. It is the answer to
// "can I do something about this", which is the question a reader has after the severity.
type Remediation string

// The kinds of remediation, most actionable first.
const (
	// RemediationUpgrade: a version that fixes it exists, in something the reader controls.
	RemediationUpgrade Remediation = "upgrade"
	// RemediationUpstream: nothing fixes it where it is, but the thing underneath can move, an
	// operating system release past end of service life, whose successor is the fix. One action, and
	// it resolves everything in that layer at once.
	RemediationUpstream Remediation = "upstream"
	// RemediationExternal: the surface is operated by somebody else. Still found, still reported,
	// still counted, never presented as something to go and fix, because telling a reader to change a
	// file on a control plane they cannot reach is worse than saying nothing.
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
// there are. "3 of 9" is interpretable where a bare digest is not, and the low indices are the
// inherited ones.
type Layer struct {
	// DiffID is the layer's content digest, as the image records it.
	DiffID string `json:"diffId,omitempty"`
	// Index is the layer's position from the bottom of the image, starting at 0.
	Index int `json:"index"`
	// Of is the number of layers in the image.
	Of int `json:"of,omitempty"`
	// CreatedBy is the build instruction that produced the layer, verbatim from the image's own
	// history. "RUN /bin/sh -c apt-get install …". It names the line to change, which is more use
	// than a layer digest and more honest than a guessed base image.
	CreatedBy string `json:"createdBy,omitempty"`
}

// Module is a downloaded Terraform module a finding lies in.
type Module struct {
	// Source is the module block's `source`, such as terraform-aws-modules/s3-bucket/aws.
	Source string `json:"source"`
	// Version is the block's `version`, empty where it gives none.
	Version string `json:"version,omitempty"`
	// File and Line are where in the module the finding is, the path relative to the module.
	File string `json:"file,omitempty"`
	Line int    `json:"line,omitempty"`
}

// PrivilegeDrop is the line of an image's entrypoint script that starts the application as a user
// other than root, on every path a start as root takes through the script.
//
// It answers a check that reads only the Dockerfile. A Dockerfile without `USER` runs its entrypoint
// as root, and a script that chowns a volume and then hands over with `exec su-exec app "$@"` needs
// to start that way. The record says which line of which file hands over, so a reader can check it.
type PrivilegeDrop struct {
	// Command is the program that switches user: su-exec, gosu, setpriv, runuser, s6-setuidgid or
	// chpst.
	Command string `json:"command"`
	// User is the user it switches to, as the script writes it with its quotes removed: `app`,
	// `1000:1000` or `$PUID:$PGID`.
	User string `json:"user"`
	// File is the script, relative to the repository root, and Line the line of the switch.
	File string `json:"file"`
	Line int    `json:"line"`
}

// Package is the dependency a finding is about.
//
// Scanners have always known this and only ever said it in prose. Trivy's message reads "Package:
// flask\nFixed Version: 0.12.3", which is a fact formatted for a human and unavailable to anything
// else. Three things wanted it and could not have it: GitLab's dependency and container reports,
// which require a structured name and version; correlating a run's findings with the SBOM it
// produced alongside them; and a VEX statement that can say which package within a product carries
// a vulnerability rather than only that the product does.
//
// Deliberately not part of Fingerprint. The same flaw in the same package at the same location is
// the same finding whether or not the scanner told us which package. So adding this must not split
// a finding in two the day a scanner starts reporting it.
type Package struct {
	// Name is the package as its ecosystem names it, e.g. "flask".
	Name string `json:"name"`
	// Version is what is installed.
	Version string `json:"version,omitempty"`
	// FixedVersion is the first release that resolves the finding. Empty when there is none. Which is
	// a different and more alarming answer than "unknown", and the reason this is reported rather
	// than inferred from the absence of a fix.
	FixedVersion string `json:"fixedVersion,omitempty"`
	// PURL is the package URL, e.g. "pkg:pypi/flask@0.12.2". The one identifier that is portable
	// across ecosystems and the one every consumer of this asked for first.
	PURL string `json:"purl,omitempty"`
	// Ecosystem is the package manager the name belongs to, as the ecosystem calls itself: "pip",
	// "npm", "gem". A name alone is ambiguous. There is a `request` on npm and a `requests` on PyPI,
	// and neither is the other.
	Ecosystem string `json:"ecosystem,omitempty"`
	// Dev says the manifest declares the package as a development dependency only: a test runner, a
	// build tool, a linter. False where the scanner reported it as a runtime dependency, and where
	// the scanner cannot tell the two apart, so false is not a claim that it ships.
	Dev bool `json:"dev,omitempty"`
	// Provided says the manifest declares the package as supplied by the runtime the application is
	// deployed into: a pom.xml dependency in Maven's provided or system scope, which is compiled
	// against and left out of what is packaged. False where the manifest puts it on the
	// application's own classpath, and where nothing read the manifest's scope.
	Provided bool `json:"provided,omitempty"`
	// CPEMatch says the scanner matched the package to the advisory only through a CPE, a product
	// identifier it built from the package's name and version, and found no advisory for the package
	// in its own ecosystem. A package named like a product then inherits that product's advisories at
	// whatever version it carries. False where any match of the finding used the package's ecosystem,
	// and on a binary the scanner identified by its contents, where the CPE is the only identifier.
	CPEMatch bool `json:"cpeMatch,omitempty"`
	// Own says the package is the project itself rather than a dependency: the root of a
	// package-lock.json, a Cargo workspace member, a Dart package that is never published, a pod
	// taken from a directory of the repository. Its name can still be a published package's, and a
	// scanner then matches it against that package's advisories. False for every package the
	// project fetches from somewhere else.
	Own bool `json:"own,omitempty"`
	// Range is the version requirement Version was read from, where the manifest states a range
	// rather than a pin: `>=10.4,<11` in a requirements.txt, written without spaces, read as 10.4.
	// Version is then the lowest release the range admits, which is not necessarily what installs; a
	// lockfile beside the manifest says what does. Empty where the version was pinned, and wherever
	// the scanner read no range.
	Range string `json:"range,omitempty"`
}

// Escalation records that exploitability data raised a finding's severity, and on what grounds.
//
// Deliberately not part of Fingerprint: a finding is the same finding whether or not a feed
// moved it, and folding this in would make every diff churn on the day EPSS reprices a CVE.
type Escalation struct {
	// From is the severity before enrichment, the scanner's own rating, and the one the report still
	// displays, because it is what the scanner actually said.
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
	// AlsoMatched are the datasets that applied to this finding without being the one that set
	// its rating.
	//
	// Only one signal can raise a severity, so without this the others leave no trace at all, and the
	// one that loses is always the same one. KEV outranks EPSS wherever both fire, so anything
	// counting how often a dataset reached a finding reads EPSS as having done less than it did, by
	// an amount nothing in the record reveals.
	AlsoMatched []Match `json:"alsoMatched,omitempty"`
	// CVE is the CVE the dataset matched, where the finding's rule id names none and the CVE came
	// from its aliases. Empty where the rule id names it, which is then the CVE matched.
	//
	// A finding named by its advisory, `GHSA-4rgh-jx4f-qfcq-http`, raised on KEV says nothing a
	// reader can look up in the catalog, which lists CVEs.
	CVE string `json:"cve,omitempty"`
}

// Rating is a scanner's own rating of a finding, finer than the SARIF level it also wrote, and the
// severity a table written for that scanner gives it.
//
// A SARIF level has three rungs and gives no reason for the one it picks. Semgrep publishes each
// rule's impact and likelihood, and Bandit each result's severity and confidence, and both still
// write `error` for a confirmed injection and for a pattern flagged only for review, which a level
// reads as the same severity.
//
// The scanner's words are kept beside the conclusion, the way Escalation keeps From beside To: the
// level stays what the scanner wrote, and a reader can check the severity against the fields it was
// read from. Deliberately not part of Fingerprint, for the reason Escalation is not.
//
// One control replaces the level: `secrets` reports every finding at `error`, the value code
// scanning and JUnit read. Where the scanner's level was what rated the finding, the control keeps
// it here first, as the severity that level gives and the field "level", with no Detail.
type Rating struct {
	// Severity is the band the scanner's table gives the rating.
	Severity Severity `json:"severity"`
	// Detail is the part of the rating that decided Severity, as the report prints it:
	// "impact high · likelihood high". Empty for a level kept by the control that replaced it.
	Detail string `json:"detail,omitempty"`
	// Fields are the rating fields the scanner published, under the scanner's own names and
	// with the scanner's own values: "impact": "HIGH".
	Fields map[string]string `json:"fields,omitempty"`
}

// Match is a dataset that applied to a finding.
//
// The same three facts an Escalation carries about the dataset that won, minus the severities:
// a match that did not set the rating moved nothing, and naming a from and a to for it would
// describe a change that never happened.
type Match struct {
	// Signal names the dataset: "kev" or "epss".
	Signal string `json:"signal"`
	// Detail is the specific fact, e.g. "on KEV" or "EPSS 0.87".
	Detail string `json:"detail"`
	// AsOf is the day the data was fetched, as YYYY-MM-DD.
	AsOf string `json:"asOf,omitempty"`
	// CVE is the CVE the dataset matched, where the finding's rule id names none, as on Escalation.
	CVE string `json:"cve,omitempty"`
}

// CVELookup is a finding's CVEs as an advisory database lists them, and where that came from.
//
// Recorded whole, so a reader of a `GO-…` row raised on KEV can open the record that named the CVE
// and check it, as they can check the KEV listing by its date.
type CVELookup struct {
	// CVEs are the CVEs the record lists as its aliases, in the record's order.
	CVEs []string `json:"cves"`
	// ID is the identifier the finding named and the lookup was keyed on: a Go advisory id, or a
	// GitHub advisory id the database lists as an alias.
	ID string `json:"id"`
	// Record is the database record that lists the CVEs, `GO-2020-0001`.
	Record string `json:"record"`
	// Dataset names the database, as the run's `consulted` names it: "govulndb".
	Dataset string `json:"dataset"`
	// AsOf is the day the copy was fetched, as YYYY-MM-DD.
	AsOf string `json:"asOf,omitempty"`
}

// ReachabilityState says whether this project's own code can reach a dependency's vulnerable
// code. Three values rather than two, because the third is the one that keeps the other two
// honest, and a fourth that is evidence rather than a verdict.
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
	// The whole reason the state is explicit. An analyzer that never looked at a dependency produces
	// exactly the same silence as one that looked and found nothing, and treating the two alike turns
	// "we did not check" into "you are fine". Which is the failure this codebase refuses everywhere
	// else. A tool that cannot say which of the two it means may only report this.
	ReachabilityUnknown ReachabilityState = "unknown"
	// ReachabilityNotBuilt means the analyzer read the build it analyzed and the dependency is in
	// none of the packages that build compiled. Build names the platforms and build tags read.
	//
	// A state of its own rather than unreachable with a weaker method, so that everything which
	// counts, ranks or marks unreachable findings leaves it alone without a case of its own. It
	// moves nothing: the platforms analyzed may not be every platform the module ships for, and a
	// dependency compiled only for one nobody analyzed is still in that binary. Lowering on it would
	// take the safer reading of a build nobody looked at. It is shown beside the finding, and the
	// finding is ranked as though no analyzer had spoken.
	ReachabilityNotBuilt ReachabilityState = "not-built"
)

// Reachability records whether this project's code can reach a dependency's vulnerable code,
// and on what evidence.
//
// The third member of a family, and it inherits both of the family's rules. Suppression records
// that a person decided to count a finding for less; Escalation records evidence that it deserves
// more; this records evidence about whether the code can be reached at all. Like Escalation it
// feeds the priority matrix and never rewrites the severity the scanner reported, and like
// Escalation it is deliberately not part of Fingerprint. A finding is the same finding whether or
// not analysis moved it, and folding this in would churn every diff on the day a call is added or
// removed.
//
// Unlike Suppression it never excuses a finding. An inference is not a decision, and a finding
// that disappears because a call graph did not find a path has no author to ask about it.
type Reachability struct {
	// State is the verdict: reachable, unreachable, or unknown.
	State ReachabilityState `json:"state"`
	// Analyzer names the tool that decided, e.g. "govulncheck".
	Analyzer string `json:"analyzer"`
	// Method is how it decided, one of the Method constants below. Buyers are told to reject
	// reachability claims that do not say how they were reached, and they are right to: a call
	// graph and a framework heuristic are both called reachability and are not the same evidence.
	// ProvesAbsence is where that difference is acted on.
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
	// Platforms are the platforms, as GOOS/GOARCH, whose build the verdict was reached over, where
	// it was not the machine's own: a call into the vulnerable code from a file behind
	// `//go:build windows`, found on Linux by a run for windows/amd64. Empty for a verdict over the
	// machine's own build.
	Platforms []string `json:"platforms,omitempty"`
	// Build is the build a ReachabilityNotBuilt or ReachabilityUnreachable state was read from, and nil
	// for any other state. A
	// module missing from a build is missing from that build only: one built only under a tag nobody
	// set, or only for a platform nobody analyzed, is still in somebody's binary, so the evidence
	// names what it looked at.
	Build *AnalyzedBuild `json:"build,omitempty"`
}

// AnalyzedBuild is the build an analyzer compiled: the platforms it built for and the build tags set
// beyond the go command's defaults.
type AnalyzedBuild struct {
	// Platforms are the platforms, as GOOS/GOARCH, the machine's own first.
	Platforms []string `json:"platforms"`
	// Tags are the build tags set, from `-tags` in GOFLAGS. Empty means none beyond the defaults.
	Tags []string `json:"tags,omitempty"`
}

// PackageVerdict is a reachability verdict about every finding on one package declared in one
// dependency file, rather than about one advisory.
//
// An analyzer reports advisories only for what it analyzed, so a package it never compiled has no
// finding of its own for a verdict to travel on. The verdict about that package travels here, and
// the engine moves it onto the findings other scanners reported for the package in that file.
type PackageVerdict struct {
	// Repository and Component say whose file it is, stamped after the scan as an Input's are.
	Repository string `json:"repository,omitempty"`
	Component  string `json:"component,omitempty"`
	// Path is the dependency file that declares the package, relative to the repository root.
	Path string `json:"path"`
	// Package is the package's name as the file declares it: a Go module path.
	Package string `json:"package"`
	// Reachability is the verdict.
	Reachability Reachability `json:"reachability"`
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
// and their own account of what they saw, because the disagreement between two scanners is the
// reason to run two, and a merge that keeps one opinion throws away the thing you were paying for.
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
// the same CVE medium and low have said something neither says alone. They draw on different
// advisory sources, and the gap is a statement about coverage. A reader who only learns that a
// second tool "also found it" cannot see that, and the console has nothing to show them.
type Observation struct {
	// Tool is the scanner that made this observation.
	Tool string `json:"tool"`
	// RuleID is what that scanner called it, which is not always what the counted finding is called.
	// And is the id an exclusion may already be written against.
	RuleID string `json:"ruleId,omitempty"`
	// Severity and Score are that scanner's own rating, kept whether or not it agrees. The
	// report decides what is worth showing; the record does not get to be selective.
	Severity Severity `json:"severity,omitempty"`
	Score    float64  `json:"score,omitempty"`
	// Location is the file this copy is in, for the row that names the counted copy's. Not written:
	// each copy is a result of its own in the report, with its location.
	Location string `json:"-"`
}

// ImportScanner is the name of Draugr's scanner that reads a SARIF file another tool wrote, which
// the engine stamps as the Scanner of every finding read from one.
const ImportScanner = "sarif-import"

// The keys of the counts the import scanner records in its Provenance.Detail, each a decimal count of
// one file's findings in one component, present only where it is above zero.
const (
	// ImportOutsidePaths counts the findings left out because their file is outside the paths: of
	// the repository they were placed in.
	ImportOutsidePaths = "outsidePaths"
	// ImportIgnored counts the findings left out because the repository's ignore: matches their file.
	ImportIgnored = "ignored"
	// ImportNotScoped counts the findings kept whole in a component whose repositories declare paths:
	// or ignore:, because the file establishes no one repository whose scope would apply.
	ImportNotScoped = "notScoped"
	// ImportUnbound is, for an import of a service's alerts that nothing binds to the commit the
	// run reads, the sentence its unbound-imports caveat says why in. Not a count.
	ImportUnbound = "unbound"
	// ImportFolded counts the findings that repeated another of the file's in every respect its
	// fingerprint compares, and were counted once.
	ImportFolded = "folded"
)

// ImportAnalysesElsewhere is the key of the import scanner's provenance field naming the code-scanning
// analyses GitHub last ran at another commit than the one the run reads. Reports show it only with
// the evidence, since the commit field already counts them.
const ImportAnalysesElsewhere = "analyses"

// Reporter names who gave an account of a finding, for telling one flaw's copies apart: the tool,
// and for a finding read from another tool's file, the tool marked as imported, with the format
// where the file is the tool's own JSON: `imported trivy (trivy-json)`.
//
// The tool's name alone does not tell them apart. Semgrep's file names its tool `Semgrep OSS`, as
// the Semgrep that Draugr runs does, and the two are separate runs that each found the flaw. Under
// one name they would read as one scanner's two findings, which correlation keeps apart, and a row
// counting one would name the other as itself.
func (r Result) Reporter() string {
	if r.Scanner != ImportScanner {
		return r.Tool
	}
	name := "imported"
	if r.Tool != "" {
		name += " " + r.Tool
	}
	if r.ImportFormat != "" {
		name += " (" + r.ImportFormat + ")"
	}
	return name
}

// Correlated reports whether another scanner's finding is the one being counted for this flaw.
//
// True only on the copies that are not counted. The finding that is counted has a Correlation too,
// naming who else found it. And is very much still a finding.
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
	// Expires is when the acceptance lapses, as YYYY-MM-DD. Empty means it does not.
	Expires string `json:"expires,omitempty"`
	// VEXStatus is what the exclusion declared this suppression means as a claim about the product:
	// not_affected, affected, or fixed. Empty when the exclusion said nothing, which is the common
	// case and reports as affected. The reading that is never an overstatement.
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
	// Author is who asserted an imported claim, the VEX document's author. Empty for a descriptor
	// rule, whose author is the git history of the line Source and Line name.
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
	// authorized each one, otherwise composition trades a long descriptor for an unanswerable one,
	// which is the worse of the two.
	Source string `json:"source,omitempty"`
	// StatementID is, for an imported claim, the statement's id within its VEX document, where the
	// supplier gave one. Empty for a descriptor rule, and for a statement with no id.
	StatementID string `json:"statementId,omitempty"`
	// Digest is, for an imported claim, the sha256 of the VEX document as read, so a reader can tell
	// which revision of a document excused the finding. Empty for a descriptor rule.
	Digest string `json:"digest,omitempty"`
	// Line is the line in Source the exclusion starts at, for a descriptor rule. Zero where it is
	// not known. Source and Line together name the exclusion that set the finding aside, which is
	// how report.json's descriptor.exclusions[] entry for it, and its git history, is found.
	Line int `json:"line,omitempty"`
	// Service is the service an imported finding was dismissed in, such as GitHub code scanning,
	// where a person dismissed the alert there rather than a file recording a suppression. Author is
	// then who dismissed it, Asserted when, and Source the alert. Empty for a suppression read from a
	// file and for every one Draugr makes.
	Service string `json:"service,omitempty"`
}

// Where says where a tool recorded that it suppressed a finding: dismissed in the service for one
// dismissed there, and otherwise as SuppressedIn reads the kind.
func (s Suppression) Where() string {
	if s.Service != "" {
		return "dismissed in " + s.Service
	}
	return "suppressed " + SuppressedIn(s.Kind)
}

// Where a suppression's decision came from, for Suppression.Origin.
//
// Draugr stamps the two it makes itself, and reads the third off their absence: a suppression in a
// scanner's report that Draugr did not put there is one the scanner honored out of the file it
// scanned. Nothing here parses a comment or opens a supplier's document, so the value says which
// party made the claim and never that the claim is true.
const (
	// OriginSaga is a rule in this project's own descriptor.
	//
	// Written onto every suppression the exclusion rules make. An empty Origin beside a name is
	// read as this too, so a report written before origins were recorded still means what it said.
	OriginSaga = "saga"
	// OriginVEX is a statement imported from a document somebody else wrote.
	OriginVEX = "vex"
	// OriginTool is a suppression the scanner already carried, honoring a directive in the file it
	// scanned: a Semgrep `nosem`, a `# noqa`, a linter's inline pragma.
	//
	// Read off the absence of Draugr's own record rather than detected, because the alternative is
	// a parser per scanner per comment syntax, all of them guessing at what the tool meant. Which
	// of the two a scanner's suppression is comes from SARIF's own `kind`, a required field, so
	// nothing here infers it either. The one exception is gosec's scanner, which marks a result
	// under a golangci-lint `nolint` directive naming gosec itself: golangci-lint, which most Go projects run gosec through,
	// reads that directive, and gosec on its own does not.
	//
	// The weakest of the four, and kept apart for that reason. A descriptor rule was reviewed by
	// whoever owns the descriptor and a supplier's claim is answerable by the supplier; this one
	// was written by whoever was editing the file, possibly to get a build green, and nothing
	// about it went past a second person. Counting it with the others would let the weakest form
	// of acceptance hide inside the strongest.
	OriginTool = "tool"
	// OriginScanner is a suppression the scanner applied out of its own configuration: a
	// `.trivyignore` line, a `.gitleaksignore` entry, a rule in `.grype.yaml`.
	//
	// Apart from OriginTool because the two answer "who do I ask" differently. A directive beside
	// the line is the work of whoever was editing that line. A file of exclusions is a file in the
	// repository, changed by a commit somebody can read, which puts it nearer the descriptor than
	// the comment. It is still outside the descriptor, still carries no required reason, and is
	// still not what the register was built to show.
	//
	// SARIF calls this kind `external`, which is also what Draugr writes for its own; ours are told
	// apart by the record they carry, never by the kind.
	OriginScanner = "scanner"
	// OriginSetting is a class of findings a control's setting sets aside, such as
	// config.controls.sca.devDependencies setting aside the findings in development dependencies.
	//
	// Apart from OriginSaga because nobody judged the finding: the setting names a kind of
	// finding, and Source names the setting rather than a file. It still lives in the descriptor or
	// is the setting's default, so it is answerable here, and a reader changes it by editing the key.
	OriginSetting = "setting"
)

// JustificationDevDependency is the reason recorded on a finding that
// config.controls.sca.devDependencies set aside.
const JustificationDevDependency = "development dependency"

// JustificationProvidedByRuntime is the reason recorded on a finding that
// config.controls.sca.providedDependencies set aside.
const JustificationProvidedByRuntime = "provided by the runtime"

// JustificationCPEMatch is the reason recorded on a finding that a control's cpeMatches set aside.
const JustificationCPEMatch = "matched by CPE only"

// JustificationOwnPackage is the reason recorded on a finding that config.controls.sca.ownPackages
// set aside.
const JustificationOwnPackage = "the project's own package"

// JustificationDetectSecretsBaseline is the reason recorded on a finding that
// config.controls.secrets.detectSecretsBaselines set aside.
const JustificationDetectSecretsBaseline = "a hash in a detect-secrets baseline" // #nosec G101 -- a reason phrase naming a file format, not a credential

// The values of Result.Aside.
const (
	// AsideGenerated marks a finding in a Go file whose header says a generator wrote it, the
	// `// Code generated ... DO NOT EDIT.` line the go command defines. The fix is in the generator.
	AsideGenerated = "generated"
	// AsideTooling marks a finding in a dependency file of a tool the developers install rather than
	// of the application: one under `.config/mise/`, or the go.mod or go.sum of a Go module that
	// builds nothing but tools. The tool still runs on their machines and in CI.
	AsideTooling = "tooling"
	// AsidePinned marks a GitHub Actions mutable-tag finding on a `uses:` reference that the
	// repository's `.github/workflows/actions.lock` pins to a commit for that workflow, or, in a
	// composite action in the same repository, for every workflow that calls the action.
	AsidePinned = "pinned"
)

// JustificationNonShipping is the reason recorded on a finding that a control's nonShippingPaths
// set aside, such as config.controls.iac.nonShippingPaths.
const JustificationNonShipping = "in docs, examples or tests"

// Suppressed reports whether this finding was excluded, by a Saga rule or by an imported claim.
func (r Result) Suppressed() bool { return r.Suppression != nil }

// SetAsideBySetting reports whether a control's setting set this finding aside rather than a rule
// naming it: OriginSetting.
func (r Result) SetAsideBySetting() bool {
	return r.Suppression != nil && r.Suppression.Origin == OriginSetting
}

// SilencedInSource reports whether a suppression came from a directive in the code rather than
// from a decision anybody recorded.
func (r Result) SilencedInSource() bool {
	return r.Suppression != nil && r.Suppression.Origin == OriginTool
}

// SetAsideByScanner reports whether the scanner set this aside rather than anybody here.
//
// Both of the scanner's own origins, because the question these counts and registers ask is whose
// decision it was, and the answer for a `.trivyignore` line is the same as for a `#nosec`: not
// this descriptor, and nobody's signature. Asking only about the narrower one filed a scanner's
// exclusion in the register of decisions somebody here signed.
func (r Result) SetAsideByScanner() bool {
	return r.Suppression != nil &&
		(r.Suppression.Origin == OriginTool || r.Suppression.Origin == OriginScanner)
}

// SetAsideInImport reports whether Draugr set this finding aside because the tool that wrote an
// imported SARIF file suppressed it, in a comment in the code or in its own settings.
//
// Apart from the scanners Draugr runs, because the reader's question is which tool to go and look
// in, and for an imported finding that is a tool this run never started.
func (r Result) SetAsideInImport() bool {
	return r.Scanner == ImportScanner && r.SetAsideByScanner()
}

// SuppressedIn says where a tool recorded that it suppressed a finding, from the SARIF kind it
// wrote: in a comment in the code for inSource, and in the tool's own settings for anything else,
// as scannersOwn reads the kind.
func SuppressedIn(kind string) string {
	if kind == "inSource" {
		return "in a comment in the code"
	}
	return "in the tool's own settings"
}

// WhoNotRecorded is who suppressed a finding, as a reader is shown it where the tool recorded
// nobody. A SARIF suppression has no field for a person, and saying so tells an unknown author apart
// from a field the report left out.
const WhoNotRecorded = "who: not recorded by the tool"

// GivenReason is a tool's justification for suppressing a finding as a reader is shown it, or that
// it gave none. SARIF makes the justification optional, and a blank would read as a reason the report
// failed to carry.
func GivenReason(justification string) string {
	if strings.TrimSpace(justification) == "" {
		return "no reason given"
	}
	return "reason: " + justification
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
	parts := []string{
		r.Tool, r.RuleID, string(r.Level), r.Message,
		r.Location.URI, strconv.Itoa(r.Location.StartLine),
		// The component is part of the identity, not decoration. Two components sharing a repository
		// produce the same flaw at the same line, and it is not the same finding: each carries its
		// component's exposure and criticality, so one can be P1 and the other P4. Collapsing them keeps
		// whichever merged first and silently discards the other. Which can be the urgent one, and
		// contradicts the whole claim that context decides priority.
		r.Component,
		// And the repository, for the same reason one level down: a component may hold several, and a
		// fragment may contribute one from another project entirely. Two of them with the same file at
		// the same line are two findings, one leaked credential per repository, not one between them.
		r.Repository,
	}
	// A finding inside a downloaded module is located at the block that calls the module, and every
	// finding of one rule in that module would share the block's line. Where in the module each is
	// tells them apart. Added only for such a finding, so no other finding's identity moves.
	if r.Module != nil {
		parts = append(parts, r.Module.Source, r.Module.File, strconv.Itoa(r.Module.Line))
	}
	if pkg := r.ImportedPackage(); pkg != "" {
		parts = append(parts, pkg)
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:])
}

// ImportedPackage is the package, name and version, that a dependency finding read from an imported
// file is about, and "" for any other finding, for an identity that has to tell two such findings
// apart.
//
// A tool's file may place every dependency finding at one line, Trivy's SARIF at the manifest's first,
// and name the package only in a message the import replaces with the advisory's title. One advisory
// in two packages is then two results alike in rule, place and message, and the package is all that
// tells them apart. Draugr's own scanners name the package in each dependency finding's message, so
// only an imported finding takes the package, and no native finding's identity moves.
func (r Result) ImportedPackage() string {
	if r.Scanner != ImportScanner || r.Package == nil || r.Package.Name == "" {
		return ""
	}
	return r.Package.Name + "@" + r.Package.Version
}

// Report is a set of findings, normalized to SARIF semantics. Tool names the primary
// scanner; when a report carries results from several tools (after Merge), each Result
// keeps its own Tool.
type Report struct {
	Tool    string   `json:"tool,omitempty"`
	Results []Result `json:"results"`
	// Rules is the metadata the scanner published about the rules it applied, keyed by rule id. A
	// result names its rule; the rule is what explains it. Carrying this through is what lets a
	// reader, in a terminal, an editor, or a pull request. Find out what "DS-0002" means. Not every
	// scanner publishes it, so entries may be missing.
	Rules map[string]Rule `json:"rules,omitempty"`
	// Provenance is what the scanners said about the run itself, as opposed to what they found:
	// which standard was applied, how much of it could be decided, what the scan was scoped to.
	//
	// A finding answers "what is wrong". Evidence also has to answer "what was measured, and against
	// what". And that was not recorded anywhere, so a compliance report could not say which benchmark
	// produced it. One entry per tool run; see Provenance.
	Provenance []Provenance `json:"provenance,omitempty"`
	// Decided are the classifications this run reached a verdict on, whether or not a finding
	// resulted. A taxon here with no finding means the scanner looked and found nothing wrong.
	//
	// The distinction this exists for: a scanner that reports nothing about a control has either
	// examined it and been satisfied, or never examined it at all, and those mean opposite things.
	// Without this, a report that says "1 of 2 scanners found it" is guessing that the other
	// dissented, when far more often the other simply does not check that control.
	//
	// "Decided" rather than "examined" on purpose: a check a scanner looked at and could not settle,
	// a CIS control that requires human judgement. Is not a dissent either.
	Decided []Taxon `json:"decided,omitempty"`
	// Consulted names the exploitability datasets this run had loaded, whether or not any of
	// them moved a finding.
	//
	// The same argument as Decided, one level up. An Escalation is written only when a signal raised
	// a severity, so its absence on a finding covers three unrelated cases: the CVE is not in the
	// dataset, it is but the finding was already at the top band, and the dataset was never loaded. A
	// consumer explaining a priority to somebody cannot tell "not on KEV" from "KEV was not
	// consulted" without this. And silence reads as the second, which makes the whole ranking look
	// like it came from nowhere.
	Consulted []Consulted `json:"consulted,omitempty"`
	// UnsettledChecks are the checks a scanner left for a person rather than decided. They are not
	// findings: nothing was seen to fail, and nothing in the target clears them, so they are kept out
	// of Results, the band counts and the gate, and listed here so the person who does the review
	// can find them.
	UnsettledChecks []UnsettledCheck `json:"unsettledChecks,omitempty"`
	// Inputs are the dependency files a scan accounted for: those it read packages from, and those
	// in its tree it did not, each with the reason.
	//
	// The argument Decided makes, applied to files. A dependency scan that reports nothing has
	// either read every manifest and found them clean or read none of them, and without this the
	// two produce the same empty report and the same PASS. Empty for a scanner that does not
	// account for its reads, which says nothing either way.
	Inputs []Input `json:"inputs,omitempty"`
	// Inventory is every package a dependency scan listed, with or without a finding. A finding
	// names only the packages a scanner had something to say about, and a package flagged as
	// malicious usually has no advisory a vulnerability scanner would match, so a lookup that read
	// the findings alone would never ask about it. Kept with a cached result so a cache hit carries
	// it too. Empty for a scanner that does not list what it read.
	Inventory []InventoryPackage `json:"inventory,omitempty"`
	// PackageVerdicts are reachability verdicts about a whole package in one dependency file, for a
	// package the analyzer has no finding of its own on: a Go module govulncheck's build never
	// compiled. Folded onto other scanners' findings with the per-advisory verdicts, and kept with a
	// cached result as Inventory is.
	PackageVerdicts []PackageVerdict `json:"packageVerdicts,omitempty"`
	// Unchecked are the checks a scan could not evaluate, or could evaluate only in part, each with the reason:
	// a read the check needs that the scan's identity was denied.
	//
	// The argument Inputs makes, applied to checks. A denied read does not fail a check: depending on
	// the check it passes, fails or produces nothing, so a check the scan could not evaluate and one
	// it found clean have to be told apart here rather than read off the results.
	Unchecked []Unchecked `json:"unchecked,omitempty"`
}

// Unchecked is one check a scan could not evaluate.
type Unchecked struct {
	// Scanner is the scanner whose check it is.
	Scanner string `json:"scanner"`
	// Component is whose check it was, stamped after the scan as an Input's is.
	Component string `json:"component,omitempty"`
	// Check is the check's identifier, and Group what it reads, which a reader grants access to:
	// the cloud service, such as "compute".
	Check string `json:"check"`
	Group string `json:"group"`
	// Reason is why it could not be evaluated, such as "denied compute.instances.list", or for a
	// precondition, which no grant clears, where to scan from instead: "scan from the management
	// account".
	Reason string `json:"reason"`
	// PartlyRead marks a check that returned results from the reads it was allowed. Its findings are
	// in the report, and it is not decided: what the denied read held was not looked at.
	PartlyRead bool `json:"partlyRead,omitempty"`
	// Kind is why: UncheckedDenied for a read the credential was refused, UncheckedPrecondition for
	// one the account cannot answer whatever it is granted. Empty where the scanner does not say.
	Kind string `json:"kind,omitempty"`
}

// The kinds of an Unchecked. Each is cleared by somebody doing something: a grant for a denial, a
// scan from another account for a precondition.
const (
	UncheckedDenied       = "denied"
	UncheckedPrecondition = "precondition"
)

// UnsettledManual is the kind of an UnsettledCheck the benchmark leaves to a person to decide.
const UnsettledManual = "manual"

// UnsettledNoResources is the kind of an UnsettledCheck with nothing of its kind to check in the
// account: it reads resources of one kind and there are none, so it neither passed nor failed.
const UnsettledNoResources = "no-resources"

// UnsettledCheck is one check a scan did not decide, and why.
type UnsettledCheck struct {
	// Scanner is the scanner whose check it is, and RuleID the rule it reports under, as a
	// config.exclude rule names it.
	Scanner string `json:"scanner"`
	RuleID  string `json:"ruleId"`
	// Title is the check as the benchmark words it.
	Title string `json:"title,omitempty"`
	// Control is the control the check belongs to. A run's checks of every control are written to
	// one SARIF run, which says nothing about which control any of them is.
	Control string `json:"control,omitempty"`
	// Component and Location are whose check it was and what it read, the cluster.
	Component string `json:"component,omitempty"`
	Location  string `json:"location"`
	// Kind is why it was not decided: UnsettledManual for a check the benchmark leaves to a person,
	// UnsettledNoResources for one with nothing of its kind to check.
	Kind string `json:"kind"`
	// Suppression is the decision recorded about it, where a config.exclude rule names it: the
	// reason somebody gave once they had reviewed it. Nil for a check still waiting on a person.
	Suppression *Suppression `json:"suppression,omitempty"`
}

// InputOperatingSystem is the Kind of an Input that stands for an image's operating system rather
// than a file: its packages, which an image scanner reads from the image's own package database.
const InputOperatingSystem = "operating-system"

// InventoryPackage is one package a dependency scan listed, and where it is declared.
type InventoryPackage struct {
	// PURL identifies the package and its version.
	PURL string `json:"purl"`
	// Scanner is the scanner that listed it.
	Scanner string `json:"scanner,omitempty"`
	// Repository and Component say whose package it is, stamped after the scan as an Input's are.
	Repository string `json:"repository,omitempty"`
	Component  string `json:"component,omitempty"`
	// Path is the dependency file it was read from, relative to the repository root, and Line the
	// first line of its entry there, or 0 where the scanner did not say.
	Path string `json:"path,omitempty"`
	Line int    `json:"line,omitempty"`
}

// Input is one dependency file as a scan accounted for it.
type Input struct {
	// Scanner is the scanner that read it, or did not.
	Scanner string `json:"scanner"`
	// Repository and Component say whose file it is. Stamped after the scan, like a finding's, so a
	// cached result shared by two components carries each one's name.
	Repository string `json:"repository,omitempty"`
	Component  string `json:"component,omitempty"`
	// Path is relative to the repository root.
	Path string `json:"path"`
	// Packages is how many packages the scanner read from the file.
	Packages int `json:"packages,omitempty"`
	// Kind is the scanner's name for the file's format, such as Trivy's `cargo` or `nuget`, which
	// covers both a packages.lock.json and a packages.config. Empty where the scanner does not say.
	Kind string `json:"kind,omitempty"`
	// Unread is why the file contributed no packages, and empty when it was read: "no lockfile",
	// "no pinned versions", "no packages read", or "not parsed: " and the parser's error. For a
	// Terraform file, the module blocks it calls that the scanner could not load, as `module "vpc"
	// not loaded`. For a file searched for secrets, "archive extension, not read" and what to do about it, or "no files read" against the repository root.
	// For a source file, why a SAST scanner did not check all of it, as `over 1 MB, not scanned`
	// and what to do about it, or `1 rule timed out, not checked: "x"`. For a go.mod, why govulncheck could not load the
	// module, as `not loaded by govulncheck: main.go:5:2: undefined: Assets`.
	//
	// With Packages above zero, the file was read in part and Unread names what was not read, as
	// `1 requirement not pinned: urllib3` for a requirements file, or `transitive dependencies not
	// resolved, run mvn dependency:resolve` for a pom.xml.
	Unread string `json:"unread,omitempty"`
	// Analysis says Unread is why an analysis of the code the file declares did not run, as for a Go
	// module govulncheck could not load, rather than why its packages were not read. Another scanner
	// reading the file's packages does not answer for it.
	Analysis bool `json:"analysis,omitempty"`
}

// Consulted is one exploitability dataset a run had available.
//
// Deliberately not the full provenance: where the copy came from and what its checksum was belong
// to the human-facing report, which has room for them. What a consumer of the evidence needs to
// explain a band is narrower. Which signals could have fired, and as of when.
type Consulted struct {
	// Signal names the dataset: "kev", "epss", "dependency-health", or "govulndb", the Go
	// vulnerability database a finding named only by a Go or GitHub advisory id is looked up in.
	Signal string `json:"signal"`
	// AsOf is the day the copy was obtained, as YYYY-MM-DD. Empty when the caller supplied a
	// file with no fetch to record, which is itself worth seeing.
	AsOf string `json:"asOf,omitempty"`
	// Stale reports that the copy was older than the run's configured maxAge when it was read.
	// Recorded at scan time because only the run knew the limit it was held to; a reader of the
	// evidence later has the date but not the policy.
	Stale bool `json:"stale,omitempty"`
	// Entries is how many records the dataset held. A feed that loaded and turned out to be
	// empty answers every lookup with "not listed", which is indistinguishable from a working
	// one unless somebody can see the count.
	Entries int `json:"entries,omitempty"`
	// Threshold is the EPSS probability at or above which a finding was raised. Zero for KEV, which
	// has no threshold. Being on it is the whole signal.
	Threshold float64 `json:"threshold,omitempty"`
	// ThresholdFrom names what set that threshold: the default, a descriptor key, or a flag.
	//
	// A number without its source is the one part of an escalation a reader cannot check. Every other
	// input says where it came from, the dataset names itself and the day its copy was obtained,
	// while the line a score was measured against arrives anonymous, and the answer to "who decided
	// 0.5" decides whether a band is a policy or an accident. It is also the value most worth
	// governing: a threshold reachable by the team being gated is a gate that can be loosened without
	// a record.
	ThresholdFrom string `json:"thresholdFrom,omitempty"`
}

// Provenance is one scanner's account of a run it performed.
//
// A slice on Report rather than a map of fields, because a control can be served by more than one
// scanner and each has its own answer, two scanners auditing a cluster apply two different
// benchmarks. Flattening them into one map keeps whichever was written last, silently, which is
// the failure this type exists to prevent.
type Provenance struct {
	// Tool is the scanner that produced this account.
	Tool string `json:"tool"`
	// Version is the scanner's version as the engine resolved it. The same value that goes into its
	// cache key, so the evidence and the cache cannot disagree about what ran. Empty when the scanner
	// does not report one.
	Version string `json:"version,omitempty"`
	// Fields are the scanner's own statements about the run, in the order it considers useful.
	//
	// Untyped, because the interesting ones are domain knowledge, "benchmark", "coverage", "scope".
	// And this package is the finding currency for every scanner Draugr will ever have. It should not
	// learn what a CIS benchmark is to carry the fact that one was applied.
	Fields []Field `json:"fields,omitempty"`
	// Component is the component whose target this account describes, where it describes one
	// target rather than the tool. Set by the engine on an entry that states coverage, which is
	// true of the tree one job read: a statement that one component's tree holds no Go module says
	// nothing about another's. Empty for what is true of the tool wherever it ran, its version or
	// its database.
	Component string `json:"component,omitempty"`
	// Detail is what the scanner recorded per item, for a consumer rather than for a terminal.
	//
	// Describe() joins Fields onto one line, and the block that reads it gives a control three of
	// them. So a field whose count grows with the descriptor crowds out the summary and is then
	// elided itself, which is an account reporting less than it holds at exactly the sizes where
	// it matters. Anything per-image, per-package or per-file belongs here: the machine formats
	// carry all of it and the console carries none of it.
	Detail []Field `json:"detail,omitempty"`
}

// Field is one statement in a Provenance entry.
//
// A slice of pairs rather than a map: rendering needs a stable order, and alphabetical is the
// wrong one. It puts "coverage" before "benchmark". The scanner knows which matters most to a
// reader, so it decides.
type Field struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// Describe returns the fields as "key: value" pairs, for a reporter with one line to spend.
//
// Punctuated, because a value is not always a phrase. "benchmark CIS 1.9" reads whichever way it is
// written, and "coverage this repository has no go.mod, so its findings carry no verdict" reads as
// a sentence that starts with a word left over from somewhere else. The colon is what says the
// first word names the rest rather than beginning it.
func (p Provenance) Describe() string {
	parts := make([]string, 0, len(p.Fields))
	for _, f := range p.Fields {
		if f.Key == "" {
			parts = append(parts, f.Value)
			continue
		}
		parts = append(parts, f.Key+": "+f.Value)
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
	// Taxa are the shared classifications this rule implements, a CIS benchmark control, a CWE. Empty
	// when the scanner claims none.
	//
	// This is what makes two tools' findings recognizable as being about the same thing, and it is
	// deliberately not the rule id. An id belongs to whoever emitted it: `draugr/cis/5.1.1` and
	// `kube-bench/cis/5.1.1` are two tools' accounts, and collapsing them into one id. As they were.
	// Makes provenance unrecoverable. A taxon is the vocabulary both are speaking, so the
	// correspondence is stated rather than inferred from a string collision.
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

// ruleTaxonomySuffix ends the taxonomy of a taxon naming another tool's rule (see SameCheckAs).
const ruleTaxonomySuffix = " rules"

// SameCheckAs is the taxon a rule carries to say it checks the same setting as another tool's rule:
// taxonomy "Trivy rules", id "KSV-0017". tool is the name that tool's findings carry as their Tool.
//
// Two tools checking one setting write ids that share nothing, so nothing but a statement can say
// they are one check. The scanner whose rule makes the statement is the one that has read both
// rule sets; the other tool's findings are left as they are.
func SameCheckAs(tool, ruleID, name string) Taxon {
	return Taxon{Taxonomy: tool + ruleTaxonomySuffix, ID: ruleID, Name: name}
}

// SameCheck reports the tool and rule a SameCheckAs taxon names, and false for any other taxon.
func (t Taxon) SameCheck() (tool, ruleID string, ok bool) {
	tool, ok = strings.CutSuffix(t.Taxonomy, ruleTaxonomySuffix)
	if !ok || tool == "" || t.ID == "" {
		return "", "", false
	}
	return tool, t.ID, true
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

// HelpURI returns where a reader can look up ruleID: what the scanner published, or a URL derived
// from a well-known identifier scheme when it published nothing. Empty when we can't say. A wrong
// link is worse than none.
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
		// Suppressed findings are reported but not judged. Missing this is how a Saga exclusion appears
		// to work, the count drops to zero. While the gate still fails on the finding it was supposed to
		// set aside.
		if res.Suppressed() {
			continue
		}
		if res.Level.Rank() > highest.Rank() {
			highest = res.Level
		}
	}
	return highest
}

// HighestSeverity returns the most severe ranked severity present, or an empty severity when there
// are no results to judge.
//
// This is what a severity gate compares, and it is deliberately the same number the report prints
// beside the band: each finding's RankedSeverity, after the control's minimum severity and every
// signal. Two ladders sit underneath it and neither is the gate's. The SARIF level is the wire
// value, and a scanner that reports a 7.8 as `warning` still shows as `high`. The scanner's own
// rating is the input to ranking rather than its outcome: a `high` on KEV is printed `critical`, and
// an unreachable `critical` is printed `high`. Judging either lets a gate and the report it ends
// disagree about the same finding.
func (r Report) HighestSeverity() Severity {
	highest := Severity("")
	for _, res := range r.Results {
		// Suppressed findings are reported but not judged, exactly as in Highest.
		if res.Suppressed() {
			continue
		}
		if sev := res.RankedSeverity(); sev.Rank() > highest.Rank() {
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
		out.addConsulted(rep.Consulted)
		out.UnsettledChecks = append(out.UnsettledChecks, rep.UnsettledChecks...)
		out.addInputs(rep.Inputs)
		out.addInventory(rep.Inventory)
		out.addPackageVerdicts(rep.PackageVerdicts)
		out.addUnchecked(rep.Unchecked)
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
// account and both belong in the evidence. Deduplicated so that merging a report with itself.
// Which aggregation does. Does not double every entry.
func (r *Report) addProvenance(entries []Provenance) {
	for _, p := range entries {
		if len(p.Fields) == 0 && p.Version == "" {
			continue // nothing said
		}
		if slices.ContainsFunc(r.Provenance, func(existing Provenance) bool {
			return existing.Tool == p.Tool && existing.Version == p.Version &&
				existing.Component == p.Component && slices.Equal(existing.Fields, p.Fields)
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

// addConsulted appends datasets that are not already present, keyed by signal.
//
// One entry per signal, because a run loads each dataset once and two entries naming "kev" would
// have to be reconciled by whoever reads them. Which is the failure addProvenance's per-tool slice
// exists to avoid, and it does not apply here.
func (r *Report) addConsulted(feeds []Consulted) {
	for _, f := range feeds {
		if f.Signal == "" {
			continue
		}
		if slices.ContainsFunc(r.Consulted, func(existing Consulted) bool {
			return existing.Signal == f.Signal
		}) {
			continue
		}
		r.Consulted = append(r.Consulted, f)
	}
}

// addInputs appends inputs that are not already present.
//
// Keyed on everything but the count: the same file read by one scanner for one component is one
// statement, and merging a report with itself must not double it.
func (r *Report) addInputs(inputs []Input) {
	for _, in := range inputs {
		if slices.ContainsFunc(r.Inputs, func(existing Input) bool {
			return existing.Scanner == in.Scanner && existing.Repository == in.Repository &&
				existing.Component == in.Component && existing.Path == in.Path
		}) {
			continue
		}
		r.Inputs = append(r.Inputs, in)
	}
}

// addInventory appends packages that are not already present. The same package listed by one
// scanner, in one file, for one component is one entry, so merging a report with itself does not
// double it.
func (r *Report) addInventory(pkgs []InventoryPackage) {
	if len(pkgs) == 0 {
		return
	}
	seen := make(map[InventoryPackage]bool, len(r.Inventory)+len(pkgs))
	for _, p := range r.Inventory {
		seen[p] = true
	}
	for _, p := range pkgs {
		if seen[p] {
			continue
		}
		seen[p] = true
		r.Inventory = append(r.Inventory, p)
	}
}

// addPackageVerdicts appends verdicts that are not already present. One analyzer's verdict about one
// package, in one file, for one component is one statement, so merging a report with itself does not
// double it.
func (r *Report) addPackageVerdicts(verdicts []PackageVerdict) {
	for _, v := range verdicts {
		if slices.ContainsFunc(r.PackageVerdicts, func(existing PackageVerdict) bool {
			return existing.Repository == v.Repository && existing.Component == v.Component &&
				existing.Path == v.Path && existing.Package == v.Package &&
				existing.Reachability.Analyzer == v.Reachability.Analyzer
		}) {
			continue
		}
		r.PackageVerdicts = append(r.PackageVerdicts, v)
	}
}

// addUnchecked appends unchecked checks that are not already present, keyed as addInputs keys.
func (r *Report) addUnchecked(unchecked []Unchecked) {
	for _, u := range unchecked {
		if slices.ContainsFunc(r.Unchecked, func(existing Unchecked) bool {
			return existing.Scanner == u.Scanner && existing.Component == u.Component && existing.Check == u.Check
		}) {
			continue
		}
		r.Unchecked = append(r.Unchecked, u)
	}
}

// ParseLevel converts a user-supplied gate level, rejecting anything it does not recognize.
//
// Rejecting matters more than it looks. An unknown level ranks 0, and every finding is at least 0,
// so a typo, or a plausible-sounding value like "high", silently turns a gate into "fail on
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
// of the longer, so a CI variable saying `org/repo` still matches a descriptor's clone URL.
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
// Both spellings put a colon after the host, `host:8443/org/repo` separates a port and
// `host:org/repo` separates the path. And only the port is all digits. Without the distinction a
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
// this package should not grow a field per domain fact. Parsed back out here so every consumer,
// console, markdown, HTML, JSON. Reads it the same way instead of each learning the key names.
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
	// A scanner that recorded no repository is describing something else, a cluster, a benchmark. And
	// belongs in the per-control provenance rather than here.
	return r, r.URL != ""
}

// RepositoriesIn collects the distinct repository/revision pairs the reports recorded.
//
// Keyed on the pair rather than the scanner: five controls reading one commit is one fact. When
// two controls disagree, both are kept, each repository scanner checks out independently, so on a
// branch that moves mid-scan they can genuinely read different commits, and collapsing that would
// be an assumption presented as evidence.
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
	// Sorted, because the order they were encountered in is the order the jobs finished in. Two
	// scans of one descriptor printed their repositories in different orders, which makes the same
	// run look like a different one to anything comparing two reports as text, and makes a reader
	// checking a report against yesterday's read a difference that is not there.
	slices.SortFunc(out, func(a, b RepositoryRef) int {
		if a.URL != b.URL {
			return strings.Compare(a.URL, b.URL)
		}
		return strings.Compare(a.Revision, b.Revision)
	})
	return out
}

// Methods an analyzer may report, strongest evidence first.
//
// Four things are sold as reachability and they are not the same claim. The difference is entirely
// about the negative: saying a flaw is reachable is a positive claim somebody can go and check,
// and saying it is unreachable is an absence claim worth exactly what the analysis cannot see.
const (
	// MethodCallGraph followed calls from an entry point to the vulnerable symbol. Bounded by what
	// the language lets a static analysis see, which every such tool publishes and none of which
	// is nothing.
	MethodCallGraph = "call-graph"
	// MethodDataFlow followed the data as well as the calls, so it can find a path unreachable
	// where a call graph finds one.
	MethodDataFlow = "data-flow"
	// MethodFrameworkHeuristic read a framework's own conventions about which handlers are wired.
	// A statement about configuration rather than about code, and a guess where the two disagree.
	MethodFrameworkHeuristic = "framework-heuristic"
	// MethodImportCheck saw whether the vulnerable package is referenced anywhere in the tree,
	// which is presence with extra steps.
	MethodImportCheck = "import-check"
	// MethodNotBuilt read the build itself, and goes with ReachabilityNotBuilt: the package is
	// declared in the dependency file and is in none of the packages the analyzer compiled. Bounded by
	// which build was read, which Build names: code compiled only for another platform, or only under
	// another build tag, is outside it. Not a proof of absence, because the builds read may not be
	// every build that ships.
	MethodNotBuilt = "not-built"
)

// ProvesAbsence reports whether a method's unreachable verdict is strong enough to lower a band.
//
// The one place this is decided. A call graph that finds no path has looked for one; a framework
// heuristic that finds no route has read a configuration file. Only the first is evidence that the
// vulnerable code does not run, and a band lowered by the second is a finding somebody stops
// looking at on the strength of a guess.
//
// An unrecognized or absent method is not strong. That is the conservative direction and the right
// default for a field an analyzer wrote: a tool that will not say how it decided has not earned a
// de-escalation, and one added later gets the strict reading until somebody classifies it here.
func ProvesAbsence(method string) bool {
	switch method {
	case MethodCallGraph, MethodDataFlow:
		return true
	default:
		return false
	}
}

// RankAt returns the severity a finding's priority band should be computed from, given what
// reachability analysis concluded.
//
// Only an unreachable verdict moves anything, and only from a method that proves absence.
// Reachable does not raise: severity already assumes the vulnerable code runs, so treating a
// confirmed call as an escalation would count the same assumption twice. Unknown moves nothing by
// definition. It is the absence of a finding, not one.
//
// A weak method's unreachable verdict still travels and is still shown. What it does not do is
// lower the band, because the reader deciding whether to act on it needs to make that call
// themselves rather than have it made by a guess.
func (r *Reachability) RankAt(base Severity) Severity {
	if r == nil || r.State != ReachabilityUnreachable || !ProvesAbsence(r.Method) {
		return base
	}
	return base.Deescalate()
}

// vulnerabilityID matches a vulnerability identifier at the start of a rule id, allowing whatever
// a scanner appends to it.
//
// Anchored at the front and not at the back, deliberately. Grype reports `CVE-2019-1010083-flask`,
// the identifier plus the package it found it in. Because one advisory can affect several packages
// in one scan, and collapsing those would merge two real findings into one. So the decoration
// stays on the rule id, which is what the scanner said, and everything that needs to know *which
// vulnerability this is* asks here instead of matching the string.
//
// Trivy reports an advisory under its own identifier where the advisory has no CVE: the Node
// Security Working Group's `NSWG-ECO-408` for an npm package, the Debian security tracker's
// `TEMP-0628843-DBAD28` and a Debian LTS advisory's `DLA-4867-1` for an operating-system package. A
// scheme missing here is not a vulnerability to anything that asks, so its findings go uncorrelated,
// unmatched by VEX and absent from the VEX document.
//
// OSV-Scanner names a finding by the first id of the advisories it grouped, which for a Python
// package is usually the PyPA advisory database's `PYSEC-2024-60`, with the CVE and the GitHub
// advisory among its aliases. Without the scheme here such a finding has no vulnerability, and so
// never meets Trivy's copy of the same flaw under its CVE.
//
// The retire.js scanner does the same for an advisory with neither a CVE nor a GitHub advisory id:
// `retirejs:<component>:<id>`, the component as retire.js's advisory repository names it (`jquery`,
// `DOMPurify`, `@angular/core`) and the advisory's own number, its issue or bug number, a vendor
// advisory id such as `SNYK-JS-ALASQL-1082932`, or, where it has none of those, `below-` and the
// version that fixes it.
var vulnerabilityID = regexp.MustCompile(
	`^(CVE-\d{4}-\d{4,}` +
		`|GHSA-[2-9cfghjmpqrvwx]{4}-[2-9cfghjmpqrvwx]{4}-[2-9cfghjmpqrvwx]{4}` +
		`|OSV-\d{4}-\d+` +
		`|RUSTSEC-\d{4}-\d{4}` +
		`|PYSEC-\d{4}-\d+` +
		`|GO-\d{4}-\d{4,}` +
		`|NSWG-ECO-\d+` +
		`|TEMP-\d{7}-[0-9A-F]{6}` +
		`|DLA-\d+-\d+` +
		`|retirejs:[@A-Za-z0-9][@/\w.-]*:(?:\d+|[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+|below-\d[\w.+-]*))`)

// VulnerabilityID is the vulnerability this finding is about, or "" when it is not about one.
//
// A rule id belongs to whoever emitted it, and two scanners reporting the same advisory do not
// spell it the same way. Anything asking "which vulnerability is this", matching a supplier's VEX
// statement, writing one, recognizing the same flaw found twice. Has to ask that question rather
// than compare rule ids, or it silently answers for one scanner and not the other.
//
// Empty for a finding that is not a vulnerability at all. A leaked credential and a misconfigured
// security group are real findings with no advisory to be un-affected by.
func (r Result) VulnerabilityID() string {
	return vulnerabilityID.FindString(r.RuleID)
}

// AliasVulnerabilityIDs are the vulnerabilities among the finding's Aliases, each once, leaving out
// VulnerabilityID and anything that names no recognized vulnerability.
func (r Result) AliasVulnerabilityIDs() []string {
	own := r.VulnerabilityID()
	var ids []string
	for _, a := range r.Aliases {
		id := vulnerabilityID.FindString(a)
		if id == "" || id == own || slices.Contains(ids, id) {
			continue
		}
		ids = append(ids, id)
	}
	return ids
}

// AgreementNote is the line under a finding saying which other scanners found it, and where they
// disagree about how bad it is.
//
// Said rather than hidden, because two tools agreeing is itself a signal, and because a reader who
// enabled a second scanner should be able to see it working, without this the row looks exactly
// like a run with one scanner and the second appears to have found nothing.
//
// Here rather than beside one renderer because the scan report and the diff both draw it, and a
// reader who has learned the line in a terminal meets the same words in a pull-request comment.
//
// A rating is shown only when it differs from the one being counted. Where the scanners agree,
// repeating the same numbers on every row is noise a reader has to look past; where they disagree,
// it is the one thing this line is carrying that they could not get anywhere else. The full record
// is in the JSON and the SARIF either way.
//
// Each other scanner is named once, however many files it found the flaw in, and never own, the
// scanner of the counted finding: a copy from that scanner differs only in its file, which is not a
// second opinion. A scanner rating the flaw differently in any copy is shown with that rating.
func AgreementNote(others []Observation, counted Severity, own string) string {
	parts := make([]string, 0, len(others))
	at := map[string]int{}
	for _, o := range others {
		if o.Tool == own {
			continue
		}
		differs := o.Severity != "" && o.Severity != counted
		i, seen := at[o.Tool]
		if !seen {
			at[o.Tool] = len(parts)
			parts = append(parts, o.Tool)
			i = len(parts) - 1
		}
		if differs && parts[i] == o.Tool {
			parts[i] = fmt.Sprintf("%s (%s)", o.Tool, ratingOf(o))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return "also found by " + strings.Join(parts, ", ")
}

// OtherFiles counts the files the copies are in other than location, the counted copy's.
func OtherFiles(others []Observation, location string) int {
	seen := map[string]bool{}
	for _, o := range others {
		if o.Location != "" && o.Location != location {
			seen[o.Location] = true
		}
	}
	return len(seen)
}

// ratingOf renders one scanner's rating, with its score where it gave one.
func ratingOf(o Observation) string {
	if o.Score > 0 {
		return fmt.Sprintf("%s %s", o.Severity, strconv.FormatFloat(o.Score, 'f', -1, 64))
	}
	return string(o.Severity)
}
