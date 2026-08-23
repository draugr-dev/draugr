package saga

import (
	"bytes"
	"fmt"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/draugr-dev/draugr/pkg/sarif"
	"gopkg.in/yaml.v3"
)

// Model is a parsed Saga descriptor — the declarative account of an application's
// security surface plus the controller configuration that drives a scan.
type Model struct {
	// Project is which project this descriptor describes, and the name a platform files its runs
	// under. Lowercase letters, digits and dashes.
	//
	// It replaces release.name, which named the same thing: the reference called that "what
	// Draugr is qualifying", and in one place a project name. Two fields for one thing meant a
	// platform had to remember an arbitrary string per project and could not tell a renamed
	// project from a misconfigured pipeline.
	Project    string        `yaml:"project,omitempty"`
	Release    Release       `yaml:"release"`
	Config     Config        `yaml:"config,omitempty"`
	Components []Component   `yaml:"components,omitempty"`
	Fragments  []FragmentRef `yaml:"fragments,omitempty"`
	References []Reference   `yaml:"references,omitempty"`
}

// Release identifies what is being assessed.
type Release struct {
	// Name is deprecated and is removed after 2026-08-30: use the top-level `project`.
	//
	// A date rather than "a future release", because a deprecation without one is a warning people
	// read and defer. Accepted until then, warned about on every validate, and gone after.
	Name    string `yaml:"name,omitempty"`
	Version string `yaml:"version"`
}

// ProjectName is which project this descriptor describes.
//
// `project` when it is set, otherwise the deprecated release.name. One accessor rather than the
// fallback written at each call site, because the day release.name goes there is exactly one place
// to change.
func (m *Model) ProjectName() string {
	if m.Project != "" {
		return m.Project
	}
	return m.Release.Name
}

// Deprecations lists what this descriptor uses that is going away, in the words somebody needs to
// fix it.
//
// Returned rather than printed, so the CLI decides where a notice belongs and a library caller is
// not writing to somebody's stdout.
func (m *Model) Deprecations() []string {
	var out []string
	if m.Release.Name != "" {
		const why = "release.name is deprecated and is removed after 2026-08-30. " +
			"Replace it with a top-level %s — it names the project a platform files runs " +
			"under, which is what release.name already meant."
		// The suggestion is there to be pasted, so it carries the whole line. A name with no
		// letters or digits in it slugifies to nothing, and `project: ` is worse than no
		// suggestion at all.
		suggestion := "`project`"
		if slug := slugify(m.Release.Name); slug != "" {
			suggestion = fmt.Sprintf("`project: %s`", slug)
		}
		out = append(out, fmt.Sprintf(why, suggestion))
	}
	return out
}

// slugify offers a project name from a release name, for the suggestion above.
func slugify(s string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(s) {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
			dash = false
		case !dash && b.Len() > 0:
			b.WriteByte('-')
			dash = true
		}
	}
	return strings.TrimRight(b.String(), "-")
}

// Config holds global, per-controller configuration. Each controller's config tree is
// free-form (scanner-specific keys live under it); use ControllerEnabled to read the
// common "enabled" flag.
type Config struct {
	Controllers map[string]ControllerSettings `yaml:"controllers,omitempty"`
	// Reports are the report formats to render on a scan (e.g. json, sarif, markdown, html).
	// Publishers deliver every rendered report to a destination.
	Reports []ReportConfig `yaml:"reports,omitempty"`
	// Publishers are the destinations that rendered reports are delivered to.
	Publishers []PublisherConfig `yaml:"publishers,omitempty"`
	// Gate tunes the pass/fail thresholds. Policy belongs in the descriptor rather than in a
	// flag every pipeline has to remember to pass.
	Gate *GateConfig `yaml:"gate,omitempty"`
	// Exclude suppresses findings that match, with a stated reason. Suppressed findings are
	// still reported — they just stop counting toward the verdict.
	Exclude []ExcludeRule `yaml:"exclude,omitempty"`
	// VEX names the author and product for a generated VEX document (`--report vex`). Optional;
	// without it Draugr falls back to the release, which produces a valid document rather than a
	// publishable one.
	VEX *VEXConfig `yaml:"vex,omitempty"`
	// VEXSources are exploitability claims applied to every component in the project.
	//
	// The project-wide half of `components[].vex`, for the case that is common inside one
	// organization: a platform team publishes one document covering everything they ship, and the
	// twelve projects consuming it should say so once rather than repeat a URL on every component.
	//
	// Scoping is still done by the document. A statement names the package it is about, so a
	// project-wide source excuses a finding only where the identifiers match — listing it here
	// widens which findings are *considered*, not what a given statement is allowed to claim.
	VEXSources []VEXSource `yaml:"vexSources,omitempty"`
	// SBOM turns on Software Bill of Materials generation for this project's repositories and
	// images. It is evidence rather than a control: an SBOM is an inventory, it finds nothing,
	// and it never affects the verdict.
	SBOM *SBOMConfig `yaml:"sbom,omitempty"`
	// Exploitability raises a finding's severity by real-world signals — CISA KEV and FIRST
	// EPSS — before it is ranked, so "what to fix first" reflects what is being exploited
	// rather than only what could be.
	Exploitability *ExploitabilityConfig `yaml:"exploitability,omitempty"`
	// Reachability ranks a dependency finding down when this project's code cannot reach the
	// vulnerable part of it, so "what to fix first" reflects what the code actually calls.
	//
	// Exploitability's mirror image, and here for the same reason: both decide how findings are
	// ranked, and a decision that can move a finding across the gate belongs somewhere a team
	// reviews rather than in a list of tools to run.
	Reachability *ReachabilityConfig `yaml:"reachability,omitempty"`
	// AllowEffects acknowledges scanner effects that would otherwise stop a run — the kinds a
	// scanner declares when it does more to a target than read it ("mutate", "privilege").
	//
	// In the descriptor rather than only a flag, because it is a decision about what may be
	// done to your systems: reviewed in a pull request, and applied identically by every
	// pipeline instead of remembered by whoever wrote the workflow.
	AllowEffects []string `yaml:"allowEffects,omitempty"`
}

// GateConfig tunes which findings fail the build.
type GateConfig struct {
	// Controls sets a per-control severity threshold, overriding --fail-on for that control
	// only. Values are severity bands: critical, high, medium, low.
	//
	// This exists because one threshold cannot serve every control. License policy is owned by
	// legal and vulnerability policy by security; "fail the build on a forbidden license but
	// only warn on a medium CVE" is a reasonable position that a single global threshold makes
	// unsayable.
	Controls map[string]string `yaml:"controls,omitempty"`

	// FailOnPriority also fails the build on any finding at or above a priority band.
	//
	// Severity rates a flaw in the abstract; priority folds in what the descriptor says about the
	// component it was found in. A team that has classified its components usually wants the gate
	// on the second, and until now could only say so with a flag — which every pipeline has to
	// remember, and which nothing reviews.
	//
	// In the descriptor for the same reason as the rest of this block: it is a decision about
	// this application, reviewed in a pull request and applied identically by every runner. A
	// --fail-on-priority flag still overrides it, so a stricter run stays possible without
	// editing the file.
	FailOnPriority string `yaml:"failOnPriority,omitempty"`
}

// GateThresholds lists the severity bands a gate may be set to, most to least severe.
//
// The bands the report prints, so a threshold reads the same as the counts beside it. The SARIF
// levels a gate used to take — error, warning, note — are still accepted and mapped onto the band
// each one means, so a descriptor written against the older vocabulary keeps working.
var GateThresholds = sarif.Severities

// ExcludeRule suppresses findings that match it. Every real repository has paths that are not
// the application — fixtures, examples, generated code — and rules that do not apply to them.
//
// Two properties are deliberate. A reason is **required**, so the why is in the diff where a
// reviewer sees it rather than in someone's memory. And a matched finding is *suppressed*, not
// deleted: it stays in the report marked with its justification, so an exclusion is auditable
// and cannot become a blind spot nobody can see.
type ExcludeRule struct {
	// Paths matches the finding's location. A pattern ending in "/" matches everything beneath
	// that directory; otherwise it is a glob (path.Match) against the whole location, so
	// "*.md" and "test/fixture.go" both work.
	Paths []string `yaml:"paths,omitempty"`
	// Rules matches the finding's rule id. `*` is a wildcard for any run of characters,
	// including separators — a rule id is an opaque string rather than a path, and the ids that
	// most need matching are compound (`license/GPL-3.0-only/github.com/somelib/thing`), so a
	// wildcard that stopped at `/` could not express "this license, any package". A pattern
	// with no `*` matches exactly. There is no escape for a literal `*`; no scanner emits one.
	Rules []string `yaml:"rules,omitempty"`
	// Reason is why this exclusion exists. Required.
	Reason string `yaml:"reason"`
	// AcceptedBy names who decided this finding was acceptable.
	//
	// The question an auditor asks of a suppression is not whether the scanner ran — it is who
	// decided, and when. `reason` answers why; without this the who lives in prose if it is
	// recorded at all, and a name buried in a sentence cannot be reported on. Optional, and a
	// suppression without one is reported as unattributed rather than rejected.
	AcceptedBy string `yaml:"acceptedBy,omitempty"`
	// Expires is the date this exclusion stops applying, as YYYY-MM-DD.
	//
	// An exclusion accepted "until the upstream fix lands" has nothing that brings the finding
	// back, so the temporary ones become permanent by default — which is how a suppression
	// mechanism decays into a way of never seeing something again. Past this date the exclusion
	// no longer suppresses and the finding returns, with the report saying it lapsed rather than
	// silently producing a finding that used to be accepted.
	Expires string `yaml:"expires,omitempty"`
	// VEX states what this suppression means as a machine-readable claim about the product,
	// for `--report vex`. Optional: without it the finding is reported as `affected`, which is
	// the claim that is never an overstatement.
	VEX *VEXDecision `yaml:"vex,omitempty"`
	// Source is the file this rule was read from, set by the loader rather than by the
	// descriptor. Splitting exclusions across files is only safe if the report can still say
	// which file authorized each one, so the provenance travels with the rule.
	Source string `yaml:"-"`
}

// expiresLayout is the date format Expires uses: a plain calendar date, because an exclusion
// lapses on a day rather than at an instant, and a timezone here would be a decision nobody
// wants to make about a governance record.
const expiresLayout = "2006-01-02"

// ExpiredOn reports whether this exclusion has lapsed as of the given day.
//
// Compared by date rather than by instant: an exclusion set to expire on the 14th applies
// throughout the 14th and stops on the 15th, which is what a reader of the descriptor expects
// from a date with no time on it.
func (e ExcludeRule) ExpiredOn(now time.Time) bool {
	if e.Expires == "" {
		return false
	}
	d, err := time.Parse(expiresLayout, e.Expires)
	if err != nil {
		return false // Validate rejects an unparseable date; never silently drop the suppression
	}
	return now.Truncate(24 * time.Hour).After(d)
}

// Matches reports whether a finding at uri with rule id ruleID falls under this exclusion.
//
// When both selectors are set they must both match. That is the narrow reading — "this rule, in
// this place" — and it is the safe one: the alternative would silently widen "ignore the test
// fixture's fake key" into "ignore that rule everywhere".
func (e ExcludeRule) Matches(uri, ruleID string) bool {
	if len(e.Paths) == 0 && len(e.Rules) == 0 {
		return false // an empty rule would suppress everything; Validate rejects it too
	}
	if len(e.Paths) > 0 && !matchesAnyPath(e.Paths, uri) {
		return false
	}
	if len(e.Rules) > 0 && !matchesAnyRule(e.Rules, ruleID) {
		return false
	}
	return true
}

// matchesAnyRule reports whether ruleID is covered by any of the patterns, treating `*` as any
// run of characters. Deliberately not path.Match, which is right for the Paths field — those
// really are paths — but wrong here: package names contain slashes, so segment-wise globbing
// could not express the common case.
func matchesAnyRule(patterns []string, ruleID string) bool {
	for _, p := range patterns {
		if wildcardMatch(p, ruleID) {
			return true
		}
	}
	return false
}

// wildcardMatch reports whether s matches pattern, where `*` matches any run of characters.
// Written out rather than compiled to a regexp: the patterns come from a Saga, and a regexp
// built from user input is a denial-of-service waiting to be discovered.
func wildcardMatch(pattern, s string) bool {
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == s // no wildcard: exact match
	}
	// The first and last segments are anchored; everything between may float.
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]
	last := parts[len(parts)-1]
	for _, mid := range parts[1 : len(parts)-1] {
		i := strings.Index(s, mid)
		if i < 0 {
			return false
		}
		s = s[i+len(mid):]
	}
	return strings.HasSuffix(s, last) && len(s) >= len(last)
}

// matchesAnyPath reports whether uri is covered by any of the patterns.
func matchesAnyPath(patterns []string, uri string) bool {
	if uri == "" {
		return false // nothing to match against; excluding it would be a guess
	}
	for _, p := range patterns {
		if strings.HasSuffix(p, "/") {
			if strings.HasPrefix(uri, p) {
				return true
			}
			continue
		}
		if p == uri {
			return true
		}
		if ok, err := path.Match(p, uri); err == nil && ok {
			return true
		}
	}
	return false
}

// ExploitabilityConfig turns on severity enrichment from real-world exploitability signals and
// says where the data comes from.
//
// In the descriptor rather than only in flags because it is a decision about how findings are
// ranked, and a team that agrees to use KEV needs somewhere to write that down where it gets
// reviewed — not a flag every pipeline has to remember to pass.
type ExploitabilityConfig struct {
	// KEV and EPSS each name a source: a file path, "cache" to read what `draugr feeds update`
	// left without touching the network, or "auto" to fetch when the cache is missing or stale.
	// Empty leaves that signal off; either may be used without the other.
	KEV  string `yaml:"kev,omitempty"`
	EPSS string `yaml:"epss,omitempty"`
	// EPSSThreshold is the EPSS probability (0–1) at or above which a finding's severity is
	// raised one band. Zero means the CLI default.
	//
	// A pointer so "not set" and "deliberately zero" stay distinguishable: zero disables the
	// EPSS bump entirely, which is a thing someone might mean.
	EPSSThreshold *float64 `yaml:"epssThreshold,omitempty"`
	// MaxAge is how old a cached feed may be before "auto" refetches it and a scan warns that
	// it is stale. Empty means the built-in default of 24 hours, which tracks EPSS being
	// republished daily.
	//
	// Configurable because a runner deliberately pinned to a known copy of the data has a
	// legitimate reason to say "do not tell me it is old" — reproducing last quarter's verdict
	// requires last quarter's feed.
	MaxAge string `yaml:"maxAge,omitempty"`
}

// ReachabilityConfig turns on reachability analysis and names the analyzers that do it.
//
// Beside ExploitabilityConfig rather than in a control's scanner block, because the two are the
// same kind of decision pointing in opposite directions: one raises a finding's rank on evidence
// that it is being exploited, the other lowers it on evidence that this code cannot reach it.
// Both move findings across a gate, and both should be visible in a diff to whoever owns that
// gate.
//
// It is also the honest surface. Every other entry in a control's scanner block adds findings, so
// enabling one there means "check this too". An analyzer named here adds none — it ranks findings
// already found, downward, which can turn a failing gate green. That is not something to discover
// from the reference docs after the fact.
type ReachabilityConfig struct {
	// Analyzers names the tools that decide reachability, e.g. "govulncheck". An analyzer is
	// named rather than inferred so the descriptor says which tool reached the verdict, and so
	// `draugr doctor` can tell you what to install before a scan finds out for you.
	//
	// Empty leaves reachability off, which is the same as omitting the block.
	Analyzers []string `yaml:"analyzers,omitempty"`
}

// ExploitabilitySources are the values KEV and EPSS accept besides a file path.
const (
	// FeedSourceCache reads the cache and never reaches the network.
	FeedSourceCache = "cache"
	// FeedSourceAuto reads the cache, fetching when it is missing or stale.
	FeedSourceAuto = "auto"
)

// SBOMConfig turns on SBOM generation and chooses the document format.
type SBOMConfig struct {
	// Enabled generates one SBOM per distinct repository and image in the project.
	Enabled bool `yaml:"enabled"`
	// Format is the document format. Empty means SBOMCycloneDXJSON.
	Format SBOMFormat `yaml:"format,omitempty"`
	// Scope is what each document covers: one target, the whole project, or both. Empty means
	// SBOMScopeComponent, which is the behavior a descriptor written before this field had.
	Scope SBOMScope `yaml:"scope,omitempty"`
}

// SBOMScope is what a generated SBOM document covers.
//
// The distinction exists because an SBOM is requested per *product* — a customer questionnaire,
// EO 14028 and the CRA all ask for the bill of materials of the thing you shipped — while Draugr
// scans per repository and image. A project with four repositories and three images produces
// seven documents and no answer to the question being asked.
type SBOMScope string

// The scopes a Saga may ask for.
const (
	// SBOMScopeComponent is the default: one document per distinct repository and image.
	SBOMScopeComponent SBOMScope = "component"
	// SBOMScopeProject is one document covering the whole release, assembled along the hierarchy
	// the Saga already declares.
	SBOMScopeProject SBOMScope = "project"
	// SBOMScopeBoth emits the per-target documents and the assembled one. The parts are the
	// evidence for the whole, and an auditor asking where a package came from wants both.
	SBOMScopeBoth SBOMScope = "both"
)

// SBOMScopes lists the valid scopes.
var SBOMScopes = []SBOMScope{SBOMScopeComponent, SBOMScopeProject, SBOMScopeBoth}

// Valid reports whether s is a known scope. The empty value is not valid here; it means "the
// default" to callers, which resolve it before use.
func (s SBOMScope) Valid() bool { return slices.Contains(SBOMScopes, s) }

// Project reports whether this scope asks for an assembled project document.
func (s SBOMScope) Project() bool { return s == SBOMScopeProject || s == SBOMScopeBoth }

// PerTarget reports whether this scope asks for the per-repository and per-image documents.
func (s SBOMScope) PerTarget() bool { return s != SBOMScopeProject }

// SBOMFormat is the document format for a generated SBOM. Both supported formats are open
// specifications that downstream tooling already reads.
type SBOMFormat string

// The SBOM document formats Draugr can emit: the two open specifications, each in both of its
// standard encodings. Which one you want is decided by whatever consumes the document, so the
// choice is yours rather than ours.
//
// Syft can emit more (its own syft-json, GitHub's dependency-snapshot format, a bare PURL list),
// but those are either vendor-specific or not an SBOM. Keeping this list to the interchange
// formats means every document Draugr produces is one a third party can read.
const (
	// SBOMCycloneDXJSON is the default: the OWASP format in JSON, ECMA-424, and the one that
	// composes — a CycloneDX document can carry nested components and describe how complete it
	// is, which is what a document covering a whole project needs. It is also the format
	// security tooling reads most readily, and the one VEX is expressed in.
	SBOMCycloneDXJSON SBOMFormat = "cyclonedx-json"
	// SBOMCycloneDXXML is CycloneDX in XML, which some enterprise tooling still expects.
	SBOMCycloneDXXML SBOMFormat = "cyclonedx-xml"
	// SBOMSPDXJSON is SPDX in JSON, ISO/IEC 5962, and what a procurement or license-compliance
	// process is most likely to ask for by name.
	SBOMSPDXJSON SBOMFormat = "spdx-json"
	// SBOMSPDXTagValue is SPDX in its original tag-value encoding, still required by some
	// compliance tooling.
	SBOMSPDXTagValue SBOMFormat = "spdx-tag-value"
)

// SBOMFormats lists the valid SBOM document formats.
var SBOMFormats = []SBOMFormat{SBOMCycloneDXJSON, SBOMCycloneDXXML, SBOMSPDXJSON, SBOMSPDXTagValue}

// Valid reports whether f is a known SBOM format. The empty value is not valid here; it means
// "the default" to callers, which resolve it before use.
func (f SBOMFormat) Valid() bool { return slices.Contains(SBOMFormats, f) }

// ControllerSettings is a free-form configuration tree for one controller.
type ControllerSettings map[string]any

// ReportConfig selects one report format to render on a scan. Known formats are validated by
// the reporting layer (pkg/report) when the scan runs, not here — the Saga stays a leaf.
type ReportConfig struct {
	Format string `yaml:"format"`
	// Template and TemplateFile supply the Go text/template for the "template" format (set
	// exactly one). Ignored by other formats.
	Template     string `yaml:"template,omitempty"`
	TemplateFile string `yaml:"templateFile,omitempty"`
	// Filename overrides the artifact's default output filename (used by file-based publishers).
	Filename string `yaml:"filename,omitempty"`
	// MinPriority narrows this report to findings at or above a priority band, leaving every
	// other report complete.
	//
	// Per report, because the reports answer to different readers. A SARIF upload becomes review
	// comments somebody reads on every pull request, where a few hundred findings they did not
	// cause is the reason nobody reads any of them; the JSON beside it is evidence, and evidence
	// is not something to trim.
	//
	// Narrowing an artifact is otherwise refused, and for a good reason: a file that claims to be
	// the scan and is not misleads whatever consumes it. What makes this different is that it is
	// declared — written in the descriptor, and stated inside the artifact it produced. A scope
	// somebody chose and can read back is a scope; an undeclared one is the problem.
	MinPriority string `yaml:"minPriority,omitempty"`
}

// Priorities lists the priority bands a report may be narrowed to, most to least urgent.
//
// Spelled here rather than taken from pkg/prioritization, which imports this package — the
// descriptor is a leaf, and a cycle to share four constants is a poor trade.
var Priorities = []string{"P1", "P2", "P3", "P4"}

// PublisherConfig configures one destination for rendered reports. Kind selects the publisher
// (e.g. "file", "github"); the remaining fields are read by that publisher. Known kinds and
// their required fields are validated by the publishing layer (pkg/publish) when the scan runs.
//
// Secrets are never stored here: the github publisher reads its token from an environment
// variable (TokenEnv, default GITHUB_TOKEN), not from the Saga.
type PublisherConfig struct {
	Kind string `yaml:"kind"`
	Dir  string `yaml:"dir,omitempty"` // file: output directory

	// github / github-pr-comment: Repo defaults to $GITHUB_REPOSITORY; the token to $GITHUB_TOKEN
	// (or TokenEnv). github: Commit/Ref default to $GITHUB_SHA / $GITHUB_REF.
	Repo     string `yaml:"repo,omitempty"`
	Commit   string `yaml:"commit,omitempty"`
	Ref      string `yaml:"ref,omitempty"`
	TokenEnv string `yaml:"tokenEnv,omitempty"` // env var holding the token; default GITHUB_TOKEN

	// github-pr-comment / azure-pr-comment: posts the markdown report as a sticky pull-request
	// comment. PR defaults to the number parsed from $GITHUB_REF (refs/pull/<n>/merge) or
	// $SYSTEM_PULLREQUEST_PULLREQUESTID; Marker identifies the sticky comment to update
	// (default a Draugr marker).
	PR     int    `yaml:"pr,omitempty"`
	Marker string `yaml:"marker,omitempty"`

	// azure-pr-comment: Org is the collection URI (default $SYSTEM_TEAMFOUNDATIONCOLLECTIONURI)
	// and Project the team project (default $SYSTEM_TEAMPROJECT). Repo defaults to
	// $BUILD_REPOSITORY_NAME and the token to $SYSTEM_ACCESSTOKEN (or TokenEnv).
	Org     string `yaml:"org,omitempty"`
	Project string `yaml:"project,omitempty"`

	// draugr-api: URL is where the server is reached, defaulting to $DRAUGR_API_URL. The token
	// comes from $DRAUGR_API_TOKEN (or TokenEnv) and never from this file, which is one people
	// commit.
	URL string `yaml:"url,omitempty"`
	// DefaultURL is what draugr.config.yaml said, carried here so a publisher can consult it
	// last. Never read from a descriptor — `yaml:"-"`, so writing it in a Saga does nothing and
	// the schema does not offer it.
	//
	// A separate field rather than filling URL, because the two sit at opposite ends of the
	// precedence chain: URL is somebody's explicit choice for this project and beats the
	// environment, while this is the organization's default and loses to it. Merging them would
	// make an ambient value indistinguishable from an intentional one.
	DefaultURL string `yaml:"-"`
}

// Component is one logical part of an application: its repositories, images, hosts, and
// infrastructure, plus optional per-component controller overrides and risk classification.
type Component struct {
	Name           string                        `yaml:"name"`
	Labels         map[string]string             `yaml:"labels,omitempty"`
	Exposure       Exposure                      `yaml:"exposure,omitempty"`
	Criticality    Criticality                   `yaml:"criticality,omitempty"`
	Repositories   []Repository                  `yaml:"repositories,omitempty"`
	Images         []Image                       `yaml:"images,omitempty"`
	Hosts          []Host                        `yaml:"hosts,omitempty"`
	Infrastructure []Infrastructure              `yaml:"infrastructure,omitempty"`
	Controllers    map[string]ControllerSettings `yaml:"controllers,omitempty"`
	// VEX are exploitability claims somebody else made about this component, read and applied to
	// its findings.
	//
	// Scoped to the component rather than the descriptor, and that is the whole safety argument:
	// a claim is an assertion by one supplier about one artifact, and a document that could reach
	// another component's findings would turn one vendor's assurance into a suppression somewhere
	// nobody was looking.
	//
	// Note the asymmetry with `config.vex`, which is not a mistake: that describes the document
	// Draugr **writes** about your product, this lists documents Draugr **reads** about a supplier's.
	// A component does not author claims about itself.
	VEX []VEXSource `yaml:"vex,omitempty"`
}

// VEXSource is where one supplier's VEX document comes from.
//
// Exactly one of Path, URL or Repository. Three ways rather than one because a supplier's document
// is somewhere different in every arrangement that actually occurs: committed alongside your
// descriptor, published at a URL, or living in a repository of theirs.
//
// Naming a source is the opt-in. There is no trust setting: a document you pointed at is one you
// accepted, and the report names its author on every finding it excused so the judgement stays
// with the reader rather than being made by a flag.
type VEXSource struct {
	// Path is a document on disk, resolved **relative to where Draugr runs** — not to the
	// descriptor, and not to the repository. That is the same rule every other path in a
	// descriptor follows (see HostSpec.Path), and stating it here is deliberate: a path whose
	// base a reader has to guess is one that works on a laptop and silently misses in CI.
	Path string `yaml:"path,omitempty"`
	// URL is a document to fetch over HTTPS. Fetched once per run and cached; the report records
	// the URL, when it was fetched and the digest of what came back, so a run stays reproducible
	// from its own evidence rather than from the network still agreeing later.
	URL string `yaml:"url,omitempty"`
	// Repository is a document inside a git repository, for a supplier who publishes VEX there
	// rather than at a stable URL.
	Repository *VEXRepository `yaml:"repository,omitempty"`
}

// VEXRepository locates a VEX document inside a git repository.
//
// Cloned with the same machinery as any other repository Draugr reads, which means it
// authenticates the same way: whatever credentials git already has on the machine — an SSH key, a
// credential helper, the header a CI checkout configured. Draugr holds no credentials of its own,
// which is why a private supplier repository works and why no token belongs in this descriptor.
type VEXRepository struct {
	// URL is the repository holding the document.
	URL string `yaml:"url"`
	// Ref is the branch, tag or commit to read. Empty takes the default branch.
	//
	// Worth pinning for a claim you are gating on: a branch moves, and a supplier revising their
	// analysis would change what your gate accepts with nothing in your descriptor having
	// changed. Either way the report records the commit actually read, so the run can be
	// reproduced after the fact even when this was left open.
	Ref string `yaml:"ref,omitempty"`
	// Path is the document's path inside the repository.
	Path string `yaml:"path"`
}

// Exposure is a component's risk-exposure level — how reachable it is to an attacker, and so
// how likely a weakness in it is to be hit. It is one axis of risk prioritization; higher
// exposure ranks a component's findings higher. The levels are a fixed ladder: an
// organization may redefine what each means, but not the count. Exposure may be proposed by
// a surveyor from topology and confirmed by a human. See docs/concepts.md (prioritization).
type Exposure string

// Exposure levels, from most to least exposed.
const (
	ExposurePublic        Exposure = "public"        // internet-facing, no authentication
	ExposureAuthenticated Exposure = "authenticated" // internet-facing, behind authentication
	ExposureInternal      Exposure = "internal"      // reachable within the environment
	ExposureRestricted    Exposure = "restricted"    // namespace- / network-policy-scoped
)

// Criticality is a component's business-criticality level — the operational impact if it
// fails or is compromised. It is the other axis of risk prioritization and is always
// human-declared, as it cannot be inferred from code. The levels are a fixed ladder with
// org-defined meaning. See docs/concepts.md (prioritization).
type Criticality string

// Criticality levels, from most to least critical.
const (
	CriticalityCritical   Criticality = "critical"   // failure causes outage or data loss
	CriticalityImportant  Criticality = "important"  // degraded functionality, no immediate outage
	CriticalitySupporting Criticality = "supporting" // limited operational impact
)

// Exposures lists the valid exposure levels, most to least exposed.
var Exposures = []Exposure{ExposurePublic, ExposureAuthenticated, ExposureInternal, ExposureRestricted}

// Criticalities lists the valid criticality levels, most to least critical.
var Criticalities = []Criticality{CriticalityCritical, CriticalityImportant, CriticalitySupporting}

// Valid reports whether e is a known exposure level. The empty value (unclassified) is not
// valid here; callers decide how to treat unset exposure.
func (e Exposure) Valid() bool { return slices.Contains(Exposures, e) }

// Valid reports whether c is a known criticality level. The empty value (unclassified) is
// not valid here; callers decide how to treat unset criticality.
func (c Criticality) Valid() bool { return slices.Contains(Criticalities, c) }

// Repository is a source repository at a revision, optionally scoped to part of its tree.
type Repository struct {
	URL      string `yaml:"url"`
	Revision string `yaml:"revision,omitempty"`
	// Paths restricts the scan to these directories. Empty scans the whole repository.
	//
	// Files at the repository root are always included regardless: manifests and the scanners'
	// own configuration live there, and a tool that cannot see go.mod or .trivyignore does not
	// fail — it reports less against a tree it did not fully understand, which is
	// indistinguishable from a clean scan.
	Paths []string `yaml:"paths,omitempty"`
	// Ignore removes matching paths from the scan, applied after Paths so it can carve out of
	// one. Gitignore-style: a trailing `/` is a directory, `*` matches within a path segment,
	// `**` across them.
	Ignore []string `yaml:"ignore,omitempty"`
}

// Image is a container image reference. Digest is the immutable content digest
// ("sha256:…") of the image the tag pointed to; when present it makes result caching
// content-addressed (a rebuilt image under the same tag re-scans). A surveyor can capture
// the running digest, or you can pin it by hand for reproducible caches.
type Image struct {
	Image  string `yaml:"image"`
	Digest string `yaml:"digest,omitempty"`
	// BuiltBy says who builds this image: "self" (the default) or "upstream" for one this
	// component runs but somebody else publishes.
	//
	// It decides what the report tells a reader to do about a vulnerable package inside it.
	// Nobody running a scan can upgrade a library inside an image they do not build — the fix is
	// a newer image, or a wait for whoever publishes it. Advice they cannot take, at the top of a
	// list called "fix first", teaches them the list is not worth reading.
	//
	// Declared rather than detected, because nothing in an image says who built it. Defaults to
	// "self" so a descriptor that says nothing keeps describing its own work, which is the common
	// case for a hand-written one — a surveyed cluster is the case that needs saying.
	BuiltBy BuiltBy `yaml:"builtBy,omitempty"`
}

// BuiltBy says who publishes an image.
type BuiltBy string

// Who builds an image.
const (
	// BuiltBySelf is the default: this team builds it, so a package inside it is theirs to
	// upgrade.
	BuiltBySelf BuiltBy = "self"
	// BuiltByUpstream is an image this team runs and somebody else publishes. Upstream rather
	// than "vendor": the publisher is as often an open-source project as a company.
	BuiltByUpstream BuiltBy = "upstream"
)

// Valid reports whether the value is one Draugr defines.
func (b BuiltBy) Valid() bool { return b == BuiltBySelf || b == BuiltByUpstream }

// BuiltByValues are the values builtBy accepts.
var BuiltByValues = []BuiltBy{BuiltBySelf, BuiltByUpstream}

// Host is a running endpoint. Type is "browser" (browser-facing UI) or "api" (programmatic);
// it tunes which security-header checks apply. Optional; defaults to "browser".
type Host struct {
	Name string `yaml:"name"`
	URL  string `yaml:"url"`
	Type string `yaml:"type,omitempty"`
	// Auth authenticates the dynamic scan of this endpoint. Absent means probe it anonymously.
	Auth *HostAuth `yaml:"auth,omitempty"`
	// Spec drives the dynamic scan from an OpenAPI document instead of crawling.
	Spec *HostSpec `yaml:"spec,omitempty"`
}

// HostSpec points the dynamic scan at an OpenAPI document describing this endpoint.
//
// An API usually has no HTML to crawl, so probing it blind reaches whatever a scanner can guess.
// A specification lists every route and method the service declares, which turns guessing into
// exercising what is actually there.
type HostSpec struct {
	// Path is the OpenAPI or Swagger document, resolved like every other path in a
	// descriptor: relative to where Draugr runs, not to the descriptor or the repository.
	Path string `yaml:"path"`
	// Methods are the HTTP methods to exercise. Empty means GET and HEAD.
	//
	// A specification lists POST, PUT and DELETE too, and a scanner handed one will exercise them
	// — a scan of a staging API that deletes its fixtures is a scan nobody runs twice. Naming a
	// write method here is how that is accepted: explicit, per endpoint, and visible in review.
	Methods []string `yaml:"methods,omitempty"`
}

// HostAuth says how to authenticate to an endpoint, by naming the environment variable that holds
// the credential.
//
// There is deliberately no field for the credential itself. A descriptor is committed, so a token
// written into one is a leaked token — and `secrets` would rightly flag it. Making the value
// inexpressible is a stronger guarantee than warning about it.
type HostAuth struct {
	// Type is "bearer" — an `Authorization: Bearer <token>` header — or "header" for a named one.
	Type string `yaml:"type"`
	// Header is the header name, required when Type is "header" (e.g. X-API-Key).
	Header string `yaml:"header,omitempty"`
	// TokenEnv names the environment variable holding the credential.
	TokenEnv string `yaml:"tokenEnv"`
}

// Infrastructure is an infrastructure surface. Kind is e.g. "kubernetes"; Ref names the
// concrete instance.
type Infrastructure struct {
	Kind string `yaml:"kind"`
	Ref  string `yaml:"ref,omitempty"`
	// Namespaces narrows the audit to the namespaces this component owns. Empty means the whole
	// cluster.
	//
	// On a shared cluster the cluster is not the unit anyone owns. Most of what the benchmark's
	// policies section examines is namespace-scoped, so a team owning three namespaces of eighty
	// otherwise receives seventy-seven namespaces' worth of findings it cannot act on — and a
	// number that will never reach zero is a number people stop reading.
	//
	// It also fixes what the component's risk classification means. `exposure` and `criticality`
	// describe a component, so declaring them against a whole shared cluster asserts them on
	// everybody else's workloads too.
	Namespaces []string `yaml:"namespaces,omitempty"`
	// OperatedBy says who runs this surface: "self", or "provider" for a managed service.
	//
	// It states a fact rather than a judgement, and what follows from it — that a finding about
	// the provider's half is not something this team can go and fix — is derived rather than
	// asserted. "managed" was the obvious word and is ambiguous: managed by whom, and a managed
	// service is still yours to pay for.
	//
	// Declared rather than detected, because whether a cluster is managed is a fact about a
	// contract and not something visible in what a scanner reads. The same argument that puts
	// exposure and criticality here.
	//
	// It narrows what it excuses. On a managed cluster the provider runs the control plane, the
	// API server and etcd; RBAC, Pod Security and network policy remain the team's, and those
	// are usually the findings that matter. Marking a whole cluster as somebody else's problem
	// would hide the half that is not.
	OperatedBy OperatedBy `yaml:"operatedBy,omitempty"`
}

// OperatedBy says who runs an infrastructure surface.
type OperatedBy string

// Who operates a surface.
const (
	// OperatedBySelf is the default: this team runs it, so every finding is theirs to act on.
	OperatedBySelf OperatedBy = "self"
	// OperatedByProvider is a managed service, where part of the surface is not reachable by
	// the team that owns the workloads on it.
	OperatedByProvider OperatedBy = "provider"
)

// Valid reports whether the value is one Draugr defines.
func (o OperatedBy) Valid() bool {
	return o == OperatedBySelf || o == OperatedByProvider
}

// OperatedByValues are the values operatedBy accepts.
var OperatedByValues = []OperatedBy{OperatedBySelf, OperatedByProvider}

// FragmentRef names Saga fragments to merge into the descriptor that lists it.
//
// A fragment adds scope or adds attributed suppressions; it can never change policy. That is what
// makes splitting a descriptor safe to review: including a file cannot quietly lower the gate or
// switch a control off, so the worst a `fragments:` entry can do is add findings or add
// suppressions that are individually attributed and counted in the report.
type FragmentRef struct {
	// Path selects the fragment files. Globs are the same dialect as `paths:` and `ignore:` —
	// `*` within a segment, `**` across them — so `**/draugr.saga-fragment.yaml` collects one
	// fragment from every component in a monorepo. Relative to the file that names it, so a
	// fragment keeps working when its directory moves.
	Path string `yaml:"path"`
	// URL is a git repository to read the fragments from. Empty means the local filesystem.
	URL string `yaml:"url,omitempty"`
	// Revision is the branch, tag or commit to read. Required when URL is set, and deliberately
	// not defaulted to the repository's default branch: a fragment that tracks a moving branch is
	// a gate that changes with no commit in your own repository. The revision a run resolved to
	// is recorded in the report, so a tag that moves is visible afterwards.
	Revision string `yaml:"revision,omitempty"`
}

// Remote reports whether this reference reads from another repository.
func (f FragmentRef) Remote() bool { return f.URL != "" }

// String names the reference the way an error should, so a message about one fragment among
// several says which.
func (f FragmentRef) String() string {
	if f.Remote() {
		return fmt.Sprintf("%s@%s %s", f.URL, f.Revision, f.Path)
	}
	return f.Path
}

// Reference links a manual/human security control (e.g. threat model, architecture diagram).
type Reference struct {
	Type string `yaml:"type"`
	Link string `yaml:"link"`
}

// Indent is how many spaces a Saga is written with.
//
// Shared because several commands write the same file — a survey creates it, `classify` sets
// exposure and criticality in place, `validate --resolved` prints it merged — and each one that
// picks its own indent reindents the whole document as a side effect of changing two fields. A
// two-field edit that rewrites sixty lines is a diff nobody can review, and the encoder's default
// is not a decision anyone made.
const Indent = 2

// Fragment is a partial Saga: what a `fragments:` entry loads, and what a Surveyor contributes.
//
// One type for both because the merge is the same. A surveyor that discovers a cluster and a file
// a person wrote are both saying "here is some more of the application", and having two merges
// would mean two answers to what a repeated component name means.
type Fragment struct {
	// Components are merged by name — a repeated name unions the two surfaces rather than
	// replacing or colliding, so a component described in two places ends up whole.
	Components []Component `yaml:"components,omitempty"`
	// Config is the subset of a Saga's config a fragment may carry.
	Config FragmentConfig `yaml:"config,omitempty"`
	// Fragments are further fragments this one pulls in, resolved relative to it.
	Fragments []FragmentRef `yaml:"fragments,omitempty"`
	// ExposureReasons explains, per component name, what topology a proposed `exposure` was read
	// from — "an Ingress routes into it", and so on.
	//
	// Never serialized: it is evidence about a proposal rather than part of the descriptor, and a
	// fragment somebody writes by hand has no use for it. It exists so a survey can put the
	// reasoning beside the value it wrote, where the value gets reviewed.
	ExposureReasons map[string]string `yaml:"-" json:"-"`
}

// FragmentConfig is the part of Config a fragment is allowed to set.
//
// A separate type rather than a validated Config, so the restriction is enforced by the decoder
// and shows up in the published schema — an editor says `gate` is not allowed here, rather than
// the user finding out when a scan behaves unexpectedly.
type FragmentConfig struct {
	// Exclude suppresses findings that match, with a stated reason. Appended to whatever the
	// descriptor and other fragments already carry.
	Exclude []ExcludeRule `yaml:"exclude,omitempty"`
}

// ControllerEnabled reports whether the named controller is enabled at the project level.
// A controller is enabled when its config entry exists and its "enabled" key is not
// explicitly false. Absent entries are considered disabled.
func (c Config) ControllerEnabled(name string) bool {
	settings, ok := c.Controllers[name]
	if !ok {
		return false
	}
	return settingsEnabled(settings)
}

// ControllerEnabled reports whether the named controller is enabled for this component,
// falling back to the project-level setting when the component has no override.
func (comp Component) ControllerEnabled(name string, project Config) bool {
	if settings, ok := comp.Controllers[name]; ok {
		return settingsEnabled(settings)
	}
	return project.ControllerEnabled(name)
}

// settingsEnabled reads the "enabled" flag, defaulting to true when the entry exists but
// omits the flag.
func settingsEnabled(settings ControllerSettings) bool {
	v, ok := settings["enabled"]
	if !ok {
		return true
	}
	enabled, ok := v.(bool)
	return ok && enabled
}

// Marshal renders a descriptor as YAML, at the indentation Draugr writes.
//
// Here rather than beside any one caller, because the indent is the whole point and every writer
// has to agree on it. yaml.Marshal's default is four spaces, which is not a choice anybody made —
// and a file written with it is reindented end to end the first time something else edits a field
// in it, turning a one-line change into a whole-file diff nobody can review.
func Marshal(doc any) ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(Indent)
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
