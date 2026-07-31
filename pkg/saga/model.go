package saga

import (
	"path"
	"slices"
	"strings"
)

// Model is a parsed Saga descriptor — the declarative account of an application's
// security surface plus the controller configuration that drives a scan.
type Model struct {
	Release               Release      `yaml:"release"`
	Config                Config       `yaml:"config,omitempty"`
	Components            []Component  `yaml:"components,omitempty"`
	ComponentsMetaSources []MetaSource `yaml:"componentsMetaSources,omitempty"`
	References            []Reference  `yaml:"references,omitempty"`
}

// Release identifies what is being assessed.
type Release struct {
	Name    string `yaml:"name"`
	Version string `yaml:"version"`
	Stage   string `yaml:"stage,omitempty"`
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
	// SBOM turns on Software Bill of Materials generation for this project's repositories and
	// images. It is evidence rather than a control: an SBOM is an inventory, it finds nothing,
	// and it never affects the verdict.
	SBOM *SBOMConfig `yaml:"sbom,omitempty"`
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
	// only. Values are SARIF levels: error, warning, note.
	//
	// This exists because one threshold cannot serve every control. Licence policy is owned by
	// legal and vulnerability policy by security; "fail the build on a forbidden licence but
	// only warn on a medium CVE" is a reasonable position that a single global threshold makes
	// unsayable.
	Controls map[string]string `yaml:"controls,omitempty"`
}

// GateLevels lists the severity thresholds a gate may be set to, most to least severe.
var GateLevels = []string{"error", "warning", "note"}

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
	// wildcard that stopped at `/` could not express "this licence, any package". A pattern
	// with no `*` matches exactly. There is no escape for a literal `*`; no scanner emits one.
	Rules []string `yaml:"rules,omitempty"`
	// Reason is why this exclusion exists. Required.
	Reason string `yaml:"reason"`
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

// SBOMConfig turns on SBOM generation and chooses the document format.
type SBOMConfig struct {
	// Enabled generates one SBOM per distinct repository and image in the project.
	Enabled bool `yaml:"enabled"`
	// Format is the document format. Empty means SBOMSPDXJSON.
	Format SBOMFormat `yaml:"format,omitempty"`
}

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
	// SBOMSPDXJSON is the default: SPDX in JSON, the ISO standard (ISO/IEC 5962), and what
	// Draugr's own releases publish.
	SBOMSPDXJSON SBOMFormat = "spdx-json"
	// SBOMSPDXTagValue is SPDX in its original tag-value encoding, still required by some
	// compliance tooling.
	SBOMSPDXTagValue SBOMFormat = "spdx-tag-value"
	// SBOMCycloneDXJSON is the OWASP format in JSON, common in security tooling.
	SBOMCycloneDXJSON SBOMFormat = "cyclonedx-json"
	// SBOMCycloneDXXML is CycloneDX in XML, which some enterprise tooling still expects.
	SBOMCycloneDXXML SBOMFormat = "cyclonedx-xml"
)

// SBOMFormats lists the valid SBOM document formats.
var SBOMFormats = []SBOMFormat{SBOMSPDXJSON, SBOMSPDXTagValue, SBOMCycloneDXJSON, SBOMCycloneDXXML}

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
}

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

	// github-pr-comment: posts the markdown report as a sticky pull-request comment. PR defaults
	// to the number parsed from $GITHUB_REF (refs/pull/<n>/merge); Marker identifies the sticky
	// comment to update (default a Draugr marker).
	PR     int    `yaml:"pr,omitempty"`
	Marker string `yaml:"marker,omitempty"`
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

// Repository is a source repository at a revision, optionally scoped to paths.
type Repository struct {
	URL      string   `yaml:"url"`
	Revision string   `yaml:"revision,omitempty"`
	Paths    []string `yaml:"paths,omitempty"`
}

// Image is a container image reference. Digest is the immutable content digest
// ("sha256:…") of the image the tag pointed to; when present it makes result caching
// content-addressed (a rebuilt image under the same tag re-scans). A surveyor can capture
// the running digest, or you can pin it by hand for reproducible caches.
type Image struct {
	Image  string `yaml:"image"`
	Digest string `yaml:"digest,omitempty"`
}

// Host is a running endpoint. Type is "browser" (browser-facing UI) or "api" (programmatic);
// it tunes which security-header checks apply. Optional; defaults to "browser".
type Host struct {
	Name string `yaml:"name"`
	URL  string `yaml:"url"`
	Type string `yaml:"type,omitempty"`
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
}

// MetaSource points at a Saga fragment kept close to a component's source.
type MetaSource struct {
	RepoURL  string `yaml:"repoUrl"`
	Path     string `yaml:"path"`
	Revision string `yaml:"revision,omitempty"`
}

// Reference links a manual/human security control (e.g. threat model, architecture diagram).
type Reference struct {
	Type string `yaml:"type"`
	Link string `yaml:"link"`
}

// Fragment is a partial Saga contributed by a Surveyor. The engine
// merges fragments into the Model.
type Fragment struct {
	Components []Component `yaml:"components,omitempty"`
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
