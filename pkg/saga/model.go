package saga

import "slices"

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
}

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

// Fragment is a partial Saga contributed by a Surveyor (one of "the Ravens"). The engine
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
