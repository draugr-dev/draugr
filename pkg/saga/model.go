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
}

// ControllerSettings is a free-form configuration tree for one controller.
type ControllerSettings map[string]any

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
// a surveyor from topology and confirmed by a human. See planning/risk-prioritization.md.
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
// org-defined meaning. See planning/risk-prioritization.md.
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

// Image is a container image reference.
type Image struct {
	Image string `yaml:"image"`
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
