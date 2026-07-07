package saga

// Model is a parsed Saga descriptor — the declarative account of an application's
// security surface plus the controller configuration that drives a scan.
type Model struct {
	Release               Release      `yaml:"release"`
	Config                Config       `yaml:"config,omitempty"`
	Components            []Component  `yaml:"components,omitempty"`
	ComponentsMetaSources []MetaSource `yaml:"componentsMetaSources,omitempty"`
	References            []Reference  `yaml:"references,omitempty"`
	NotApplicable         []NAControl  `yaml:"notApplicable,omitempty"`
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
// infrastructure, plus optional per-component controller overrides.
type Component struct {
	Name           string                        `yaml:"name"`
	Labels         map[string]string             `yaml:"labels,omitempty"`
	Repositories   []Repository                  `yaml:"repositories,omitempty"`
	Images         []Image                       `yaml:"images,omitempty"`
	Hosts          []Host                        `yaml:"hosts,omitempty"`
	Infrastructure []Infrastructure              `yaml:"infrastructure,omitempty"`
	Controllers    map[string]ControllerSettings `yaml:"controllers,omitempty"`
}

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

// Host is a running endpoint. Type is "api" or "web".
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

// NAControl declares a control that is not applicable, with a justification.
type NAControl struct {
	Type   string `yaml:"type"`
	Reason string `yaml:"reason"`
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
