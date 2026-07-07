package saga

// This is a v0 placeholder sufficient for the plugin contract. The full descriptor
// schema (repositories, images, hosts, infrastructure, controller config, meta-sources,
// validation, env substitution) lands with the Saga schema work.

// Model is a parsed Saga descriptor.
type Model struct {
	Release    Release
	Components []Component
}

// Release identifies what is being assessed.
type Release struct {
	Name    string
	Version string
}

// Component is one logical part of an application (its repos, images, hosts, infra).
type Component struct {
	Name string
}

// Fragment is a partial Saga contributed by a Surveyor (one of "the Ravens"). The engine
// merges fragments into the Model.
type Fragment struct {
	Components []Component
}
