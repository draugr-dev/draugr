package sealed

// Expected is a scenario's expected.yaml: what `draugr init` proposes for the repository and what
// a sealed scan of it reports.
type Expected struct {
	// Init is what `draugr init` writes for the repository.
	Init InitExpectation `yaml:"init"`
	// Secrets are credentials the harness writes into the repository before it is committed.
	// Each must be reported by the secrets control.
	Secrets []SecretExpectation `yaml:"secrets"`
	// Findings are every other result the scan must report, and together with the secrets and the
	// fixture's inline sast annotations, every result it may report.
	Findings []FindingExpectation `yaml:"findings"`
}

// InitExpectation is the descriptor `draugr init` writes.
type InitExpectation struct {
	// Controls are the controls it enables, in any order.
	Controls []string `yaml:"controls"`
	// Components are the components it declares.
	Components []ComponentExpectation `yaml:"components"`
}

// ComponentExpectation is one component `draugr init` declares.
type ComponentExpectation struct {
	Name string `yaml:"name"`
	// Repositories are the repository urls, relative to the descriptor.
	Repositories []string `yaml:"repositories"`
}

// SecretExpectation is one generated credential.
type SecretExpectation struct {
	// File is where the harness writes it, relative to the repository. It is written on line 1.
	File string `yaml:"file"`
	// Rules are the rules that must report it.
	Rules []string `yaml:"rules"`
}

// FindingExpectation is one result a scan must report.
type FindingExpectation struct {
	Control string `yaml:"control"`
	// Tool is the scanner that reported it, as the SARIF names it.
	Tool string `yaml:"tool"`
	Rule string `yaml:"rule"`
	// Location is file:line relative to the repository, or the file alone for a result about a
	// whole file.
	Location string `yaml:"location"`
	// Package is "ecosystem name version", for a finding about a dependency.
	Package string `yaml:"package,omitempty"`
	// Reachability is the verdict reachability analysis reached, where it ran.
	Reachability string `yaml:"reachability,omitempty"`
}
