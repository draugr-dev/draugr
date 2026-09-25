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
	// Sealed changes what the container provides, for a scenario about a failure.
	Sealed RunOptions `yaml:"sealed"`
	// Errors are the controls that must fail to run, each with text its error must contain. Every
	// other control must run.
	Errors []ErrorExpectation `yaml:"errors"`
}

// RunOptions take something away from a sealed run, so a scenario can assert that its absence
// is reported rather than passed.
type RunOptions struct {
	// WithoutTool is a program removed from PATH inside the container.
	WithoutTool string `yaml:"withoutTool"`
	// FailingTool is a program replaced by one that writes FailingToolMessage and exits 2.
	FailingTool string `yaml:"failingTool"`
	// WithoutTrivyDB leaves Trivy's vulnerability database unwritten.
	WithoutTrivyDB bool `yaml:"withoutTrivyDB"`
	// GoVulnDBAge is how long before the run the local Go vulnerability database is recorded as
	// fetched, as a Go duration. Empty means at the start of the run.
	GoVulnDBAge string `yaml:"goVulnDBAge"`
}

// ErrorExpectation is one control that must fail to run.
type ErrorExpectation struct {
	Control string `yaml:"control"`
	// Contains is text the control's error must include.
	Contains string `yaml:"contains"`
}

// InitExpectation is the descriptor `draugr init` writes.
type InitExpectation struct {
	// Controls are the controls it enables, in any order.
	Controls []string `yaml:"controls"`
	// Scanners are the scanners it enables inside a control beyond the control's default, as
	// control.scanner (sast.gosec, sca.retirejs), in any order. Empty means none.
	Scanners []string `yaml:"scanners"`
	// Reachability are the reachability analyzers it turns on. Empty means none.
	Reachability []string `yaml:"reachability"`
	// Components are the components it declares.
	Components []ComponentExpectation `yaml:"components"`
	// PerDirectory is what `draugr init --per-directory` writes, for a scenario whose tree has
	// directories with their own dependency files. Unset skips that run.
	PerDirectory *InitExpectation `yaml:"perDirectory"`
}

// ComponentExpectation is one component `draugr init` declares.
type ComponentExpectation struct {
	Name string `yaml:"name"`
	// Repositories are the repository urls, relative to the descriptor.
	Repositories []string `yaml:"repositories"`
	// Paths and Ignore are the scope its repositories declare. Empty means the whole repository.
	Paths  []string `yaml:"paths"`
	Ignore []string `yaml:"ignore"`
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
