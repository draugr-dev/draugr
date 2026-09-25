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
	// Sealed changes what the container provides and how the scan runs.
	Sealed RunOptions `yaml:"sealed"`
	// Errors are the controls that must fail to run, each with text its error must contain. Every
	// other control must run.
	Errors []ErrorExpectation `yaml:"errors"`
	// Proves names the options whose effect the findings assert, as <scanner>.<option> for a
	// scanner's option (gosec.include) or <control>.<option> for a control's own (licenses.deny).
	// Each must be set in the scenario's descriptor, and the findings must differ because of it.
	Proves []string `yaml:"proves"`
	// Requests are requests the sealed server must have received by the end of the scan, each the
	// start of a line of its log, "METHOD request-uri", for a scenario whose findings depend on
	// something a scanner fetched from it.
	Requests []string `yaml:"requests"`
	// NeverRequested are line starts no request in the log may have, "DELETE " for every delete.
	NeverRequested []string `yaml:"neverRequested"`
	// InitScan is where a scan with the descriptor init wrote departs from Findings and Errors.
	InitScan InitScanExpectation `yaml:"initScan"`
}

// RunOptions change what a sealed run provides. Most take something away, so a scenario can
// assert that its absence is reported rather than passed.
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
	// WithoutOffline scans without --offline, for a scenario whose scanner resolves something from
	// the sealed server, which the flag would stop it asking for. The container still has no
	// network beyond its own loopback.
	WithoutOffline bool `yaml:"withoutOffline"`
}

// ScanFlags are the flags a sealed scan runs with beyond its descriptor and output.
func (o RunOptions) ScanFlags() []string {
	if o.WithoutOffline {
		return []string{"--log-level", "warn"}
	}
	return []string{"--offline", "--log-level", "warn"}
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
	// Specs are the API documents it proposes as a host's spec, in the hosts block it writes
	// commented out. Empty means none.
	Specs []string `yaml:"specs"`
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
	// Rules are the rules that must report it. Empty means nothing may report it, which is how a
	// scenario writes a credential outside every component's paths and holds every component to
	// leaving it alone.
	Rules []string `yaml:"rules"`
	// Components are the components that must each report it, once per rule. Empty means one
	// report from any component, which is enough where one component scans the repository. Where
	// several share it, a secret reported under a component whose paths do not hold it is a
	// credential filed with a team that cannot rotate it, and only naming the owner catches that.
	Components []string `yaml:"components,omitempty"`
	// Removed deletes the file in a second commit, so the secret is in the repository's history
	// and not in its tree, and each report of it has to carry the history mark.
	Removed bool `yaml:"removed"`
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
	// Component is the component the finding was reported for. Empty matches any, which is enough
	// where one component scans the repository; two components scanning one file report it twice,
	// and only the component tells those two findings apart.
	Component string `yaml:"component,omitempty"`
	// Reachability is the verdict reachability analysis reached, where it ran.
	Reachability string `yaml:"reachability,omitempty"`
	// Historical says the finding comes from the repository's history rather than its tree, and
	// the SARIF result has to carry the mark.
	Historical bool `yaml:"historical,omitempty"`
	// Suppressed is the origin of the suppression the finding has to carry: saga, vex, tool or
	// scanner. Empty means the finding has to arrive active.
	Suppressed string `yaml:"suppressed,omitempty"`
}

// LeavesFieldsUnwritten reports whether a scan of the scenario leaves out fields the normalizers
// clear: a control that failed to start writes no scanner version, and a scan whose results are
// all about whole files, or that finds nothing, has no line to take a fingerprint from. Secrets
// are written on line 1, except one found only in history, which is a result about a commit
// rather than a line of the tree.
func (e Expected) LeavesFieldsUnwritten() bool {
	if len(e.Errors) > 0 {
		return true
	}
	for _, s := range e.Secrets {
		if !s.Removed {
			return false
		}
	}
	for _, f := range e.Findings {
		if _, line, err := splitLocation(f.Location); err == nil && line > 0 {
			return false
		}
	}
	return true
}
