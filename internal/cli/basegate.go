package cli

import (
	"bytes"
	"fmt"
	"io"
	"path/filepath"
	"slices"

	"github.com/draugr-dev/draugr/pkg/diff"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/skald"
)

// thisScan names the run in progress where a message compares it with its base, in the place
// `draugr diff` names the head report's path.
const thisScan = "this scan"

// baseGate is a scan's gate on new findings: the threshold, the setting that named it, and the
// base scan it compares against.
type baseGate struct {
	failOn sarif.Severity
	band   string
	// from is the setting that named the threshold, --fail-on-new or config.gate.failOnNew.
	from string
	// basePath is --base, and base the report it names. Empty where no --base was passed.
	basePath string
	base     sarif.Report
	// sarifAt is the results.sarif this run writes, where -o writes one, for the message that says
	// how to list the new findings.
	sarifAt string
}

// newBaseGate resolves the gate on new findings and reads the base, before anything is scanned.
//
// The threshold is resolved as `draugr diff` resolves it, by the same function. The base is checked
// against this run's scope here, where the scope is already known, with the check `draugr diff`
// makes on two reports: a base of one component compared with a scan of two reads every finding
// in the other as new.
func newBaseGate(opts scanOptions, gate *saga.GateConfig, scope engine.Scope) (baseGate, error) {
	failOn, band, err := resolveDiffGate(opts.failOnNew, "", gate)
	if err != nil {
		return baseGate{}, err
	}
	g := baseGate{failOn: failOn, band: band, from: "config.gate.failOnNew", basePath: opts.base}
	if opts.failOnNew != "" {
		g.from = "--fail-on-new"
	}
	if opts.outputDir != "" && (len(opts.reports) == 0 || slices.Contains(opts.reports, "sarif")) {
		g.sarifAt = filepath.Join(opts.outputDir, "results.sarif")
	}
	if opts.base == "" {
		return g, nil
	}
	if g.base, err = loadSARIF(opts.base); err != nil {
		return baseGate{}, fmt.Errorf("--base: %w", err)
	}
	if err := comparableScopes(opts.base, g.base, thisScan, scopeReport(scope)); err != nil {
		return baseGate{}, err
	}
	return g, nil
}

// setting is the threshold as report.json states it, empty where none is set.
func (g baseGate) setting() string { return newGateSetting(g.failOn, g.band) }

// noteUnapplied says on w that a gate on new findings is set and has no base to apply to.
//
// report.json states the setting with no comparison beside it, and this is the same fact where a
// person reads the run. Without it a pipeline that sets the gate and never passes --base reads as
// one whose changes introduce nothing.
func (g baseGate) noteUnapplied(w io.Writer) {
	if g.setting() == "" || g.basePath != "" {
		return
	}
	_, _ = fmt.Fprintf(w, "%s is %s and no --base names a scan to compare against, so no finding was judged as new.\n",
		g.from, g.setting())
}

// compare classifies this run's findings against the base, and returns the comparison as
// report.json states it and the number of new findings that met the gate. Nil and zero where no
// --base was passed.
//
// The head is this run as results.sarif carries it, written and read back, so the comparison is
// the one `draugr diff` would make between the base and that file. Comparing the run as it is held
// in memory would match findings on fields the file spells differently.
func (g baseGate) compare(run engine.Result) (*skald.NewFindings, int, error) {
	if g.basePath == "" {
		return nil, 0, nil
	}
	head, err := headAsWritten(run)
	if err != nil {
		return nil, 0, err
	}
	compared, err := compareWithBase(g.basePath, g.base, thisScan, head)
	if err != nil {
		return nil, 0, err
	}
	compared.Gate = diff.Gate{FailOn: g.failOn, FailOnPriority: g.band}
	compared.Tripped = compared.GateNew(g.failOn, g.band)
	return &skald.NewFindings{
		Base:       sarif.RepositoriesIn([]sarif.Report{g.base}),
		Introduced: compared.Counted().New,
		Tripped:    len(compared.Tripped) > 0,
	}, len(compared.Tripped), nil
}

// failure is the error a scan exits with when a gate failed: the verdict, the gate on new findings,
// or both, in that order. policyFailed is the verdict; tripped counts the new findings that met
// the gate.
func (g baseGate) failure(policyFailed bool, tripped int) error {
	if tripped == 0 {
		return fmt.Errorf("policy verdict: fail")
	}
	newErr := errNewFindings(tripped)
	if g.sarifAt != "" {
		newErr = fmt.Errorf("%w; `draugr diff %s %s` lists them", newErr, g.basePath, g.sarifAt)
	} else {
		newErr = fmt.Errorf("%w; scan again with -o <dir>, and `draugr diff %s <dir>/results.sarif` "+
			"lists them", newErr, g.basePath)
	}
	if policyFailed {
		return fmt.Errorf("policy verdict: fail, and %w", newErr)
	}
	return newErr
}

// headAsWritten is the run as results.sarif carries it, read back the way `draugr diff` reads one.
func headAsWritten(run engine.Result) (sarif.Report, error) {
	var buf bytes.Buffer
	if err := skald.WriteSARIF(&buf, run); err != nil {
		return sarif.Report{}, err
	}
	return sarif.FromSARIF(buf.Bytes())
}

// scopeReport is a report carrying nothing but the scope a run will stamp on its SARIF, for
// checking a base against a run that has not happened yet.
func scopeReport(scope engine.Scope) sarif.Report {
	var r sarif.Report
	if p, ok := skald.ScopeProvenance(scope); ok {
		r.Provenance = []sarif.Provenance{p}
	}
	return r
}
