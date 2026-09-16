package plugin

import (
	"encoding/json"

	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// Scope declares whether a controller operates on the whole project or per component.
type Scope string

// The scopes a controller may declare.
const (
	ScopeProject   Scope = "project"
	ScopeComponent Scope = "component"
)

// Controller orchestrates one or more scanners for a single security control. It plans
// the work for a component (or the project) and aggregates the scanners' results.
type Controller interface {
	Info() ControllerInfo
	// Plan expands a component (or the project, when comp is nil) into scan jobs.
	Plan(model saga.Model, comp *saga.Component) ([]ScanJob, error)
	// Aggregate merges and deduplicates this control's scanner outputs into one result.
	Aggregate(results []sarif.Report) (ControlResult, error)
}

// ControllerInfo describes a controller.
type ControllerInfo struct {
	// Name is the control name, e.g. "images", "sast", "opensource".
	Name  string
	Scope Scope
	// Summary is a one-line description of what the control does, for `draugr controls`.
	Summary string
	// DefaultScanners lists the scanner(s) the control runs by default. Some controls accept
	// additional opt-in scanners, turned on with controls.<name>.<scanner>.enabled; those are
	// discovered from the registry rather than listed here.
	DefaultScanners []string
	// OptionSchema is a JSON Schema for the settings the control itself takes, as distinct from
	// the ones its scanners take. Empty for a control that takes none, which is most of them.
	//
	// A key under a control is one of three things: `enabled`, a scanner's block, or an option
	// like this. The first two are known from the registry; without this the third cannot be
	// told from a typo, so either every unrecognized key is accepted, which is how a descriptor
	// comes to claim a decision it is not making, or every one is rejected, which breaks the
	// controls that legitimately take settings of their own.
	//
	// Declared the same way a scanner declares its options, so `draugr validate`, the published
	// JSON Schema and an editor's completion all read one source and cannot disagree.
	OptionSchema json.RawMessage
}

// Validator is an optional interface a Controller may implement to check a descriptor for
// mistakes its own settings can make and nothing else can see.
//
// A JSON Schema decides whether a setting is well formed. It cannot decide whether the settings
// agree with each other or with the rest of the descriptor: that an image naming a signer names
// one that was declared, that two patterns do not both claim the same image. Those are policy
// questions, and the control is the only thing that knows them.
//
// Returns every problem rather than the first, so a descriptor with three mistakes reports three
// rather than one per re-run. An empty result means nothing to say.
//
// Called by `draugr validate` and before a scan, which is the point: a control's settings decide
// what is checked and what is let through, so being told at the cheap moment is worth more here
// than a clear error at the expensive one.
type Validator interface {
	Validate(model saga.Model) []error
}

// Explainer is an optional interface a Controller may implement to state what a shorthand in the
// descriptor expanded to, once the descriptor is known to be valid.
//
// A shorthand exists where the literal value has a trap, so what it produces is exactly the thing
// nobody can check by reading the file. Printing the expansion turns a generated value into one
// somebody can compare against what they meant, before a scan depends on it.
//
// Not warnings. Nothing here is wrong, and reporting it as though it were teaches a reader to skim
// the marks that matter.
type Explainer interface {
	Explain(model saga.Model) []string
}

// ScanJob is a unit of scan work produced by a controller's Plan.
type ScanJob struct {
	Scanner  string
	Target   Target
	Config   Config
	CacheKey CacheKey
}

// ControlResult is a control's outcome after aggregation.
type ControlResult struct {
	Control string
	Report  sarif.Report
	Summary Summary
}

// Summary counts findings by severity, for the Norn (policy/gate).
type Summary struct {
	Errors   int
	Warnings int
	Notes    int
}
