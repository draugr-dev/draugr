package plugin

import (
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
	// additional opt-in scanners (see controllers.<name>.scanners); those are discovered from
	// the registry rather than listed here.
	DefaultScanners []string
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
