package controllers

import "github.com/draugr-dev/draugr/pkg/sarif"

// severityFloors raises the normalized severity of findings from controls whose tools
// under-rate (or don't rate) them. A leaked secret, for example, should never rank "low"
// however the scanner scored it. Controls without an entry have no floor.
var severityFloors = map[string]sarif.Severity{
	"secrets": sarif.SeverityHigh,
}

// SeverityFloor returns the minimum normalized severity for a control's findings, or an
// empty severity (no floor) when the control declares none. Used by prioritization when
// resolving a finding's severity.
func SeverityFloor(control string) sarif.Severity {
	return severityFloors[control]
}
