package controllers

import (
	"github.com/draugr-dev/draugr/pkg/prioritization"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

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

// priorityFloors keep a control's findings from being ranked routine by a component's
// classification, and exist because a severity floor alone does not survive the priority model.
//
// The two mechanisms otherwise reach opposite conclusions about the same finding. `secrets`
// declares that a credential is serious whatever the scanner rated it — that is what the severity
// floor above says. Priority then applies exposure and criticality, which are premised on
// seriousness varying with context, and damps it back to P3 or P4. The report then tells a reader
// that nothing is urgent and that they cannot ship, in the same six lines, from the same finding.
//
// The resolution is not "exposure is wrong": for a CVE in a dependency, where a component sits is
// exactly what decides how much it matters. It is that some findings are not bounded by the
// component at all. A credential is valid wherever it is valid — a cloud account, a registry, an
// artifact store — and git history is frequently readable by more people than the service is
// reachable by, so `internal` can understate who can obtain it.
//
// A floor, not a fixed band: exposure may still raise a credential on a public critical component
// to P1. It may not push one below "this cycle".
var priorityFloors = map[string]prioritization.Priority{
	"secrets": prioritization.P2,
}

// priorityFloorReasons say why, for the report. A band a reader cannot account for from the
// component's classification is one they have to take on trust, and the reasoning is the part
// worth keeping inspectable.
var priorityFloorReasons = map[string]string{ // #nosec G101 -- prose about credentials, not one
	"secrets": "a credential is valid wherever it is valid, not only where the component sits",
}

// PriorityFloor returns the lowest band a control's findings may be ranked at, and why. An empty
// priority means the control declares no floor and the matrices' answer stands.
func PriorityFloor(control string) (prioritization.Priority, string) {
	return priorityFloors[control], priorityFloorReasons[control]
}
