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

// contextFloors let a control say that a component's exposure and criticality do not bound its
// findings, so they are ranked as though the component were the most exposed and most critical
// one in the descriptor.
//
// It exists because a severity floor alone does not survive the priority model, and the two then
// reach opposite conclusions about the same finding. `secrets` declares that a credential is
// serious whatever the scanner rated it — that is the severity floor above. Priority then applies
// exposure and criticality, which are premised on seriousness varying with context, and damps it
// to P3 or P4. The report tells a reader that nothing is urgent and that they cannot ship, in the
// same six lines, from the same finding.
//
// The resolution is not that exposure is wrong: for a CVE in a dependency, where a component sits
// is exactly what decides how much it matters. It is that some findings are not bounded by the
// component at all. A credential is valid wherever it is valid — a cloud account, a registry, an
// artifact store — and git history is frequently readable by more people than the service is
// reachable by, so `internal` can understate who can obtain it.
//
// A context tier rather than a fixed band, because the claim is about **exposure**, not about
// urgency. Pinning a band would also decide the severity question, and severity is still the
// scanner's and the severity floor's to answer: a critical finding and a high one should not
// collapse into the same row because they happen to share a control.
//
// Ranking rather than gating. A finding somebody has judged belongs in `config.exclude`, where it
// stays in the report marked suppressed with a reason — a lower band is the wrong lever for a
// false positive, and using it that way is the same category error this fixes.
var contextFloors = map[string]prioritization.Context{
	"secrets": prioritization.C1,
}

// contextFloorReasons say why, for the report. A band a reader cannot account for from the
// component's classification is one they have to take on trust, and the reasoning is the part
// worth keeping inspectable.
//
// It states the conclusion, not the mechanism. Internally the floor works by ranking the finding
// at the most exposed context tier, but "ranked as internet-facing" printed against a component
// the reader has classified as internal reads as a claim about the component — one they can see is
// untrue, which costs the note its credibility on the row where it matters most.
//
// Short, because it prints under every finding in a table somebody is scanning rather than
// reading. Why the control declares a floor is in docs/concepts/prioritization.md, where a reader
// who wants it will look; repeating the argument on every row buys nothing and costs the row.
// #nosec G101 -- report copy: a map of control names to the sentence printed under a finding.
var contextFloorReasons = map[string]string{
	"secrets": "a leaked credential is high priority wherever it is found",
}

// ContextFloor returns the most concerning context tier a control's findings are ranked at, and
// why. An empty tier means the control declares none and the component's own classification
// stands.
func ContextFloor(control string) (prioritization.Context, string) {
	return contextFloors[control], contextFloorReasons[control]
}
