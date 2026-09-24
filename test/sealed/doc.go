// Package sealed builds what the sealed coverage tier runs against: advisory databases generated
// from one file of our own text, a container with no network, the expectations a scenario states,
// and the comparison between those and what a scan produced.
//
// The tier exists to assert exact results. A test against the live databases can only assert
// structure, because an advisory published tomorrow changes today's answer. Against a database
// generated from test/integration/testdata/ecosystems/advisories.yaml, a scan either produces the
// findings the scenario names or it has a bug, and running it with no network makes any fetch the
// design did not account for fail rather than drift.
package sealed
