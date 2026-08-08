// Package ciguard holds assertions about this repository's own CI configuration.
//
// It has no runtime code. It exists because a class of mistake in a workflow file produces no
// diagnostics at all: the run is green, or it never starts, and nothing names what was wrong. A
// unit test is the cheapest place to find those, and the only place that finds them before the
// change is merged.
package ciguard
