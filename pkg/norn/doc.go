// Package norn evaluates scan results against policy to produce a verdict
// (PASS / FAIL / WAIVED) per control and overall. It begins with declarative severity
// thresholds and is expected to grow toward a richer policy language (e.g. OPA/Rego).
//
// See docs/ARCHITECTURE.md.
package norn
