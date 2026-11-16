// Package plugin is the Draugr plugin SDK. It defines the three extension kinds, being
// Scanner, Controller and Surveyor, and the value types they share (Target, Config).
//
// A plugin is Go code compiled into the draugr binary and registered in internal/builtins,
// the only place the CLI reads plugins from. Draugr loads no plugin at runtime, whether from
// another process, a shared library or a manifest. Package tooladapter builds a Scanner from a
// Go description of how to run a command-line tool and decode its output, which is how several
// built-in scanners are written. Findings from a tool Draugr has no scanner for can be read
// from a SARIF file through a component's imports, with no code.
//
// See docs/contributing/plugin-api.md.
package plugin
