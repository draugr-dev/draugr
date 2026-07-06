// Package engine orchestrates a run: it builds the execution plan (controllers ×
// components), schedules scan jobs with bounded parallelism, applies content-hash
// caching so unchanged targets are not re-scanned, and drives the pipeline from
// describe through publish.
//
// See docs/ARCHITECTURE.md.
package engine
