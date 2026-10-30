package saga

import (
	_ "embed"
	"strings"
)

//go:generate go run ../../internal/schemagen/gen

// SchemaJSON is the Saga's JSON Schema, embedded so the binary always carries the schema it
// actually enforces. That makes `draugr schema` exact, no network, no version guessing. And is
// what lets an air-gapped or pinned setup validate against precisely this build.
//
//go:embed draugr.saga.schema.json
var SchemaJSON []byte

// FragmentSchemaJSON is the Saga fragment's JSON Schema, embedded for the same reason.
//
// A separate document because a fragment is a different shape: it has no `release:`, and it may
// not carry policy. Validating one against the Saga's schema would report a missing release on
// every valid fragment, which is why the two file types are distinguishable by name.
//
//go:embed draugr.saga-fragment.schema.json
var FragmentSchemaJSON []byte

// ConfigSchemaJSON is the JSON Schema for draugr.config.yaml, embedded for the same reason.
//
// Beside the Saga's because its `controls` block is the Saga's: the same per-control definitions,
// generated from the same registry in the same `go generate`, so a scanner option is held to the
// same rule in both files.
//
//go:embed draugr.config.schema.json
var ConfigSchemaJSON []byte

// schemaBaseURL is where published copies live. The unversioned file tracks the newest release;
// each release also publishes an immutable copy under its own tag.
const schemaBaseURL = "https://draugr.dev/schema"

// SchemaURL is the schema that tracks the latest release. Use it to follow along with new
// Draugr versions; use SchemaURLFor to stay matched to a specific one.
const SchemaURL = schemaBaseURL + "/draugr.saga.schema.json"

// FragmentSchemaURL is the published fragment schema tracking the latest release.
const FragmentSchemaURL = schemaBaseURL + "/draugr.saga-fragment.schema.json"

// ConfigSchemaURL is the published draugr.config.yaml schema tracking the latest release.
const ConfigSchemaURL = schemaBaseURL + "/draugr.config.schema.json"

// SchemaURLFor returns the published schema for a specific Draugr version, so an editor
// validates a Saga against the same rules the installed binary applies. Unreleased builds
// ("dev", or an empty version) have no published copy, so they fall back to the latest.
func SchemaURLFor(version string) string { return versioned(version, "draugr.saga.schema.json") }

// ConfigSchemaURLFor is SchemaURLFor for the draugr.config.yaml schema.
func ConfigSchemaURLFor(version string) string {
	return versioned(version, "draugr.config.schema.json")
}

// versioned is the published copy of file for version, or the latest one for an unreleased build.
func versioned(version, file string) string {
	v := strings.TrimSpace(version)
	if v == "" || v == "dev" {
		return schemaBaseURL + "/" + file
	}
	if !strings.HasPrefix(v, "v") {
		v = "v" + v
	}
	return schemaBaseURL + "/" + v + "/" + file
}
