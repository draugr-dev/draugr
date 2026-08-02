package saga

import (
	_ "embed"
	"strings"
)

//go:generate go run ../../internal/schemagen/gen

// SchemaJSON is the Saga's JSON Schema, embedded so the binary always carries the schema it
// actually enforces. That makes `draugr schema` exact — no network, no version guessing — and is
// what lets an air-gapped or pinned setup validate against precisely this build.
//
//go:embed draugr.saga.schema.json
var SchemaJSON []byte

// schemaBaseURL is where published copies live. The unversioned file tracks the newest release;
// each release also publishes an immutable copy under its own tag.
const schemaBaseURL = "https://draugr.dev/schema"

// SchemaURL is the schema that tracks the latest release. Use it to follow along with new
// Draugr versions; use SchemaURLFor to stay matched to a specific one.
const SchemaURL = schemaBaseURL + "/draugr.saga.schema.json"

// SchemaURLFor returns the published schema for a specific Draugr version, so an editor
// validates a Saga against the same rules the installed binary applies. Unreleased builds
// ("dev", or an empty version) have no published copy, so they fall back to the latest.
func SchemaURLFor(version string) string {
	v := strings.TrimSpace(version)
	if v == "" || v == "dev" {
		return SchemaURL
	}
	if !strings.HasPrefix(v, "v") {
		v = "v" + v
	}
	return schemaBaseURL + "/" + v + "/draugr.saga.schema.json"
}
