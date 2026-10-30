// Command gen rewrites the Saga JSON Schema's generated sections from the plugin registry, and the
// fragment and config schemas derived from it.
//
// Run via `go generate ./pkg/saga/...`.
package main

import (
	"fmt"
	"os"

	"github.com/draugr-dev/draugr/internal/builtins"
	"github.com/draugr-dev/draugr/internal/schemagen"
)

func main() {
	const path = "draugr.saga.schema.json"
	const fragmentPath = "draugr.saga-fragment.schema.json"
	const configPath = "draugr.config.schema.json"
	current, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read schema:", err)
		os.Exit(1)
	}
	out, err := schemagen.Apply(current, builtins.Registry())
	if err != nil {
		fmt.Fprintln(os.Stderr, "generate:", err)
		os.Exit(1)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil { // #nosec G703 -- path is the const above
		fmt.Fprintln(os.Stderr, "write schema:", err)
		os.Exit(1)
	}

	// The fragment schema is derived from the Saga's, so it is regenerated in the same breath and
	// cannot fall behind it.
	frag, err := schemagen.FragmentSchema(out)
	if err != nil {
		fmt.Fprintln(os.Stderr, "generate fragment schema:", err)
		os.Exit(1)
	}
	if err := os.WriteFile(fragmentPath, frag, 0o600); err != nil { // #nosec G703 -- the const below
		fmt.Fprintln(os.Stderr, "write fragment schema:", err)
		os.Exit(1)
	}

	// The config schema shares the Saga's control definitions, so it is regenerated beside them for
	// the same reason.
	cfg, err := schemagen.ConfigSchema(out)
	if err != nil {
		fmt.Fprintln(os.Stderr, "generate config schema:", err)
		os.Exit(1)
	}
	if err := os.WriteFile(configPath, cfg, 0o600); err != nil { // #nosec G703 -- the const above
		fmt.Fprintln(os.Stderr, "write config schema:", err)
		os.Exit(1)
	}
}
