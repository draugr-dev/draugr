// Command gen rewrites the Saga JSON Schema's generated sections from the plugin registry.
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
	if err := os.WriteFile(path, out, 0o600); err != nil { //nolint:gosec // path is the const above
		fmt.Fprintln(os.Stderr, "write schema:", err)
		os.Exit(1)
	}
}
