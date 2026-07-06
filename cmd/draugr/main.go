// Command draugr is the Draugr CLI: developer-first, descriptor-driven security
// scanning orchestration. See docs/ARCHITECTURE.md.
package main

import (
	"context"
	"os"

	"github.com/draugr-dev/draugr/internal/cli"
)

func main() {
	os.Exit(cli.Execute(context.Background()))
}
