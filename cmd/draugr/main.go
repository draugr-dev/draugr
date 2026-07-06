// Command draugr is the Draugr CLI: developer-first, descriptor-driven security
// scanning orchestration. This is a bootstrap skeleton — real subcommands (scan,
// survey, plan, report) arrive in later milestones. See docs/ARCHITECTURE.md.
package main

import (
	"fmt"
	"os"

	"github.com/draugr-dev/draugr/internal/version"
)

const usage = `Draugr — developer-first, descriptor-driven security scanning orchestration.

Usage:
  draugr <command> [flags]

Commands:
  version    Print the Draugr version
  help       Show this help

Run "draugr help" for this message.`

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		fmt.Println(usage)
		return 0
	}
	switch args[0] {
	case "version", "--version", "-v":
		fmt.Println(version.String())
		return 0
	case "help", "-h", "--help":
		fmt.Println(usage)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "draugr: unknown command %q\n\n%s\n", args[0], usage)
		return 2
	}
}
