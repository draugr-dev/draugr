// Command serve runs a command inside a sealed container with sealed.ServedHandler listening on
// the loopback interface beside it:
//
//	serve <root> <request log> <command> [args...]
//
// It exists so a scenario can hand a scanner a Maven repository, a rule registry or a container
// registry with the network still switched off.
package main

import (
	"fmt"
	"os"

	"github.com/draugr-dev/draugr/test/sealed"
)

func main() {
	if len(os.Args) < 4 {
		fmt.Fprintln(os.Stderr, "usage: serve <root> <request log> <command> [args...]")
		os.Exit(2)
	}
	os.Exit(sealed.ServeAndRun(sealed.ServedAddr, os.Args[1], os.Args[2], os.Args[3:], os.Stdout, os.Stderr))
}
