// Command golang is a sealed-tier fixture: it reaches one of golang.org/x/text's vulnerable
// functions and not the other, and starts a process from its arguments.
package main

import (
	"fmt"
	"os"
	"os/exec"

	"golang.org/x/text/language"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: golang <language tag> <command>")
		os.Exit(2)
	}
	tag, err := language.Parse(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(tag)

	// ruleid: G204, G702
	out, err := exec.Command(os.Args[2]).Output()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Print(string(out))
}
