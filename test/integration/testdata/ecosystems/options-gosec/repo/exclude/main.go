// Command exclude is a sealed-tier fixture for gosec's options: exclude: [G204] reports every rule except that one.
package main

import (
	// ruleid: G501
	"crypto/md5"
	"fmt"
	"os"
	"os/exec"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: exclude <text> <command>")
		os.Exit(2)
	}
	// ruleid: G401
	fmt.Printf("%x\n", md5.Sum([]byte(os.Args[1])))

	// ruleid: G702
	// ok: G204
	out, err := exec.Command(os.Args[2]).Output()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Print(string(out))
}
