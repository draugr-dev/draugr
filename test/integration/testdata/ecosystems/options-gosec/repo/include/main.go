// Command include is a sealed-tier fixture for gosec's options: include: [G204] reports that rule alone.
package main

import (
	// ok: G501
	"crypto/md5"
	"fmt"
	"os"
	"os/exec"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: include <text> <command>")
		os.Exit(2)
	}
	// ok: G401
	fmt.Printf("%x\n", md5.Sum([]byte(os.Args[1])))

	// ruleid: G204
	// ok: G702
	out, err := exec.Command(os.Args[2]).Output()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Print(string(out))
}
