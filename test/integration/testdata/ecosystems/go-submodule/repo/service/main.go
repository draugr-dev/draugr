// Command service is a sealed-tier fixture: it reaches gjson's vulnerable Get.
package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/tidwall/gjson"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: service <json>")
		os.Exit(2)
	}
	fmt.Println(gjson.Get(os.Args[1], "name").String())

	// ruleid: G204, G702
	out, err := exec.Command(os.Args[1]).Output()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Print(string(out))
}
