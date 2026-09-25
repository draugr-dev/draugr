// Command worker is a sealed-tier fixture: it reaches gjson's vulnerable Get.
package main

import (
	"fmt"
	"os"

	"github.com/tidwall/gjson"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: worker <json>")
		os.Exit(2)
	}
	fmt.Println(gjson.Get(os.Args[1], "name").String())
}
