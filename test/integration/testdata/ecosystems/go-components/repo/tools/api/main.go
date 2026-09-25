// Command api is a sealed-tier fixture: it uses gjson without reaching its vulnerable functions.
package main

import (
	"fmt"
	"os"

	"github.com/tidwall/gjson"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: api <json>")
		os.Exit(2)
	}
	fmt.Println(gjson.Valid(os.Args[1]))
}
