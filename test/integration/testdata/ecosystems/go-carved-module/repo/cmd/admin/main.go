// Command admin is a sealed-tier fixture: it imports the shared store and reaches gjson's
// vulnerable Get through it.
package main

import (
	"fmt"
	"os"

	"example.com/sealed/carved/internal/store"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: admin <json>")
		os.Exit(2)
	}
	fmt.Println(store.Name(os.Args[1]))
}
