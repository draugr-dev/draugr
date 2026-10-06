// Command api is a sealed-tier fixture: it imports the shared store and reaches only Valid.
package main

import (
	"fmt"
	"os"

	"example.com/sealed/carved/internal/store"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: api <json>")
		os.Exit(2)
	}
	fmt.Println(store.Valid(os.Args[1]))
}
