// Package store is a sealed-tier fixture: shared code both commands import, holding one call to
// gjson's vulnerable Get and one to its Valid.
package store

import "github.com/tidwall/gjson"

// Name reads a record's name, through gjson's vulnerable Get.
func Name(record string) string {
	return gjson.Get(record, "name").String()
}

// Valid reports whether a record is well-formed JSON, through gjson's Valid.
func Valid(record string) bool {
	return gjson.Valid(record)
}
