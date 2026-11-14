package scanners

import (
	"path/filepath"
	"slices"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// A filesystem scan lists every package it read, with or without a vulnerability, at the file and
// line it is declared on, so dependency health can ask about the ones no advisory matched. A
// package with no package URL cannot be asked about, and the operating system's packages are not a
// checkout's.
func TestTrivyFSListsEveryPackageItRead(t *testing.T) {
	dir := t.TempDir()
	lock := filepath.Join(dir, "web", "package-lock.json")
	out := []byte(`{"Results":[
	  {"Target":"` + lock + `","Class":"lang-pkgs","Type":"npm",
	   "Packages":[
	     {"Name":"evil","Version":"6.6.6","Identifier":{"UID":"a","PURL":"pkg:npm/evil@6.6.6"},"Locations":[{"StartLine":9}]},
	     {"Name":"lodash","Version":"4.17.20","Identifier":{"UID":"b","PURL":"pkg:npm/lodash@4.17.20"}},
	     {"Name":"nameless","Version":"1.0.0","Identifier":{"UID":"c"}}
	   ],
	   "Vulnerabilities":[{"VulnerabilityID":"CVE-2021-23337","PkgName":"lodash","InstalledVersion":"4.17.20",
	     "PkgIdentifier":{"UID":"b","PURL":"pkg:npm/lodash@4.17.20"},"Severity":"HIGH"}]},
	  {"Target":"debian","Class":"os-pkgs","Type":"debian",
	   "Packages":[{"Name":"openssl","Version":"3.0.0","Identifier":{"PURL":"pkg:deb/debian/openssl@3.0.0"}}]}
	]}`)
	rep, err := parseTrivyVulns(out, dir, plugin.Config{})
	if err != nil {
		t.Fatal(err)
	}
	want := []sarif.InventoryPackage{
		{PURL: "pkg:npm/evil@6.6.6", Path: "web/package-lock.json", Line: 9},
		{PURL: "pkg:npm/lodash@4.17.20", Path: "web/package-lock.json"},
	}
	if !slices.Equal(rep.Inventory, want) {
		t.Errorf("inventory = %+v, want %+v", rep.Inventory, want)
	}

	// An image scan has no checkout, so it lists nothing.
	if rep, err := parseTrivyVulns(out, "", plugin.Config{}); err != nil || len(rep.Inventory) != 0 {
		t.Errorf("an image scan listed %+v (%v)", rep.Inventory, err)
	}
}
