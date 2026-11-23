package scanners

import (
	"context"
	"os"
	"slices"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// grype-fs lists every package it read, with or without a vulnerability, at the first file it was
// found in, so dependency health can ask about the ones no advisory matched, as it does with
// trivy-fs. A package with no package URL cannot be asked about, an operating system's package is
// not a checkout's, and a file Syft cataloged is not a package. Two repositories, because a list
// keyed on anything coarser than the repository would let one scan's packages answer for the other's.
func TestGrypeFSListsEveryPackageItRead(t *testing.T) {
	trees := map[string]string{
		"https://example.com/api.git": writeTree(t, map[string]string{"package-lock.json": "{}"}),
		"https://example.com/web.git": writeTree(t, map[string]string{"web/package-lock.json": "{}"}),
	}
	inventory := map[string]string{
		trees["https://example.com/api.git"]: `{"components":[
			{"type":"library","purl":"pkg:npm/discord.dll@1.0.0","properties":[
				{"name":"syft:location:0:path","value":"/package-lock.json"}]}
		]}`,
		trees["https://example.com/web.git"]: `{"components":[
			{"type":"library","purl":"pkg:npm/lodash@4.17.20","properties":[
				{"name":"syft:location:0:path","value":"/web/package-lock.json"},
				{"name":"syft:location:1:path","value":"/web/package.json"}]},
			{"type":"library","name":"nameless","properties":[
				{"name":"syft:location:0:path","value":"/web/package-lock.json"}]},
			{"type":"library","purl":"pkg:deb/debian/openssl@3.0.0","properties":[
				{"name":"syft:location:0:path","value":"/var/lib/dpkg/status"}]},
			{"type":"library","purl":"pkg:npm/nowhere@1.0.0"},
			{"type":"file","name":"/web/package-lock.json"}
		]}`,
	}
	g, _ := NewGrypeFS().(repoScanner)
	g.checkout = checkoutOf(trees)
	g.run = func(_ context.Context, dir string, argv []string) ([]byte, error) {
		if err := os.WriteFile(inventoryPath(argv), []byte(inventory[dir]), 0o600); err != nil {
			return nil, err
		}
		return grypeOutput(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"grype"}},"results":[]}]}`, "{}"), nil
	}
	var got []sarif.InventoryPackage
	for _, url := range []string{"https://example.com/api.git", "https://example.com/web.git"} {
		rep, err := g.Scan(context.Background(), plugin.RepositoryTarget{URL: url}, plugin.Config{})
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, rep.Inventory...)
	}
	want := []sarif.InventoryPackage{
		{PURL: "pkg:npm/discord.dll@1.0.0", Scanner: "grype-fs", Repository: "https://example.com/api", Path: "package-lock.json"},
		{PURL: "pkg:npm/lodash@4.17.20", Scanner: "grype-fs", Repository: "https://example.com/web", Path: "web/package-lock.json"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("inventory =\n%+v\nwant\n%+v", got, want)
	}
}

// Each package manager's URL is one dependency health can ask about; an operating system's is not.
func TestOSPackage(t *testing.T) {
	for purl, want := range map[string]bool{
		"pkg:deb/debian/openssl@3.0.0": true, "pkg:rpm/redhat/bash@5.1": true, "pkg:apk/alpine/musl@1.2.4": true,
		"pkg:npm/lodash@4.17.20": false, "pkg:golang/golang.org/x/text@v0.3.0": false,
	} {
		if got := osPackage(purl); got != want {
			t.Errorf("%s: %v, want %v", purl, got, want)
		}
	}
}
