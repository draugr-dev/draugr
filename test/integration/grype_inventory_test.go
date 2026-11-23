//go:build integration

package integration

import (
	"context"
	"testing"

	"github.com/draugr-dev/draugr/internal/scanners"
	"github.com/draugr-dev/draugr/pkg/plugin"
)

// grype-fs lists the packages Grype read, with or without a finding, from the CycloneDX Grype
// writes beside its SARIF, so dependency health can ask about a package no advisory names. left-pad
// 1.3.0 has no advisory, so only the list can carry it.
func TestGrypeFSListsAPackageWithNoFinding(t *testing.T) {
	requireTool(t, "grype", "the list is read from what Grype writes")
	requireTool(t, "git", "the scan checks the repository out before scanning it")

	repo := newRepo(t, map[string]string{
		"package.json": `{"name":"app","version":"1.0.0","dependencies":{"left-pad":"1.3.0"}}`,
		"package-lock.json": `{"name":"app","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":{` +
			`"":{"name":"app","version":"1.0.0","dependencies":{"left-pad":"1.3.0"}},` +
			`"node_modules/left-pad":{"version":"1.3.0","resolved":"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"}}}`,
	})
	report, err := scanners.NewGrypeFS().Scan(context.Background(), plugin.RepositoryTarget{URL: repo}, plugin.Config{})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range report.Inventory {
		if p.PURL == "pkg:npm/left-pad@1.3.0" {
			if p.Path != "package-lock.json" || p.Scanner != "grype-fs" {
				t.Errorf("left-pad listed as %+v, want at package-lock.json by grype-fs", p)
			}
			return
		}
	}
	t.Errorf("left-pad is not listed; inventory %+v", report.Inventory)
}
