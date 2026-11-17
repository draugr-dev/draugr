package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/builtins"
)

// Two components, each in a repository of its own, import what Trivy and Grype wrote about the same
// dependencies. Each file's findings become upgrades on the component that imports it, naming the
// release to move to, and the console says once how many name no CVE: Grype's file names each
// finding by its GitHub or Go advisory and lists no CVE, where Trivy's names one for all but one.
func TestImportedDependencyFindingsBecomeUpgradesOnEachComponent(t *testing.T) {
	file := func(name string) string {
		abs, err := filepath.Abs("../scanners/testdata/sarif-import/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return abs
	}
	saga := writeSaga(t, `
project: shop
config:
  controls:
    sca:
      trivyFs: {enabled: false}
components:
  - name: api
    exposure: public
    criticality: critical
    repositories:
      - url: "`+t.TempDir()+`"
    imports:
      - control: sca
        file: "`+file("trivy-deps.sarif")+`"
  - name: web
    exposure: public
    criticality: critical
    repositories:
      - url: "`+t.TempDir()+`"
    imports:
      - control: sca
        file: "`+file("grype-deps.sarif")+`"
`)
	opts := scanOptions{format: "json", controls: []string{"sca"}, noGate: true}
	var buf bytes.Buffer
	if err := runScan(context.Background(), saga, opts, builtins.Registry(), &buf); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Actions []struct {
			Title, Component, Package, From, Target string
			Clears                                  int
		} `json:"actions"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	type upgrade struct{ component, pkg, from, target string }
	want := map[upgrade]int{
		{"api", "lodash", "4.17.15", "4.18.0"}:            6,
		{"api", "golang.org/x/text", "v0.3.5", "v0.41.0"}: 4,
		{"web", "lodash", "4.17.15", "4.18.0"}:            5,
		{"web", "golang.org/x/text", "v0.3.5", "v0.41.0"}: 4,
	}
	if len(doc.Actions) != len(want) {
		t.Fatalf("actions = %+v, want one upgrade of each package on each component", doc.Actions)
	}
	for _, a := range doc.Actions {
		u := upgrade{a.Component, a.Package, a.From, a.Target}
		if clears, ok := want[u]; !ok || a.Clears != clears || !strings.HasPrefix(a.Title, "Upgrade ") {
			t.Errorf("action %q %+v clears %d, want one of %v", a.Title, u, a.Clears, want)
		}
	}

	opts.format = "console"
	var console bytes.Buffer
	if err := runScan(context.Background(), saga, opts, builtins.Registry(), &console); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(console.String(), "not checked against KEV or EPSS: 10 imported findings name no CVE"); n != 1 {
		t.Errorf("want the count of findings KEV and EPSS cannot reach once, got %d:\n%s", n, console.String())
	}
}
