package scanners

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/manifests"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/report"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// pomTwoScanners reads one of the outputs recorded for one pom.xml declaring commons-text 1.9,
// whose own pom declares commons-lang3 3.11, with the directory scanned replaced by /checkout:
//
//   - trivy-offline.json and trivy-license-offline.json are Trivy 0.76.1 under --offline-scan with
//     no local Maven repository: commons-text and nothing below it.
//   - trivy-resolved.json and trivy-license-resolved.json are Trivy 0.76.1 with both dependency poms
//     to read, served from a repository on localhost, which is what it reports when they are in the
//     local Maven repository: commons-text and commons-lang3 below it.
//   - grype.sarif, grype.json and grype.cdx.json are the three reports one run of Grype 0.121.0
//     (Syft 1.55.0) writes for the same pom, whichever repository the dependency poms are in,
//     since it reads none of them: the pom's own package and commons-text, and no commons-lang3.
func pomTwoScanners(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "pom-two-scanners", name)) // #nosec G304 -- under testdata
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The poms the outputs were recorded from. The resolved one names the repository the recording
// read its dependency poms from, which moves its dependency to line 14.
const (
	pomOfflineTree = `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>service</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-text</artifactId>
      <version>1.9</version>
    </dependency>
  </dependencies>
</project>
`
	pomResolvedTree = `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>service</artifactId>
  <version>1.0.0</version>
  <repositories>
    <repository>
      <id>local</id>
      <url>http://127.0.0.1:18795/</url>
    </repository>
  </repositories>
  <dependencies>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-text</artifactId>
      <version>1.9</version>
    </dependency>
  </dependencies>
</project>
`
)

// runPomScan runs sca with the scanners named and licenses with trivy-license over two components
// in two repositories: shop's pom has its transitive dependencies unresolved, the issue's
// reproduction, and billing's resolves. It returns each component's coverage by component and
// control, and the console.
func runPomScan(t *testing.T, sca ...string) (map[string]engine.InputCoverage, string) {
	t.Helper()
	trees := map[string]string{
		"shop":    writeTree(t, map[string]string{"pom.xml": pomOfflineTree}),
		"billing": writeTree(t, map[string]string{"pom.xml": pomResolvedTree}),
	}
	vulns := map[string][]byte{trees["shop"]: pomTwoScanners(t, "trivy-offline.json"), trees["billing"]: pomTwoScanners(t, "trivy-resolved.json")}
	licenses := map[string][]byte{trees["shop"]: pomTwoScanners(t, "trivy-license-offline.json"), trees["billing"]: pomTwoScanners(t, "trivy-license-resolved.json")}

	prior := grypeRunInDir
	t.Cleanup(func() { grypeRunInDir = prior })
	grypeJSON, inventory := pomTwoScanners(t, "grype.json"), pomTwoScanners(t, "grype.cdx.json")
	grypeRunInDir = func(_ context.Context, _ string, argv []string) ([]byte, error) {
		for i, a := range argv {
			if a != "-o" || i+1 == len(argv) {
				continue
			}
			format, path, ok := strings.Cut(argv[i+1], "=")
			if !ok {
				continue
			}
			body := grypeJSON
			if format == "cyclonedx-json" {
				body = inventory
			}
			if err := os.WriteFile(path, body, 0o600); err != nil {
				return nil, err
			}
		}
		return pomTwoScanners(t, "grype.sarif"), nil
	}
	grype := NewGrypeFS().(repoScanner)
	grype.checkout, grype.prewarm, grype.cacheVersion, grype.dataState = checkoutOf(trees), nil, nil, nil

	trivy := NewTrivyFS().(repoScanner)
	trivy.checkout, trivy.prewarm, trivy.cacheVersion, trivy.dataState = checkoutOf(trees), nil, nil, nil
	trivy.runLogged = trivyFSRun(func(_ context.Context, dir string, _ []string) ([]byte, []byte, error) {
		return vulns[dir], nil, nil
	})
	lic := NewTrivyLicense().(licenseScanner).repo.(repoScanner)
	lic.checkout, lic.prewarm, lic.cacheVersion, lic.dataState = checkoutOf(trees), nil, nil, nil
	lic.runLogged = trivyFSRun(func(_ context.Context, dir string, _ []string) ([]byte, []byte, error) {
		return licenses[dir], nil, nil
	})

	reg := engine.NewRegistry()
	reg.RegisterController(matchController{control: "sca", scanners: sca})
	reg.RegisterController(matchController{control: "licenses", scanners: []string{"trivy-license"}})
	reg.RegisterScanner(grype)
	reg.RegisterScanner(trivy)
	reg.RegisterScanner(lic)
	model := saga.Model{
		Config: saga.Config{Controls: map[string]saga.ControllerSettings{"sca": {"enabled": true}, "licenses": {"enabled": true}}},
		Components: []saga.Component{
			{Name: "shop", Repositories: []saga.Repository{{URL: "shop"}}},
			{Name: "billing", Repositories: []saga.Repository{{URL: "billing"}}},
		},
	}
	res, err := engine.New(reg).Run(context.Background(), model)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]engine.InputCoverage{}
	for _, in := range res.Inputs {
		got[in.Component+"/"+in.Control] = in
	}
	return got, renderFormat(t, "console", report.Data{Project: "p", Run: res})
}

// checkPomCoverage compares each component's coverage with want, and the console's caveat rows with
// rows, which are every row naming a pom.xml.
func checkPomCoverage(t *testing.T, got, want map[string]engine.InputCoverage, console string, rows ...string) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("inputs\n%+v\nwant\n%+v", got, want)
	}
	var pomRows []string
	for _, line := range strings.Split(console, "\n") {
		if strings.Contains(line, " pom.xml ") {
			pomRows = append(pomRows, strings.TrimSpace(line))
		}
	}
	if !reflect.DeepEqual(pomRows, rows) {
		t.Errorf("pom rows\n%q\nwant\n%q\nconsole:\n%s", pomRows, rows, console)
	}
}

// With trivy-fs beside grype-fs, shop's pom keeps its caveat under sca, though Grype reported it
// with packages, and the row shows Trivy's reason, the one naming what clears it, in one row with
// licenses. billing's pom resolved: Trivy read every dependency of it, which clears the row under
// both controls whatever Grype read.
func TestAPomGrypeReadIsCaveatedBesideTrivy(t *testing.T) {
	got, console := runPomScan(t, "grype-fs", "trivy-fs")
	shopPom := []engine.UnreadInput{{Repository: "shop", Path: "pom.xml", Reason: unresolvedPom}}
	// trivy-license names the file's format, which the report folds a component's files by.
	shopLicensePom := []engine.UnreadInput{{Repository: "shop", Path: "pom.xml", Reason: unresolvedPom, Kind: "pom"}}
	checkPomCoverage(t, got, map[string]engine.InputCoverage{
		"shop/sca":         {Component: "shop", Control: "sca", Scanners: []string{"grype-fs", "trivy-fs"}, Read: 1, Unread: shopPom},
		"shop/licenses":    {Component: "shop", Control: "licenses", Scanners: []string{"trivy-license"}, Read: 1, Unread: shopLicensePom},
		"billing/sca":      {Component: "billing", Control: "sca", Scanners: []string{"grype-fs", "trivy-fs"}, Read: 1},
		"billing/licenses": {Component: "billing", Control: "licenses", Scanners: []string{"trivy-license"}, Read: 1},
	}, console,
		"shop       pom.xml  unread-files  transitive dependencies not resolved, run mvn dependency:resolve (licenses, sca)")
}

// With grype-fs alone under sca, both poms are read in part under sca with Grype's reason, which
// names no action because none clears it: billing's too, since Grype read none of the dependency
// poms Trivy found. licenses keeps Trivy's reason for shop alone, on a row of its own, because
// mvn dependency:resolve clears shop's pom for licenses and not for sca.
func TestAPomGrypeReadAloneNamesNoAction(t *testing.T) {
	got, console := runPomScan(t, "grype-fs")
	grypeReason := string(manifests.TransitiveNotReadByGrype)
	checkPomCoverage(t, got, map[string]engine.InputCoverage{
		"shop/sca": {Component: "shop", Control: "sca", Scanners: []string{"grype-fs"}, Read: 1,
			Unread: []engine.UnreadInput{{Repository: "shop", Path: "pom.xml", Reason: grypeReason}}},
		"shop/licenses": {Component: "shop", Control: "licenses", Scanners: []string{"trivy-license"}, Read: 1,
			Unread: []engine.UnreadInput{{Repository: "shop", Path: "pom.xml", Reason: unresolvedPom, Kind: "pom"}}},
		"billing/sca": {Component: "billing", Control: "sca", Scanners: []string{"grype-fs"}, Read: 1,
			Unread: []engine.UnreadInput{{Repository: "billing", Path: "pom.xml", Reason: grypeReason}}},
		"billing/licenses": {Component: "billing", Control: "licenses", Scanners: []string{"trivy-license"}, Read: 1},
	}, console,
		"billing    pom.xml  unread-files  transitive dependencies not read by Grype (sca)",
		"shop       pom.xml  unread-files  transitive dependencies not resolved, run mvn dependency:resolve (licenses)",
		"shop       pom.xml  unread-files  transitive dependencies not read by Grype (sca)")
}

// Grype's reason fits the console's caveat column with both controls named after it.
func TestGrypePomReasonFitsTheCaveatColumn(t *testing.T) {
	if n := len(string(manifests.TransitiveNotReadByGrype) + " (licenses, sca)"); n > 80 {
		t.Errorf("%q with its controls is %d characters, over 80", manifests.TransitiveNotReadByGrype, n)
	}
}

// Every pom.xml Grype read packages from is read in part, wherever it sits and however many
// packages Syft took from it, and no other file is. The pom components are trimmed from Grype
// 0.121.0's inventory of four poms: local-property pins commons-text through a property it defines
// and declares a second dependency through a property nobody defines, remote-parent takes jackson's
// version from a parent no repository holds and pins commons-text, and modules holds an aggregator
// and a child taking commons-text's version from it. Syft leaves both unversioned dependencies out
// without a trace and lists commons-text once, at one of the three poms that declare it. The
// requirements file and the jar are another cataloger's, and keep their reading.
func TestEveryPomGrypeReadIsReadInPart(t *testing.T) {
	inventory := `{"components":[
		{"type":"library","name":"child","properties":[{"name":"syft:package:foundBy","value":"java-pom-cataloger"},{"name":"syft:location:0:path","value":"/modules/child/pom.xml"}]},
		{"type":"library","name":"commons-text","properties":[{"name":"syft:package:foundBy","value":"java-pom-cataloger"},{"name":"syft:location:0:path","value":"/local-property/pom.xml"}]},
		{"type":"library","name":"local-property","properties":[{"name":"syft:package:foundBy","value":"java-pom-cataloger"},{"name":"syft:location:0:path","value":"/local-property/pom.xml"}]},
		{"type":"library","name":"modules-parent","properties":[{"name":"syft:package:foundBy","value":"java-pom-cataloger"},{"name":"syft:location:0:path","value":"/modules/pom.xml"}]},
		{"type":"library","name":"remote-parent","properties":[{"name":"syft:package:foundBy","value":"java-pom-cataloger"},{"name":"syft:location:0:path","value":"/remote-parent/pom.xml"}]},
		{"type":"library","name":"flask","properties":[{"name":"syft:package:foundBy","value":"python-package-cataloger"},{"name":"syft:location:0:path","value":"/requirements.txt"}]},
		{"type":"library","name":"lib","properties":[{"name":"syft:package:foundBy","value":"java-archive-cataloger"},{"name":"syft:location:0:path","value":"/lib/app.jar"}]},
		{"type":"file","name":"/checkout/modules/pom.xml"}
	]}`
	got, err := parseGrypeInventory([]byte(inventory), "/checkout")
	if err != nil {
		t.Fatal(err)
	}
	part := string(manifests.TransitiveNotReadByGrype)
	want := []sarif.Input{
		{Path: "lib/app.jar", Packages: 1},
		{Path: "local-property/pom.xml", Packages: 2, Unread: part},
		{Path: "modules/child/pom.xml", Packages: 1, Unread: part},
		{Path: "modules/pom.xml", Packages: 1, Unread: part},
		{Path: "remote-parent/pom.xml", Packages: 1, Unread: part},
		{Path: "requirements.txt", Packages: 1},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("inputs\n%+v\nwant\n%+v", got, want)
	}
}
