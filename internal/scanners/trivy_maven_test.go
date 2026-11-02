package scanners

import (
	"context"
	"slices"
	"testing"

	"github.com/draugr-dev/draugr/internal/netpolicy"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// The two components of these tests, each in a repository of its own: api sets resolveMaven in
// its trivyFs block and web does not.
var (
	apiRepo = plugin.RepositoryTarget{URL: "https://example.com/api.git"}
	webRepo = plugin.RepositoryTarget{URL: "https://example.com/web.git"}
	apiCfg  = plugin.Config{resolveMavenKey: true}
	webCfg  = plugin.Config{}
)

// trivyArgvs is every Trivy command line a scan of the two components runs, keyed by scanner and
// component. trivy-license and trivy-config receive api's setting too, to show they ignore it.
func trivyArgvs(t *testing.T) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	for comp, cfg := range map[string]plugin.Config{"api": apiCfg, "web": webCfg} {
		dir := "/work/" + comp
		out["trivy-fs/"+comp] = trivyFSArgs(dir, cfg)
		out["trivy-license/"+comp] = trivyLicenseRepoArgs(dir, cfg)
		out["trivy-config/"+comp] = trivyConfigArgs(dir, nil)
		img, err := trivyArgv(plugin.ImageTarget{Ref: "acme/" + comp + ":1"}, nil)
		if err != nil {
			t.Fatal(err)
		}
		out["trivy/"+comp] = img
		licImg, err := trivyLicenseImageArgv(plugin.ImageTarget{Ref: "acme/" + comp + ":1"}, nil)
		if err != nil {
			t.Fatal(err)
		}
		out["trivy-license-image/"+comp] = licImg
	}
	return out
}

// withFSTrivy has trivy-config build its `trivy fs --scanners misconfig` command, the one that runs
// Trivy's dependency analyzers.
func withFSTrivy(t *testing.T) {
	t.Helper()
	was := sharedTrivyVersion.val
	t.Cleanup(func() { sharedTrivyVersion.val = was })
	sharedTrivyVersion.val = "trivy@0.74.0;db@2026-07-15T00:56:58Z"
}

// Every Trivy run passes --offline-scan, except trivy-fs for the component that set resolveMaven.
func TestEveryTrivyRunPassesOfflineScanUnlessTrivyFSResolves(t *testing.T) {
	withFSTrivy(t)
	for key, argv := range trivyArgvs(t) {
		want := key != "trivy-fs/api"
		if got := slices.Contains(argv, "--offline-scan"); got != want {
			t.Errorf("%s: --offline-scan present = %v, want %v: %v", key, got, want, argv)
		}
		// Flags before the target: Trivy takes the positional argument last.
		if last := argv[len(argv)-1]; last != "/work/api" && last != "/work/web" &&
			last != "acme/api:1" && last != "acme/web:1" {
			t.Errorf("%s: target is no longer last: %v", key, argv)
		}
	}
}

// `trivy config` runs no dependency analyzer and refuses --offline-scan, so the older command keeps
// the argv it had.
func TestTrivyConfigCommandTakesNoOfflineScan(t *testing.T) {
	was := sharedTrivyVersion.val
	t.Cleanup(func() { sharedTrivyVersion.val = was })
	sharedTrivyVersion.val = "trivy@0.52.0;db@2026-07-15T00:56:58Z"
	if argv := trivyConfigArgs("/src", nil); slices.Contains(argv, "--offline-scan") {
		t.Errorf("`trivy config` refuses --offline-scan: %v", argv)
	}
}

// --offline wins over resolveMaven: no Trivy run resolves, trivy-fs for api included.
func TestOfflineKeepsOfflineScanEverywhere(t *testing.T) {
	withFSTrivy(t)
	netpolicy.SetOffline(true)
	t.Cleanup(func() { netpolicy.SetOffline(false) })
	for key, argv := range trivyArgvs(t) {
		if !slices.Contains(argv, "--offline-scan") {
			t.Errorf("%s: offline argv lacks --offline-scan: %v", key, argv)
		}
		if first := slices.Index(argv, "--offline-scan"); slices.Contains(argv[first+1:], "--offline-scan") {
			t.Errorf("%s: --offline-scan passed twice: %v", key, argv)
		}
	}
	if resolvesPoms(apiCfg) {
		t.Error("resolvesPoms should be false offline, whatever the config says")
	}
}

// trivy-fs declares disclosure for a job whose block sets resolveMaven, and for no other.
func TestTrivyFSDisclosesOnlyWithResolveMaven(t *testing.T) {
	info := NewTrivyFS().Info()
	api := plugin.EffectsFor(info, apiCfg)
	if len(api) != 1 || api[0].Kind != plugin.EffectDisclosure || api[0].Option != resolveMavenKey {
		t.Errorf("api's trivy-fs job: effects = %+v, want one disclosure behind resolveMaven", api)
	}
	if web := plugin.EffectsFor(info, webCfg); len(web) != 0 {
		t.Errorf("web's trivy-fs job: effects = %+v, want none", web)
	}
	for _, s := range []plugin.Scanner{NewTrivyLicense(), NewTrivyConfig(), NewTrivy()} {
		if got := plugin.EffectsFor(s.Info(), apiCfg); len(got) != 0 {
			t.Errorf("%s never resolves, so declares nothing: %+v", s.Info().Name, got)
		}
	}
}

// A pom.xml as Trivy reads it with --offline-scan, the dependency it declares and nothing below
// it, and as it reads it resolved, with the dependency's own dependency.
const (
	pomOffline = `{"Results":[{"Target":"pom.xml","Class":"lang-pkgs","Type":"pom","Packages":[
 {"Name":"dev.example:app","Version":"1.0.0","Relationship":"root"},
 {"Name":"org.apache.commons:commons-text","Version":"1.9","Relationship":"direct"}]}]}`
	pomResolved = `{"Results":[{"Target":"pom.xml","Class":"lang-pkgs","Type":"pom","Packages":[
 {"Name":"dev.example:app","Version":"1.0.0","Relationship":"root"},
 {"Name":"org.apache.commons:commons-text","Version":"1.9","Relationship":"direct"},
 {"Name":"org.apache.commons:commons-lang3","Version":"3.11","Relationship":"indirect"}]}]}`
)

// trivyLike answers as Trivy does: the resolved tree without --offline-scan, the declared
// dependencies with it.
func trivyLike(_ context.Context, _ string, argv []string) ([]byte, error) {
	if slices.Contains(argv, "--offline-scan") {
		return []byte(pomOffline), nil
	}
	return []byte(pomResolved), nil
}

// pomInput is the pom.xml input a scan of one repository reported.
func pomInput(t *testing.T, s repoScanner, target plugin.RepositoryTarget, cfg plugin.Config) sarif.Input {
	t.Helper()
	rep, err := s.Scan(context.Background(), target, cfg)
	if err != nil {
		t.Fatalf("%s: %v", target.URL, err)
	}
	for _, in := range rep.Inputs {
		if in.Path == "pom.xml" {
			return in
		}
	}
	t.Fatalf("%s: no pom.xml input in %+v", target.URL, rep.Inputs)
	return sarif.Input{}
}

// A pom.xml read with --offline-scan is listed with what was not read; read with resolveMaven it is
// read in full. Two components in two repositories, so one job's setting cannot answer for the
// other's file.
func TestOfflineScannedPomIsReadInPart(t *testing.T) {
	pom := `<project><dependencies><dependency><groupId>org.apache.commons</groupId>` +
		`<artifactId>commons-text</artifactId><version>1.9</version></dependency></dependencies></project>`
	trees := map[string]string{
		apiRepo.URL: writeTree(t, map[string]string{"pom.xml": pom}),
		webRepo.URL: writeTree(t, map[string]string{"pom.xml": pom}),
	}
	fs, _ := NewTrivyFS().(repoScanner)
	fs.checkout = checkoutOf(trees)
	fs.run = trivyLike

	if in := pomInput(t, fs, apiRepo, apiCfg); in.Unread != "" || in.Packages != 3 {
		t.Errorf("api, resolved: pom.xml = %+v, want read in full", in)
	}
	if in := pomInput(t, fs, webRepo, webCfg); in.Unread != unresolvedPom || in.Packages != 2 {
		t.Errorf("web, offline-scan: pom.xml = %+v, want read in part with %q", in, unresolvedPom)
	}

	// trivy-license never resolves, so both components' poms carry the reason.
	lic, _ := NewTrivyLicense().(licenseScanner).repo.(repoScanner)
	lic.checkout = checkoutOf(trees)
	lic.run = trivyLike
	for _, tc := range []struct {
		target plugin.RepositoryTarget
		cfg    plugin.Config
	}{{apiRepo, apiCfg}, {webRepo, webCfg}} {
		if in := pomInput(t, lic, tc.target, tc.cfg); in.Unread != unresolvedPom {
			t.Errorf("trivy-license %s: pom.xml = %+v, want %q", tc.target.URL, in, unresolvedPom)
		}
	}
}

// Only a pom with a direct dependency and no indirect one is caveated: a pom declaring nothing has
// nothing to resolve, one with an indirect dependency was resolved from the local Maven repository,
// and a file of another ecosystem is not a pom.
func TestPomUnresolved(t *testing.T) {
	pkg := func(rel string) trivyPackage { return trivyPackage{Relationship: rel} }
	for name, tc := range map[string]struct {
		typ  string
		pkgs []trivyPackage
		want bool
	}{
		"declared only":    {"pom", []trivyPackage{pkg("root"), pkg("direct")}, true},
		"resolved locally": {"pom", []trivyPackage{pkg("root"), pkg("direct"), pkg("indirect")}, false},
		"no dependencies":  {"pom", []trivyPackage{pkg("root")}, false},
		"module only":      {"pom", []trivyPackage{pkg("root"), pkg("workspace")}, false},
		"another manifest": {"npm", []trivyPackage{pkg("root"), pkg("direct")}, false},
	} {
		if got := pomUnresolved(tc.typ, tc.pkgs); got != tc.want {
			t.Errorf("%s: pomUnresolved = %v, want %v", name, got, tc.want)
		}
	}
}
