package scanners

import (
	"context"
	"encoding/json"
	"slices"
	"testing"

	"github.com/draugr-dev/draugr/internal/english"
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

// unparsedLockLog is the debug line Trivy logs for a bun.lock it failed to parse, which the scan
// reads beside the report.
const unparsedLockLog = "2026-11-02T04:43:38-06:00\tDEBUG\tWalk error\tfile_path=\"bun.lock\" err=\"parse error: " +
	"failed to parse bun.lock: unexpected end of JSON input\"\n"

// trivyLike answers as Trivy does: the resolved tree without --offline-scan, the declared
// dependencies with it, and in either case a log naming a bun.lock it could not parse.
func trivyLike(_ context.Context, _ string, argv []string) ([]byte, []byte, error) {
	if slices.Contains(argv, "--offline-scan") {
		return []byte(pomOffline), []byte(unparsedLockLog), nil
	}
	return []byte(pomResolved), []byte(unparsedLockLog), nil
}

// lockInput is the bun.lock input a scan of one repository reported.
func lockInput(t *testing.T, s repoScanner, target plugin.RepositoryTarget, cfg plugin.Config) sarif.Input {
	t.Helper()
	rep, err := s.Scan(context.Background(), target, cfg)
	if err != nil {
		t.Fatalf("%s: %v", target.URL, err)
	}
	for _, in := range rep.Inputs {
		if in.Path == "bun.lock" {
			return in
		}
	}
	t.Fatalf("%s: no bun.lock input in %+v", target.URL, rep.Inputs)
	return sarif.Input{}
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
	lock := `{"lockfileVersion": 1, "packages": {`
	trees := map[string]string{
		apiRepo.URL: writeTree(t, map[string]string{"pom.xml": pom, "bun.lock": lock}),
		webRepo.URL: writeTree(t, map[string]string{"pom.xml": pom, "bun.lock": lock}),
	}
	// The pom's reason and the unparsed lockfile's are two files' answers from one run, and both
	// are reported.
	const notParsed = "not parsed: unexpected end of JSON input"
	fs, _ := NewTrivyFS().(repoScanner)
	fs.checkout = checkoutOf(trees)
	fs.runLogged = trivyFSRun(trivyLike)

	if in := pomInput(t, fs, apiRepo, apiCfg); in.Unread != "" || in.Packages != 3 {
		t.Errorf("api, resolved: pom.xml = %+v, want read in full", in)
	}
	if in := pomInput(t, fs, webRepo, webCfg); in.Unread != unresolvedPom || in.Packages != 2 {
		t.Errorf("web, offline-scan: pom.xml = %+v, want read in part with %q", in, unresolvedPom)
	}
	for _, tc := range []struct {
		target plugin.RepositoryTarget
		cfg    plugin.Config
	}{{apiRepo, apiCfg}, {webRepo, webCfg}} {
		if in := lockInput(t, fs, tc.target, tc.cfg); in.Unread != notParsed {
			t.Errorf("trivy-fs %s: bun.lock = %+v, want %q", tc.target.URL, in, notParsed)
		}
	}

	// trivy-license never resolves, so both components' poms carry the reason.
	lic, _ := NewTrivyLicense().(licenseScanner).repo.(repoScanner)
	lic.checkout = checkoutOf(trees)
	lic.runLogged = trivyFSRun(trivyLike)
	for _, tc := range []struct {
		target plugin.RepositoryTarget
		cfg    plugin.Config
	}{{apiRepo, apiCfg}, {webRepo, webCfg}} {
		if in := pomInput(t, lic, tc.target, tc.cfg); in.Unread != unresolvedPom {
			t.Errorf("trivy-license %s: pom.xml = %+v, want %q", tc.target.URL, in, unresolvedPom)
		}
		if in := lockInput(t, lic, tc.target, tc.cfg); in.Unread != notParsed {
			t.Errorf("trivy-license %s: bun.lock = %+v, want %q", tc.target.URL, in, notParsed)
		}
	}
}

// The package lists Trivy 0.76.1 reports for a pom.xml under --offline-scan with an empty local
// Maven repository, one per way a direct dependency gets its version. A dependency Trivy could not
// version is listed with none.
const (
	// A remote <parent> (spring-boot-starter-parent) and two dependencies taking their versions
	// from it.
	pomRemoteParent = `{"Results":[{"Target":"pom.xml","Class":"lang-pkgs","Type":"pom","Packages":[
 {"Name":"dev.example:remote-parent","Version":"1.0.0","Relationship":"root"},
 {"Name":"com.fasterxml.jackson.core:jackson-databind","Relationship":"direct"},
 {"Name":"org.springframework.boot:spring-boot-starter-web","Relationship":"direct"}]}]}`
	// One pinned dependency and one taking its version from the remote parent.
	pomMixed = `{"Results":[{"Target":"pom.xml","Class":"lang-pkgs","Type":"pom","Packages":[
 {"Name":"dev.example:mixed","Version":"1.0.0","Relationship":"root"},
 {"Name":"com.fasterxml.jackson.core:jackson-databind","Relationship":"direct"},
 {"Name":"org.apache.commons:commons-text","Version":"1.9","Relationship":"direct"}]}]}`
	// A version from a property the pom defines itself.
	pomLocalProperty = `{"Results":[{"Target":"pom.xml","Class":"lang-pkgs","Type":"pom","Packages":[
 {"Name":"dev.example:local-property","Version":"1.0.0","Relationship":"root"},
 {"Name":"org.apache.commons:commons-text","Version":"1.9","Relationship":"direct"}]}]}`
)

// A pom whose direct dependencies took their versions from a remote parent, a BOM or a property one
// of them defines is listed with a count of the versions not resolved; one whose versions are all
// in the pom is listed for its transitive dependencies alone. Two components in two repositories,
// one per shape, so neither file's reason can come from the other's.
func TestPomWithUnresolvedVersionsIsReadInPart(t *testing.T) {
	trees := map[string]string{
		apiRepo.URL: writeTree(t, map[string]string{"pom.xml": "<project/>"}),
		webRepo.URL: writeTree(t, map[string]string{"pom.xml": "<project/>"}),
	}
	answers := map[string]string{apiRepo.URL: pomRemoteParent, webRepo.URL: pomMixed}
	dirs := map[string]string{trees[apiRepo.URL]: apiRepo.URL, trees[webRepo.URL]: webRepo.URL}
	run := trivyFSRun(func(_ context.Context, dir string, _ []string) ([]byte, []byte, error) {
		return []byte(answers[dirs[dir]]), nil, nil
	})
	fs, _ := NewTrivyFS().(repoScanner)
	fs.checkout, fs.runLogged = checkoutOf(trees), run
	lic, _ := NewTrivyLicense().(licenseScanner).repo.(repoScanner)
	lic.checkout, lic.runLogged = checkoutOf(trees), run

	for _, s := range []repoScanner{fs, lic} {
		for _, tc := range []struct {
			target plugin.RepositoryTarget
			cfg    plugin.Config
			want   string
		}{
			// resolveMaven does not clear it: no repository answered for the version.
			{apiRepo, apiCfg, "2 dependency versions not resolved, run mvn dependency:resolve"},
			{webRepo, webCfg, "1 dependency version not resolved, run mvn dependency:resolve"},
		} {
			if in := pomInput(t, s, tc.target, tc.cfg); in.Unread != tc.want {
				t.Errorf("%s %s: pom.xml = %+v, want %q", s.info.Name, tc.target.URL, in, tc.want)
			}
		}
	}
}

// Every pom reason fits the console's caveat column with both controls named after it.
func TestPomReasonsFitTheCaveatColumn(t *testing.T) {
	for _, reason := range []string{unresolvedPom, english.Count(999, "dependency version") + unversionedPom} {
		if n := len(reason + " (licenses, sca)"); n > 80 {
			t.Errorf("%q with its controls is %d characters, over 80", reason, n)
		}
	}
}

// pomUnread over Trivy's own package lists and the shapes around them.
func TestPomUnread(t *testing.T) {
	pkgsOf := func(doc string) []trivyPackage {
		var d trivyVulnDoc
		if err := json.Unmarshal([]byte(doc), &d); err != nil {
			t.Fatal(err)
		}
		return d.Results[0].Packages
	}
	pkg := func(rel, version string) trivyPackage { return trivyPackage{Relationship: rel, Version: version} }
	const versions = "dependency version"
	for name, tc := range map[string]struct {
		typ         string
		pkgs        []trivyPackage
		offlineScan bool
		want        string
	}{
		"remote parent":            {"pom", pkgsOf(pomRemoteParent), true, "2 " + versions + "s" + unversionedPom},
		"remote parent, resolved":  {"pom", pkgsOf(pomRemoteParent), false, "2 " + versions + "s" + unversionedPom},
		"pinned and parent":        {"pom", pkgsOf(pomMixed), true, "1 " + versions + unversionedPom},
		"local property":           {"pom", pkgsOf(pomLocalProperty), true, unresolvedPom},
		"local property, resolved": {"pom", pkgsOf(pomLocalProperty), false, ""},
		"unexpanded property":      {"pom", []trivyPackage{pkg("root", "1"), pkg("direct", "${jackson.version}")}, true, "1 " + versions + unversionedPom},
		"resolved locally":         {"pom", []trivyPackage{pkg("root", "1"), pkg("direct", "1.9"), pkg("indirect", "3.11")}, true, ""},
		"no dependencies":          {"pom", []trivyPackage{pkg("root", "1")}, true, ""},
		"module only":              {"pom", []trivyPackage{pkg("root", "1"), pkg("workspace", "1")}, true, ""},
		"another manifest":         {"npm", []trivyPackage{pkg("root", "1"), pkg("direct", "")}, true, ""},
	} {
		got, ok := pomUnread(tc.typ, tc.pkgs, tc.offlineScan)
		if got != tc.want || ok != (tc.want != "") {
			t.Errorf("%s: pomUnread = %q, %v, want %q", name, got, ok, tc.want)
		}
	}
}
