package scanners

import (
	"context"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// onHost runs the test as if the machine were p.
func onHost(t *testing.T, p goPlatform) {
	t.Helper()
	was := hostGoPlatform
	hostGoPlatform = p
	t.Cleanup(func() { hostGoPlatform = was })
}

var (
	linuxHost  = goPlatform{"linux", "amd64"}
	darwinHost = goPlatform{"darwin", "arm64"}
)

// platformModule is a module with code for every kind of platform: a file every platform builds, a
// Windows file calling into a dependency beside its stub for the rest, a Linux file, a plan9 file,
// a file behind a tag that is not a platform, and Windows files `./...` never builds as the
// module's: a test, one under testdata and one in a nested module.
var platformModule = map[string]string{
	"go.mod":                      "module example.com/app\n\ngo 1.21\n",
	"main.go":                     goMain,
	"winapi/call_windows.go":      "package winapi\n\nimport \"golang.org/x/sys/windows\"\n\nvar _ = windows.GetCurrentProcessId\n",
	"winapi/call_other.go":        "//go:build !windows\n\npackage winapi\n",
	"proc/proc_linux.go":          "package proc\n",
	"plan/note_plan9.go":          "package plan\n",
	"plan/note.go":                "//go:build !plan9\n\npackage plan\n",
	"slow/slow.go":                "//go:build integration\n\npackage slow\n",
	"winapi/call_windows_test.go": "package winapi\n",
	"testdata/x_windows.go":       "package x\n",
	"nested/go.mod":               "module example.com/nested\n\ngo 1.21\n",
	"nested/n_windows.go":         "package nested\n",
}

func TestGoModulePlatformsOnLinux(t *testing.T) {
	dir := writeTree(t, platformModule)
	got := goModulePlatforms(dir, nil, linuxHost)
	if len(got.Builds) != 1 || got.Builds[0].Platform != (goPlatform{"windows", "amd64"}) {
		t.Fatalf("builds = %+v, want windows/amd64 alone: darwin builds nothing Linux does not", got.Builds)
	}
	win := got.Builds[0]
	if !win.Imports {
		t.Error("the Windows file imports golang.org/x/sys/windows, and Imports is false")
	}
	if want := []string{filepath.Join(dir, "winapi")}; !slices.Equal(win.Dirs, want) {
		t.Errorf("dirs = %v, want %v", win.Dirs, want)
	}
	if len(win.Files) != 1 || !win.Files[filepath.Join(dir, "winapi", "call_windows.go")] {
		t.Errorf("files = %v, want call_windows.go alone: not the test, testdata or the nested module", win.Files)
	}
	if want := []string{filepath.Join(dir, "plan", "note_plan9.go")}; !slices.Equal(got.Unbuilt, want) {
		t.Errorf("unbuilt = %v, want %v: the integration file is behind a tag, not a platform", got.Unbuilt, want)
	}
}

// On a Mac the platforms beside it are Linux and Windows: the Linux file is read by a run for
// linux/amd64, and darwin's own build is the host's.
func TestGoModulePlatformsOnAMac(t *testing.T) {
	dir := writeTree(t, platformModule)
	got := goModulePlatforms(dir, nil, darwinHost)
	var names []string
	for _, b := range got.Builds {
		names = append(names, b.Platform.String())
	}
	if !slices.Equal(names, []string{"linux/amd64", "windows/amd64"}) {
		t.Fatalf("builds = %v, want linux/amd64 and windows/amd64", names)
	}
	if linux := got.Builds[0]; linux.Imports || !linux.Files[filepath.Join(dir, "proc", "proc_linux.go")] {
		t.Errorf("linux build = %+v, want proc_linux.go, importing only the standard library", linux)
	}
}

func TestImportsBeyondStd(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"std.go":    "package p\n\nimport (\n\t\"os\"\n\t\"C\"\n)\n",
		"dep.go":    "package p\n\nimport \"github.com/x/y\"\n",
		"broken.go": "package\n",
	})
	if importsBeyondStd(filepath.Join(dir, "std.go")) {
		t.Error("os and C are the standard library's")
	}
	if !importsBeyondStd(filepath.Join(dir, "dep.go")) {
		t.Error("github.com/x/y is not the standard library's")
	}
	if !importsBeyondStd(filepath.Join(dir, "broken.go")) {
		t.Error("a file that does not parse is counted, so govulncheck runs and says why")
	}
}

// A run planned for another platform has the marker taken off and GOOS, GOARCH and CGO_ENABLED set;
// a run for the host is passed as it is.
func TestOnGoPlatform(t *testing.T) {
	var gotArgv, gotEnv []string
	var gotPlatform goPlatform
	var marked bool
	run := onGoPlatform(func(ctx context.Context, _ string, argv, env []string) ([]byte, error) {
		gotArgv, gotEnv = argv, env
		gotPlatform, marked = runGoPlatform(ctx)
		return nil, nil
	})
	argv := withGoPlatform([]string{"gosec", "-fmt", "sarif", "./..."}, goPlatform{"windows", "amd64"})
	if _, err := run(context.Background(), "", argv, []string{"GOWORK=off"}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(gotArgv, []string{"gosec", "-fmt", "sarif", "./..."}) {
		t.Errorf("argv = %v, want the marker taken off", gotArgv)
	}
	if !slices.Equal(gotEnv, []string{"GOWORK=off", "GOOS=windows", "GOARCH=amd64", "CGO_ENABLED=0"}) {
		t.Errorf("env = %v", gotEnv)
	}
	if !marked || gotPlatform.String() != "windows/amd64" {
		t.Errorf("platform in context = %v, %v", gotPlatform, marked)
	}
	if _, err := run(context.Background(), "", []string{"gosec", "./..."}, nil); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(gotArgv, []string{"gosec", "./..."}) || len(gotEnv) != 0 || marked {
		t.Errorf("a host run became argv %v, env %v, marked %v", gotArgv, gotEnv, marked)
	}
}

func TestGosecArgsAddARunForEachOtherPlatform(t *testing.T) {
	onHost(t, linuxHost)
	dir := writeTree(t, platformModule)
	got := gosecArgs(dir, nil)
	var platforms []string
	for _, argv := range got {
		p, ok := goPlatformOf(argv)
		if !ok {
			platforms = append(platforms, "host")
			continue
		}
		platforms = append(platforms, p.String())
	}
	if !slices.Equal(platforms, []string{"host", "windows/amd64", "host", "windows/amd64"}) {
		t.Errorf("runs = %v, want each module for the host and windows/amd64", platforms)
	}
}

// A run for Windows reads only the packages holding Windows code; it finds none where the go
// command lists other packages only.
func TestOnlyPlatformPackages(t *testing.T) {
	onHost(t, linuxHost)
	dir := writeTree(t, platformModule)
	pkgs := []string{dir, filepath.Join(dir, "winapi"), filepath.Join(dir, "proc")}
	got := onlyPlatformPackages(pkgs, dir, nil, goPlatform{"windows", "amd64"})
	if want := []string{filepath.Join(dir, "winapi")}; !slices.Equal(got, want) {
		t.Errorf("packages = %v, want %v", got, want)
	}
	if got := onlyPlatformPackages(pkgs, dir, nil, goPlatform{"darwin", "arm64"}); len(got) != 0 {
		t.Errorf("darwin builds nothing Linux does not, and kept %v", got)
	}
}

// The Windows run's findings in code the host builds are the host run's to report, and only its
// finding in the Windows file is kept, naming the platform. The plan9 file no run builds is named
// as a file gosec did not analyze.
func TestParseGosecKeepsAPlatformRunsFindingsInItsOwnCode(t *testing.T) {
	onHost(t, linuxHost)
	dir := writeTree(t, platformModule)
	doc := func(results ...string) string {
		return `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"gosec","rules":[{"id":"G204"}]}},"results":[` +
			strings.Join(results, ",") + `]}]}` + "\n"
	}
	result := func(uri string, line int) string {
		return `{"ruleId":"G204","message":{"text":"m"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"` +
			uri + `"},"region":{"startLine":` + strconv.Itoa(line) + `}}}]}`
	}
	// The Windows run also reports a finding in main.go the host's run did not, which is code the
	// host builds and so not the Windows run's to report.
	out := doc(result("main.go", 3)) + doc(result("main.go", 3), result("main.go", 9), result("winapi/call_windows.go", 3)) + doc() + doc()
	rep, err := parseGosec([]byte(out), dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range rep.Results {
		got = append(got, r.Location.URI+" "+strings.Join(r.Platforms, ","))
	}
	if !slices.Equal(got, []string{"main.go ", "winapi/call_windows.go windows/amd64"}) {
		t.Errorf("results = %q", got)
	}
	if len(rep.Inputs) != 1 || rep.Inputs[0].Path != "plan/note_plan9.go" || !rep.Inputs[0].Analysis ||
		rep.Inputs[0].Unread != unbuiltReason("gosec") {
		t.Errorf("inputs = %+v, want the plan9 file named", rep.Inputs)
	}
	if unbuiltReason("gosec") != "gosec: not built for linux/amd64, windows/amd64, darwin/arm64" {
		t.Errorf("reason = %q, want the platforms read named", unbuiltReason("gosec"))
	}

	// A report missing for the Windows run is refused, and the error counts it.
	if _, err := parseGosec([]byte(doc()+doc()), dir, nil); err == nil ||
		!strings.Contains(err.Error(), "2 reports for 2 modules and 2 runs for another platform") {
		t.Errorf("err = %v", err)
	}
}

// A module whose every package is Windows code holds no package for the host's run, and that is not
// a module gosec did not analyze: the Windows run reads it. A Windows run that failed is named with
// its platform.
func TestParseGosecAModuleOfOnlyAnotherPlatformsCode(t *testing.T) {
	onHost(t, linuxHost)
	dir := writeTree(t, map[string]string{
		"go.mod":         "module example.com/win\n\ngo 1.21\n",
		"run_windows.go": "package win\n",
	})
	noPackages := `{"draugrModule":{"goMod":"go.mod","noPackages":true}}` + "\n"
	failed := `{"draugrModule":{"goMod":"go.mod","failed":"exit status 1","platform":"windows/amd64"}}` + "\n"
	rep, err := parseGosec([]byte(noPackages+failed), dir, nil)
	if len(rep.Inputs) != 0 {
		t.Errorf("inputs = %+v, want none: the Windows run read the module", rep.Inputs)
	}
	if err == nil || !strings.Contains(err.Error(), "over go.mod for windows/amd64: exit status 1") {
		t.Errorf("err = %v, want the Windows run's failure named", err)
	}
}

// Two platform runs that found one finding in a file both build name both platforms on it.
func TestJoinPlatforms(t *testing.T) {
	r := sarif.Result{Tool: "gosec", RuleID: "G204", Location: sarif.Location{URI: "a.go", StartLine: 3}}
	win, mac := r, r
	win.Platforms, mac.Platforms = []string{"windows/amd64"}, []string{"darwin/arm64"}
	got := sarif.Merge(joinPlatforms([]sarif.Report{{Results: []sarif.Result{win}}, {Results: []sarif.Result{mac}}})...)
	if len(got.Results) != 1 || !slices.Equal(got.Results[0].Platforms, []string{"windows/amd64", "darwin/arm64"}) {
		t.Errorf("results = %+v", got.Results)
	}
}

// A Windows file importing a dependency gets a govulncheck run for windows/amd64 from its package,
// and a call into the vulnerable function from that file makes the finding reachable where the
// host's run said unreachable, naming the platform.
func TestGovulncheckRunsForAnotherPlatformsDependencyCalls(t *testing.T) {
	onHost(t, linuxHost)
	dir := writeTree(t, platformModule)
	argvs := govulncheckArgs(dir, nil, plugin.Config{})
	// The nested module's Windows file imports nothing, so it gets no run, and its host build is empty.
	if len(argvs) != 2 {
		t.Fatalf("runs = %v, want the module for the host and for windows/amd64", argvs)
	}
	win := argvs[1]
	if p, ok := goPlatformOf(win); !ok || p.String() != "windows/amd64" || win[len(win)-1] != "./winapi" {
		t.Errorf("windows run = %v, want windows/amd64 from ./winapi", win)
	}

	run := func(called bool) string {
		trace := `[{"module":"golang.org/x/sys","version":"v0.1.0"}]`
		if called {
			trace = `[{"module":"golang.org/x/sys","version":"v0.1.0","package":"golang.org/x/sys/windows","function":"GetCurrentProcessId"},` +
				`{"module":"example.com/app","package":"example.com/app/winapi","function":"init"}]`
		}
		return `{"config":{"scan_level":"symbol"}}
{"SBOM":{"modules":[{"path":"example.com/app"},{"path":"golang.org/x/sys","version":"v0.1.0"}],"roots":["example.com/app"]}}
{"osv":{"id":"GO-2022-0001","aliases":["CVE-2022-0001"]}}
{"finding":{"osv":"GO-2022-0001","fixed_version":"v0.2.0","trace":` + trace + `}}
`
	}
	rep, err := parseGovulncheck([]byte(run(false)+run(true)), dir, plugin.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 1 {
		t.Fatalf("results = %+v, want one, for the CVE the advisory names", rep.Results)
	}
	for _, r := range rep.Results {
		if r.Reachability.State != sarif.ReachabilityReachable || !slices.Equal(r.Reachability.Platforms, []string{"windows/amd64"}) {
			t.Errorf("%s: reachability = %+v, want reachable on windows/amd64", r.RuleID, r.Reachability)
		}
	}
	for _, in := range rep.Inputs {
		if in.Path == "go.mod" {
			t.Errorf("a module whose Windows code imports a dependency was named as unchecked: %+v", in)
		}
	}
}

// A Windows file importing only the standard library gets no govulncheck run, and its module's
// go.mod is named as code govulncheck did not check for the standard library's advisories.
func TestGovulncheckNamesAnotherPlatformsStdlibOnlyCode(t *testing.T) {
	onHost(t, linuxHost)
	dir := writeTree(t, map[string]string{
		"go.mod":                "module example.com/app\n\ngo 1.21\n",
		"main.go":               goMain,
		"proc/alive_windows.go": "package proc\n\nimport \"os\"\n\nvar _ = os.FindProcess\n",
		"proc/alive_other.go":   "//go:build !windows\n\npackage proc\n",
		"proc/group_windows.go": "package proc\n\nimport \"os/exec\"\n\nvar _ exec.Cmd\n",
	})
	argvs := govulncheckArgs(dir, nil, plugin.Config{})
	if len(argvs) != 1 {
		t.Fatalf("runs = %v, want the host's alone", argvs)
	}
	if _, ok := goPlatformOf(argvs[0]); ok {
		t.Fatalf("run = %v, want the host's", argvs[0])
	}
	rep, err := parseGovulncheck([]byte(`{"config":{"scan_level":"symbol"}}`+"\n"), dir, plugin.Config{})
	if err != nil {
		t.Fatal(err)
	}
	want := "Go standard-library advisories not checked for windows/amd64-only code · 2 files"
	if len(rep.Inputs) != 1 || rep.Inputs[0].Path != "go.mod" || rep.Inputs[0].Unread != want || !rep.Inputs[0].Analysis {
		t.Errorf("inputs = %+v, want go.mod with %q", rep.Inputs, want)
	}
}

// A Windows run that could not load names its platform in the reason, and a missing run is counted
// with the platform runs planned.
func TestParseGovulncheckAPlatformRunThatDidNotLoad(t *testing.T) {
	onHost(t, linuxHost)
	dir := writeTree(t, platformModule)
	unloaded := `{"draugrUnloaded":{"goMod":"go.mod","reason":"govulncheck: undefined: x","platform":"windows/amd64"}}` + "\n"
	host := `{"config":{"scan_level":"symbol"}}` + "\n"
	rep, err := parseGovulncheck([]byte(host+unloaded), dir, plugin.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Inputs) == 0 || rep.Inputs[0].Path != "go.mod" || rep.Inputs[0].Unread != "govulncheck for windows/amd64: undefined: x" {
		t.Errorf("inputs = %+v", rep.Inputs)
	}
	if _, err := parseGovulncheck([]byte(host), dir, plugin.Config{}); err == nil ||
		!strings.Contains(err.Error(), "1 runs for 1 module and 1 run for another platform") {
		t.Errorf("err = %v", err)
	}
	if _, err := parseGovulncheck(nil, dir, plugin.Config{}); err == nil ||
		!strings.Contains(err.Error(), "0 runs for 1 module and 1 run for another platform") {
		t.Errorf("err = %v", err)
	}
}

func TestWithPlatformVerdicts(t *testing.T) {
	result := func(state sarif.ReachabilityState, platforms ...string) sarif.Result {
		return sarif.Result{RuleID: "CVE-1", Location: sarif.Location{URI: "go.mod"}, Package: &sarif.Package{Name: "m"},
			Reachability: &sarif.Reachability{State: state, Platforms: platforms}}
	}
	reachable, unreachable := sarif.ReachabilityReachable, sarif.ReachabilityUnreachable

	// The host's reachable verdict stands over a platform's.
	got := withPlatformVerdicts([]sarif.Result{result(reachable)}, []sarif.Result{result(reachable, "windows/amd64")})
	if len(got) != 1 || len(got[0].Reachability.Platforms) != 0 {
		t.Errorf("host reachable: %+v", got[0].Reachability)
	}
	// A platform's unreachable verdict changes nothing.
	got = withPlatformVerdicts([]sarif.Result{result(unreachable)}, []sarif.Result{result(unreachable, "windows/amd64")})
	if len(got) != 1 || got[0].Reachability.State != unreachable || len(got[0].Reachability.Platforms) != 0 {
		t.Errorf("both unreachable: %+v", got[0].Reachability)
	}
	// Reachable on two platforms beside the host names both.
	got = withPlatformVerdicts([]sarif.Result{result(unreachable)},
		[]sarif.Result{result(reachable, "windows/amd64"), result(reachable, "darwin/arm64")})
	if len(got) != 1 || !slices.Equal(got[0].Reachability.Platforms, []string{"windows/amd64", "darwin/arm64"}) {
		t.Errorf("two platforms: %+v", got[0].Reachability)
	}
	// A finding the host's run did not report takes the platform's verdict.
	other := result(unreachable, "windows/amd64")
	other.RuleID = "CVE-2"
	if got = withPlatformVerdicts(nil, []sarif.Result{other}); len(got) != 1 || got[0].RuleID != "CVE-2" {
		t.Errorf("platform only: %+v", got)
	}
}
