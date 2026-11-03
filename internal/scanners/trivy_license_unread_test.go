package scanners

import (
	"context"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/controllers"
	"github.com/draugr-dev/draugr/internal/english"
	"github.com/draugr-dev/draugr/internal/git"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/report"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// The recorded output under testdata/unlicensed is Trivy 0.76.1, `trivy fs --scanners license
// --format json --offline-scan` and `trivy fs --scanners vuln --list-all-pkgs --format json
// --offline-scan`, over two repositories with nothing installed.
//
//   - `native` holds rs/codec/Cargo.lock and rs/store/Cargo.lock (gmp-mpfr-sys 1.6.4, LGPL-3.0+ on
//     crates.io, and libc), and rb/Gemfile.lock (gpgme 2.0.24, LGPL-2.1+ on rubygems.org).
//   - `mixed` holds cs/App/packages.lock.json and cs/Legacy/packages.config (MySql.Data 8.0.33,
//     GPL-2.0-only on nuget.org, among others), which Trivy reads as one format, nuget, and
//     php/composer.lock, whose entries carry their licenses.
//
// Trivy lists every package and gives a license to the composer ones alone. ArtifactName is cut to
// the repository's name.

// unlicensedRead returns one recorded output.
func unlicensedRead(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "unlicensed", name)) // #nosec G304 -- under testdata
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// runUnlicensed scans both components with trivy-license under licenses and trivy-fs under sca,
// each scanner replaying what Trivy wrote for the repository it was given.
func runUnlicensed(t *testing.T) engine.Result {
	t.Helper()
	dirs := map[string]string{"native": t.TempDir(), "mixed": t.TempDir()}
	repoOf := map[string]string{dirs["native"]: "native", dirs["mixed"]: "mixed"}
	checkout := func(_ context.Context, url, _ string, _ git.Scope) (git.Tree, func(), error) {
		return git.Tree{Dir: dirs[url]}, func() {}, nil
	}
	replay := func(kind string) func(context.Context, string, []string) ([]byte, []byte, error) {
		return func(_ context.Context, dir string, _ []string) ([]byte, []byte, error) {
			return unlicensedRead(t, repoOf[dir]+"."+kind+".json"), nil, nil
		}
	}

	// The process-wide version probe answers once and keeps the answer, and a later test reading it
	// would build another command line. A probe of this test's own fails it if anything asks.
	was := sharedTrivyVersion
	t.Cleanup(func() { sharedTrivyVersion = was })
	sharedTrivyVersion = &trivyVersionProbe{run: func(context.Context, []string) ([]byte, error) {
		t.Error("the scan asked Trivy its version, and the process keeps the answer")
		return nil, errors.New("no Trivy in this test")
	}}

	fs := NewTrivyFS().(repoScanner)
	fs.checkout, fs.prewarm, fs.cacheVersion, fs.dataState = checkout, nil, nil, nil
	fs.runLogged = trivyFSRun(replay("vuln"))

	// The repository mode alone, as the pom tests register it. The dispatcher's CacheVersion,
	// Prewarm and DataState call the process-wide Trivy, whatever the repository mode was given.
	lic := NewTrivyLicense().(licenseScanner).repo.(repoScanner)
	lic.checkout, lic.prewarm, lic.cacheVersion, lic.dataState = checkout, nil, nil, nil
	lic.runLogged = trivyFSRun(replay("license"))

	reg := engine.NewRegistry()
	reg.RegisterController(controllers.NewSCA())
	reg.RegisterController(controllers.NewLicenses())
	reg.RegisterScanner(fs)
	reg.RegisterScanner(lic)

	model := saga.Model{Config: saga.Config{Controls: map[string]saga.ControllerSettings{
		"sca": {"enabled": true}, "licenses": {"enabled": true},
	}}}
	for _, name := range []string{"native", "mixed"} {
		model.Components = append(model.Components,
			saga.Component{Name: name, Repositories: []saga.Repository{{URL: name}}})
	}
	res, err := engine.New(reg).Run(context.Background(), model)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// inputsOf is one component's coverage under one control.
func inputsOf(t *testing.T, res engine.Result, component, control string) engine.InputCoverage {
	t.Helper()
	for _, c := range res.Inputs {
		if c.Component == component && c.Control == control {
			return c
		}
	}
	t.Fatalf("no %s coverage for %s in %+v", control, component, res.Inputs)
	return engine.InputCoverage{}
}

// A lockfile whose packages Trivy read with no license for any of them is listed under licenses
// with the count, with Trivy's name for its format, and with the act that fills the cache Trivy
// reads where there is one. A composer.lock, whose entries carry their licenses, is not listed, and
// sca reads every file in full. Two components in two repositories, so neither file's row can come
// from the other's.
func TestLockfileWithNoLicenseIsReadInPartForLicenses(t *testing.T) {
	res := runUnlicensed(t)
	const dotnet = ", run dotnet restore"
	for _, tc := range []struct {
		component string
		unread    []engine.UnreadInput
		read      int
	}{
		{"native", []engine.UnreadInput{
			{Repository: "native", Path: "rb/Gemfile.lock", Reason: "records no licenses for 2 packages", Kind: "bundler"},
			{Repository: "native", Path: "rs/codec/Cargo.lock", Reason: "records no licenses for 3 packages", Kind: "cargo"},
			{Repository: "native", Path: "rs/store/Cargo.lock", Reason: "records no licenses for 2 packages", Kind: "cargo"},
		}, 3},
		{"mixed", []engine.UnreadInput{
			{Repository: "mixed", Path: "cs/App/packages.lock.json", Reason: "licenses of 2 packages not read" + dotnet, Kind: "nuget"},
			{Repository: "mixed", Path: "cs/Legacy/packages.config", Reason: "licenses of 3 packages not read" + dotnet, Kind: "nuget"},
		}, 3},
	} {
		lic := inputsOf(t, res, tc.component, "licenses")
		if !reflect.DeepEqual(lic.Unread, tc.unread) {
			t.Errorf("%s licenses: unread = %+v, want %+v", tc.component, lic.Unread, tc.unread)
		}
		// Read in part: the packages were read, so each file is counted as read as well.
		if lic.Read != tc.read {
			t.Errorf("%s licenses: read = %d, want %d", tc.component, lic.Read, tc.read)
		}
		sca := inputsOf(t, res, tc.component, "sca")
		if len(sca.Unread) != 0 || sca.Read != tc.read {
			t.Errorf("%s sca: read %d, unread %+v, want %d read in full", tc.component, sca.Read, sca.Unread, tc.read)
		}
	}

	// The composer.lock's licenses were checked: its copyleft package is reported.
	var found []string
	for _, r := range res.Controls["licenses"].Report.Results {
		found = append(found, r.Component+" "+r.RuleID)
	}
	if want := []string{"mixed license/LGPL-2.1-only/phpmailer/phpmailer"}; !slices.Equal(found, want) {
		t.Errorf("licenses findings = %v, want %v", found, want)
	}
}

// The console folds a component's files of one format into one caveat row, counting the files in
// What and the packages in Why: two Cargo.lock files by their shared name, a packages.lock.json and
// a packages.config by the format they share. A format with one file keeps its path. The licenses
// row counts every file it did not read, and --evidence names the files a folded row stands for.
func TestConsoleFoldsUnreadLicensesByComponentAndFormat(t *testing.T) {
	res := runUnlicensed(t)
	d := report.Data{Project: "p", Run: res, Verdict: norn.Result{Verdict: norn.Pass, Controls: []norn.ControlOutcome{
		{Control: "licenses", Verdict: norn.Pass}, {Control: "sca", Verdict: norn.Pass},
	}}}
	console := renderFormat(t, "console", d)
	for _, row := range []string{
		`^  licenses\s+pass\s+.* · 5 files unread$`,
		`^  sca\s+pass\s+no findings$`,
		`^CAVEATS\s+.* · --evidence names each file$`,
		`^  mixed\s+NuGet files ×2\s+unread-files\s+licenses of 5 packages not read, run dotnet restore \(licenses\)$`,
		`^  native\s+rb/Gemfile\.lock\s+unread-files\s+records no licenses for 2 packages \(licenses\)$`,
		`^  native\s+Cargo\.lock ×2\s+unread-files\s+records no licenses for 5 packages \(licenses\)$`,
	} {
		if !regexp.MustCompile(`(?m)` + row).MatchString(console) {
			t.Errorf("console has no line matching %s:\n%s", row, console)
		}
	}
	folded := []string{"rs/codec/Cargo.lock", "rs/store/Cargo.lock", "cs/App/packages.lock.json", "cs/Legacy/packages.config"}
	for _, path := range folded {
		if strings.Contains(console, path) {
			t.Errorf("the default view names %s, which a folded row stands for:\n%s", path, console)
		}
	}

	d.Evidence = true
	evidence := renderFormat(t, "console", d)
	for _, path := range folded {
		if !strings.Contains(evidence, path) {
			t.Errorf("--evidence does not name %s:\n%s", path, evidence)
		}
	}
	if !regexp.MustCompile(`(?m)^  unread\s+licenses · mixed · cs/App/packages\.lock\.json · `).MatchString(evidence) {
		t.Errorf("--evidence has no unread row for cs/App/packages.lock.json:\n%s", evidence)
	}
}

// licenseUnread over the shapes around the rule.
func TestLicenseUnread(t *testing.T) {
	pkg := func(rel string, licenses ...string) trivyPackage {
		return trivyPackage{Relationship: rel, Licenses: licenses}
	}
	for name, tc := range map[string]struct {
		typ  string
		pkgs []trivyPackage
		want string
	}{
		"none carries one":   {"cargo", []trivyPackage{pkg(""), pkg("")}, "records no licenses for 2 packages"},
		"one carries one":    {"npm", []trivyPackage{pkg("direct"), pkg("indirect", "MIT")}, ""},
		"all carry one":      {"composer", []trivyPackage{pkg("", "MIT")}, ""},
		"go module cache":    {"gomod", []trivyPackage{pkg("root"), pkg("direct")}, "license of 1 package not read, run go mod download"},
		"nuget packages":     {"nuget", []trivyPackage{pkg("direct"), pkg("indirect")}, "licenses of 2 packages not read, run dotnet restore"},
		"only the project":   {"gomod", []trivyPackage{pkg("root", "MIT")}, ""},
		"no packages":        {"cargo", nil, ""},
		"workspace licensed": {"yarn", []trivyPackage{pkg("root", "MIT"), pkg("workspace", "MIT"), pkg("")}, "records no license for 1 package"},
	} {
		got, ok := licenseUnread(tc.typ, tc.pkgs)
		if got != tc.want || ok != (tc.want != "") {
			t.Errorf("%s: licenseUnread = %q, %v, want %q", name, got, ok, tc.want)
		}
	}
}

// Every reason fits the console's caveat column with its control named after it.
func TestLicenseReasonsFitTheCaveatColumn(t *testing.T) {
	pkgs := make([]trivyPackage, 99999)
	for _, typ := range append(slices.Collect(maps.Keys(unlicensedRemedy)), "cargo") {
		reason, _ := licenseUnread(typ, pkgs)
		if !strings.Contains(reason, english.Count(99999, "package")) {
			t.Fatalf("%s: reason %q", typ, reason)
		}
		if n := len(reason + " (licenses)"); n > 80 {
			t.Errorf("%q with its control is %d characters, over 80", reason, n)
		}
	}
}
