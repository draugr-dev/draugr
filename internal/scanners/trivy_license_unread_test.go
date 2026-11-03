package scanners

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/controllers"
	"github.com/draugr-dev/draugr/internal/english"
	"github.com/draugr-dev/draugr/internal/git"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// The recorded output under testdata/unlicensed is Trivy 0.76.1, `trivy fs --scanners license
// --format json --offline-scan` and `trivy fs --scanners vuln --list-all-pkgs --format json
// --offline-scan`, over two repositories with nothing installed. `native` holds rs/Cargo.lock
// (gmp-mpfr-sys 1.6.4, LGPL-3.0+ on crates.io) and rb/Gemfile.lock (gpgme 2.0.24, LGPL-2.1+ on
// rubygems.org); `mixed` holds cs/packages.lock.json (MySql.Data 8.0.33, GPL-2.0-only on
// nuget.org) and php/composer.lock, whose entries carry their licenses. Trivy lists every package
// and gives a license to the composer ones alone. ArtifactName is cut to the repository's name.

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

	fs := NewTrivyFS().(repoScanner)
	fs.checkout, fs.prewarm, fs.cacheVersion, fs.dataState = checkout, nil, nil, nil
	fs.runLogged = trivyFSRun(replay("vuln"))

	whole := NewTrivyLicense().(licenseScanner)
	lic := whole.repo.(repoScanner)
	lic.checkout, lic.prewarm, lic.cacheVersion, lic.dataState = checkout, nil, nil, nil
	lic.runLogged = trivyFSRun(replay("license"))
	whole.repo = lic

	reg := engine.NewRegistry()
	reg.RegisterController(controllers.NewSCA())
	reg.RegisterController(controllers.NewLicenses())
	reg.RegisterScanner(fs)
	reg.RegisterScanner(whole)

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
// with the count, and with the act that fills the cache Trivy reads where there is one. A
// composer.lock, whose entries carry their licenses, is not listed, and sca reads every file in
// full. Two components in two repositories, so neither file's row can come from the other's.
func TestLockfileWithNoLicenseIsReadInPartForLicenses(t *testing.T) {
	res := runUnlicensed(t)
	for _, tc := range []struct {
		component string
		unread    []engine.UnreadInput
	}{
		{"native", []engine.UnreadInput{
			{Repository: "native", Path: "rb/Gemfile.lock", Reason: "no license recorded for 2 packages"},
			{Repository: "native", Path: "rs/Cargo.lock", Reason: "no license recorded for 3 packages"},
		}},
		{"mixed", []engine.UnreadInput{
			{Repository: "mixed", Path: "cs/packages.lock.json",
				Reason: "no license recorded for 1 package, run dotnet restore"},
		}},
	} {
		lic := inputsOf(t, res, tc.component, "licenses")
		if !reflect.DeepEqual(lic.Unread, tc.unread) {
			t.Errorf("%s licenses: unread = %+v, want %+v", tc.component, lic.Unread, tc.unread)
		}
		// Read in part: the packages were read, so each file is counted as read as well.
		if lic.Read != 2 {
			t.Errorf("%s licenses: read = %d, want 2", tc.component, lic.Read)
		}
		sca := inputsOf(t, res, tc.component, "sca")
		if len(sca.Unread) != 0 || sca.Read != 2 {
			t.Errorf("%s sca: read %d, unread %+v, want 2 read in full", tc.component, sca.Read, sca.Unread)
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
		"none carries one":   {"cargo", []trivyPackage{pkg(""), pkg("")}, "no license recorded for 2 packages"},
		"one carries one":    {"npm", []trivyPackage{pkg("direct"), pkg("indirect", "MIT")}, ""},
		"all carry one":      {"composer", []trivyPackage{pkg("", "MIT")}, ""},
		"go module cache":    {"gomod", []trivyPackage{pkg("root"), pkg("direct")}, "no license recorded for 1 package, run go mod download"},
		"nuget packages":     {"nuget", []trivyPackage{pkg("direct"), pkg("indirect")}, "no license recorded for 2 packages, run dotnet restore"},
		"only the project":   {"gomod", []trivyPackage{pkg("root", "MIT")}, ""},
		"no packages":        {"cargo", nil, ""},
		"workspace licensed": {"yarn", []trivyPackage{pkg("root", "MIT"), pkg("workspace", "MIT"), pkg("")}, "no license recorded for 1 package"},
	} {
		got, ok := licenseUnread(tc.typ, tc.pkgs)
		if got != tc.want || ok != (tc.want != "") {
			t.Errorf("%s: licenseUnread = %q, %v, want %q", name, got, ok, tc.want)
		}
	}
}

// Every reason fits the console's caveat column with its control named after it.
func TestLicenseReasonsFitTheCaveatColumn(t *testing.T) {
	for typ := range unlicensedRemedy {
		pkgs := make([]trivyPackage, 99999)
		reason, _ := licenseUnread(typ, pkgs)
		if !strings.HasPrefix(reason, "no license recorded for "+english.Count(99999, "package")) {
			t.Fatalf("%s: reason %q", typ, reason)
		}
		if n := len(reason + " (licenses)"); n > 80 {
			t.Errorf("%q with its control is %d characters, over 80", reason, n)
		}
	}
}
