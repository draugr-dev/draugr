package scanners

import (
	"context"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// loadtestGoMod is a second module in the checkout, one the imported file was not run in.
const loadtestGoMod = "module example.com/reach/test/loadtest\n\ngo 1.22\n\nrequire golang.org/x/text v0.3.0\n"

// An imported govulncheck file covers the module it was run in. The checkout's other module is named
// as not analyzed, with the command that would cover it, and the one it analyzed as analyzed, so a
// second file covering the other can answer for it.
func TestAnImportedGovulncheckFileNamesTheModulesItDidNotAnalyze(t *testing.T) {
	dir := checkoutWith(t, map[string]string{
		"go.mod": reachGoMod, "main.go": reachMain,
		"test/loadtest/go.mod":    loadtestGoMod,
		"testdata/fixture/go.mod": "module example.com/fixture\n", // not a module of the build
	})
	path := copiedAt(t, mustRead(t, filepath.Join("testdata", "govulncheck-reachable.json")), time.Now())
	repo := plugin.RepositoryTarget{URL: dir}
	rep, err := NewSARIFImport().Scan(context.Background(),
		plugin.FileTarget{Path: path, Format: saga.ImportFormatGovulncheckJSON, Repositories: []plugin.RepositoryTarget{repo}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var analysis []sarif.Input
	for _, in := range rep.Inputs {
		if in.Analysis {
			analysis = append(analysis, in)
		}
	}
	want := []sarif.Input{
		{Scanner: plugin.ImportScanner, Repository: repo.Source(), Path: "go.mod", Analysis: true},
		{Scanner: plugin.ImportScanner, Repository: repo.Source(), Path: "test/loadtest/go.mod", Analysis: true,
			Unread: "Run and import: govulncheck -C test/loadtest -format json ./..."},
	}
	if !reflect.DeepEqual(analysis, want) {
		t.Errorf("inputs =\n%+v\nwant\n%+v", analysis, want)
	}
}

// A module at the root that no run analyzed is named with the command run at the root, and with no
// local checkout, or a component of two repositories, there are no modules to account for.
func TestAnImportedGovulncheckFileAccountsOnlyForACheckoutItCanRead(t *testing.T) {
	if got := notAnalyzedByImport("go.mod"); got != "Run and import: govulncheck -format json ./... at the root" {
		t.Errorf("the root module's reason = %q", got)
	}
	path := copiedAt(t, mustRead(t, filepath.Join("testdata", "govulncheck-reachable.json")), time.Now())
	dir := checkoutWith(t, map[string]string{"go.mod": reachGoMod, "test/loadtest/go.mod": loadtestGoMod})
	for name, repos := range map[string][]plugin.RepositoryTarget{
		"a remote repository": {{URL: "https://github.com/acme/reach"}},
		"two repositories":    {{URL: dir}, {URL: "https://github.com/acme/web"}},
	} {
		rep, err := NewSARIFImport().Scan(context.Background(),
			plugin.FileTarget{Path: path, Format: saga.ImportFormatGovulncheckJSON, Repositories: repos}, nil)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, in := range rep.Inputs {
			if in.Analysis {
				t.Errorf("%s: accounted for %s, with no checkout to read modules from", name, in.Path)
			}
		}
	}
}
