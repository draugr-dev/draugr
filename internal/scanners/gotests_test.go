package scanners

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/draugr-dev/draugr/internal/git"
	"github.com/draugr-dev/draugr/internal/nonshipping"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// A module whose every Go file is a test file is a test's, wherever it sits; one with a single file
// that is not, or with no Go file at all, is not. The application module beside them is not either.
func TestMarkGoTestModulesReadsWhatTheModuleHolds(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"go.mod":  "module example.com/app\n\ngo 1.24\n\nrequire golang.org/x/text v0.3.7\n",
		"main.go": "package main\n\nfunc main() {}\n",

		"e2e/go.mod":             "module example.com/app/e2e\n\ngo 1.24\n\nrequire golang.org/x/net v0.7.0\n",
		"e2e/go.sum":             "golang.org/x/net v0.7.0 h1:x=\n",
		"e2e/container_test.go":  "package e2e\n",
		"e2e/harness_test.go":    "package e2e\n",
		"e2e/testdata/server.go": "package main\n",
		"e2e/nested/go.mod":      "module example.com/nested\n",
		"e2e/nested/main.go":     "package main\n",

		"mixed/go.mod":         "module example.com/app/mixed\n\ngo 1.24\n\nrequire golang.org/x/net v0.7.0\n",
		"mixed/suite_test.go":  "package mixed\n",
		"mixed/helpers.go":     "package mixed\n",
		"nogo/go.mod":          "module example.com/app/nogo\n\ngo 1.24\n\nrequire golang.org/x/net v0.7.0\n",
		"nogo/README.md":       "Nothing here.\n",
		"labeled/go.mod":       "module example.com/app/labeled\n\ngo 1.24\n\nrequire golang.org/x/net v0.7.0\n",
		"labeled/only_test.go": "package labeled\n",
	})
	labeled := depAt("labeled/go.mod")
	labeled.NonShipping = nonshipping.Docs
	results := []sarif.Result{depAt("go.mod"), depAt("e2e/go.mod"), depAt("e2e/go.sum"), depAt("mixed/go.mod"),
		depAt("nogo/go.mod"), labeled, {RuleID: "G101", Location: sarif.Location{URI: "e2e/go.mod"}}}
	markGoTestModules(results, dir, git.Scope{})
	for i, want := range []string{"", nonshipping.Test, nonshipping.Test, "", "", nonshipping.Docs, ""} {
		if results[i].NonShipping != want {
			t.Errorf("%s (%s): label %q, want %q", results[i].Location.URI, results[i].RuleID, results[i].NonShipping, want)
		}
	}
	markGoTestModules(results, "", git.Scope{})
}

// A scope that could have left one of the module's files out of the checkout labels nothing: a
// missing non-test file reads exactly like one that never existed.
func TestMarkGoTestModulesNeedsTheWholeModule(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"e2e/go.mod":    "module example.com/app/e2e\n\ngo 1.24\n\nrequire golang.org/x/net v0.7.0\n",
		"e2e/a_test.go": "package e2e\n",
	})
	results := []sarif.Result{depAt("e2e/go.mod")}
	markGoTestModules(results, dir, git.Scope{Ignore: []string{"e2e/fixtures/**"}})
	if results[0].NonShipping != "" {
		t.Errorf("label %q under a scope that may leave a file out, want none", results[0].NonShipping)
	}
}

// A symbolic link, or a directory that cannot be read, leaves the module unlabeled.
func TestGoTestsOnlyRefusesWhatItCannotRead(t *testing.T) {
	dir := writeTree(t, map[string]string{"go.mod": "module example.com/e2e\n", "a_test.go": "package e2e\n"})
	if !goTestsOnly(dir) {
		t.Fatal("a module of one test file should read as tests only")
	}
	if err := os.Symlink(filepath.Join(dir, "a_test.go"), filepath.Join(dir, "link_test.go")); err != nil {
		t.Fatal(err)
	}
	if goTestsOnly(dir) {
		t.Error("a module holding a symbolic link read as tests only")
	}
	if goTestsOnly(filepath.Join(dir, "absent")) {
		t.Error("a missing directory read as tests only")
	}
}

// Through a repository scan, in two repositories: each module is read in its own checkout.
func TestRepoScanLabelsTestModulesInEachRepository(t *testing.T) {
	trees := map[string]string{
		"https://example.com/proxy.git": writeTree(t, map[string]string{
			"e2e/go.mod":    "module example.com/proxy/e2e\n\ngo 1.24\n\nrequire golang.org/x/net v0.7.0\n",
			"e2e/a_test.go": "package e2e\n",
		}),
		"https://example.com/agent.git": writeTree(t, map[string]string{
			"e2e/go.mod":    "module example.com/agent/e2e\n\ngo 1.24\n\nrequire golang.org/x/net v0.7.0\n",
			"e2e/runner.go": "package main\n\nfunc main() {}\n",
		}),
	}
	s := repoScanner{
		info:     plugin.ScannerInfo{Name: "trivy-fs", Controls: []string{"sca"}},
		args:     func(dir string, _ plugin.Config) []string { return []string{"trivy", "fs", dir} },
		checkout: checkoutOf(trees),
		run: func(context.Context, string, []string) ([]byte, error) {
			return []byte(`{}`), nil
		},
		parse: func(_ []byte, dir string, _ plugin.Config) (sarif.Report, error) {
			return sarif.Report{Results: []sarif.Result{depAt(filepath.Join(dir, "e2e", "go.mod"))}}, nil
		},
	}
	for url, want := range map[string]string{
		"https://example.com/proxy.git": nonshipping.Test,
		"https://example.com/agent.git": "",
	} {
		rep, err := s.Scan(context.Background(), plugin.RepositoryTarget{URL: url}, plugin.Config{})
		if err != nil {
			t.Fatal(err)
		}
		if len(rep.Results) != 1 || rep.Results[0].NonShipping != want {
			t.Errorf("%s: results %+v, want one labeled %q", url, rep.Results, want)
		}
	}
}
