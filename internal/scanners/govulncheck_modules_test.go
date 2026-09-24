package scanners

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
)

// Two modules' runs arrive concatenated, each opening with its config message. Each is judged on
// its own and located at its own go.mod: the module that calls the vulnerable function is
// reachable, and the one that only requires the dependency is unreachable rather than borrowing
// the first's call path.
func TestParseGovulncheckJudgesEachModuleOnItsOwn(t *testing.T) {
	dir := t.TempDir()
	for path, body := range map[string]string{
		"go.mod":       "module example.com/app\n\ngo 1.21\n",
		"tools/go.mod": "module \"example.com/tools\"\n\ngo 1.21\n",
	} {
		full := filepath.Join(dir, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	run := func(root string, called bool) string {
		trace := `[{"module":"github.com/tidwall/gjson","version":"v1.6.5"}]`
		if called {
			trace = `[{"module":"github.com/tidwall/gjson","version":"v1.6.5","package":"github.com/tidwall/gjson","function":"Get"},` +
				`{"module":"` + root + `","package":"` + root + `","function":"main"}]`
		}
		return `{"config":{"scan_level":"symbol"}}
{"SBOM":{"modules":[{"path":"` + root + `"},{"path":"github.com/tidwall/gjson","version":"v1.6.5"}],"roots":["` + root + `"]}}
{"osv":{"id":"GO-2021-0054","aliases":["CVE-2020-36067"]}}
{"finding":{"osv":"GO-2021-0054","fixed_version":"v1.6.6","trace":` + trace + `}}
`
	}
	out := run("example.com/app", true) + run("example.com/tools", false)

	rep, err := parseGovulncheck([]byte(out), dir, plugin.Config{})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, r := range rep.Results {
		got[r.Location.URI] = string(r.Reachability.State)
	}
	if got["go.mod"] != "reachable" || got["tools/go.mod"] != "unreachable" || len(got) != 2 {
		t.Errorf("verdicts by manifest = %v, want reachable at go.mod and unreachable at tools/go.mod", got)
	}
}

func TestGoModulePath(t *testing.T) {
	dir := t.TempDir()
	for body, want := range map[string]string{
		"module example.com/a\n":          "example.com/a",
		"// comment\nmodule \"quoted\"\n": "quoted",
		"go 1.21\n":                       "",
	} {
		path := filepath.Join(dir, "go.mod")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := goModulePath(path); got != want {
			t.Errorf("goModulePath(%q) = %q, want %q", body, got, want)
		}
	}
	if got := goModulePath(filepath.Join(dir, "absent")); got != "" {
		t.Errorf("an absent go.mod declared %q", got)
	}
	if got := goModuleManifests(""); len(got) != 0 {
		t.Errorf("no root gave %v", got)
	}
}
