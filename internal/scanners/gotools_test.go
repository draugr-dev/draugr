package scanners

import (
	"context"
	"go/build/constraint"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/git"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// toolsFile is the `tools.go` convention: a file behind `//go:build tools` that imports the tools so
// go.mod keeps them.
const toolsFile = "//go:build tools\n\npackage tools\n\nimport _ \"golang.org/x/net/html\"\n"

// depAt is a dependency finding in the file at uri.
func depAt(uri string) sarif.Result {
	return sarif.Result{RuleID: "CVE-2026-0001", Location: sarif.Location{URI: uri, StartLine: 5},
		Package: &sarif.Package{Name: "golang.org/x/net", Version: "v0.7.0"}}
}

// The four shapes the mark has to tell apart, each a module of its own in one repository beside an
// application module: a module whose every file is behind `//go:build tools` is marked, the same
// module with one more file outside the constraint is not, a module with `tool` directives and no Go
// file is marked, and an application module that also declares `tool` directives is not.
func TestMarkGoToolModulesReadsWhatTheModuleBuilds(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"go.mod":  "module example.com/app\n\ngo 1.24\n\nrequire golang.org/x/text v0.3.7\n",
		"main.go": "package main\n\nimport _ \"golang.org/x/text/language\"\n\nfunc main() {}\n",

		"_tools/go.mod":   "module example.com/app/tools\n\ngo 1.22\n\nrequire golang.org/x/net v0.7.0\n",
		"_tools/tools.go": toolsFile,
		// What no build of the module's own packages reads: a nested module, vendor and testdata.
		"_tools/nested/go.mod":         "module example.com/nested\n",
		"_tools/nested/main.go":        "package main\n",
		"_tools/vendor/x/x.go":         "package x\n",
		"_tools/testdata/fixture.go":   "package fixture\n",
		"_tools/README.md":             "Pinned linters.\n",
		"_tools/internal/more/lint.go": "// Copyright 2026 The Authors.\n\n//go:build tools && !windows\n\npackage more\n",

		"mixed/go.mod":          "module example.com/app/mixed\n\ngo 1.22\n\nrequire golang.org/x/net v0.7.0\n",
		"mixed/tools.go":        toolsFile,
		"mixed/cmd/gen/main.go": "package main\n\nfunc main() {}\n",

		"directives/go.mod": "module example.com/app/directives\n\ngo 1.24\n\ntool golang.org/x/tools/cmd/stringer\n\n" +
			"require golang.org/x/net v0.7.0\n",
		"directives/go.sum": "golang.org/x/net v0.7.0 h1:x=\n",

		"service/go.mod": "module example.com/service\n\ngo 1.24\n\ntool golang.org/x/tools/cmd/stringer\n\n" +
			"require golang.org/x/net v0.7.0\n",
		"service/main.go": "package main\n\nfunc main() {}\n",

		"empty/go.mod":  "module example.com/empty\n\ngo 1.24\n",
		"broken/go.mod": "module example.com/broken\n\nthis is not a directive\n",
		"orphan/go.sum": "golang.org/x/net v0.7.0 h1:x=\n",
	})
	license := depAt("_tools/go.mod")
	license.Package = nil
	generated := depAt("_tools/go.mod")
	generated.Aside = sarif.AsideGenerated
	results := []sarif.Result{
		depAt("go.mod"),
		depAt("_tools/go.mod"),
		depAt("mixed/go.mod"),
		depAt("directives/go.mod"),
		depAt("directives/go.sum"),
		depAt("service/go.mod"),
		depAt("empty/go.mod"),
		depAt("broken/go.mod"),
		depAt("orphan/go.sum"),
		depAt("_tools/tools.go"),
		depAt("../_tools/go.mod"),
		license,
		generated,
		depAt("_tools/./go.mod"),
	}
	markGoToolModules(results, dir, git.Scope{})
	want := []string{"", "tooling", "", "tooling", "tooling", "", "", "", "", "", "", "", "generated", "tooling"}
	for i, w := range want {
		if results[i].Aside != w {
			t.Errorf("result %d (%s): aside %q, want %q", i, results[i].Location.URI, results[i].Aside, w)
		}
	}

	none := []sarif.Result{depAt("_tools/go.mod")}
	markGoToolModules(none, "", git.Scope{})
	if none[0].Aside != "" {
		t.Error("a result with no checkout to read was marked")
	}
}

// A scope that may have left one of a module's files out of the checkout leaves the module
// unmarked, because the file it left out may be the application's: a tools-only module is judged
// by every file in it, and an absent file reads like one that never existed.
func TestMarkGoToolModulesNeedsTheWholeModule(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"_tools/go.mod":   "module example.com/app/tools\n\ngo 1.22\n\nrequire golang.org/x/net v0.7.0\n",
		"_tools/tools.go": toolsFile,
	})
	for _, c := range []struct {
		scope git.Scope
		want  string
	}{
		{git.Scope{Paths: []string{"_tools"}}, "tooling"},
		{git.Scope{Ignore: []string{"docs/"}}, "tooling"},
		{git.Scope{Paths: []string{"_tools/go.mod", "_tools/tools.go"}}, ""},
		{git.Scope{Ignore: []string{"_tools/cmd/"}}, ""},
	} {
		results := []sarif.Result{depAt("_tools/go.mod")}
		markGoToolModules(results, dir, c.scope)
		if results[0].Aside != c.want {
			t.Errorf("scope %+v: aside %q, want %q", c.scope, results[0].Aside, c.want)
		}
	}
}

// The go-components sealed scenario's tools module holds `main` programs that call gjson, one of
// them reachably. Its directory is named tools, and that decides nothing: its files are not behind
// the tools constraint, so it is not marked.
func TestMarkGoToolModulesLeavesTheSealedToolsModuleUnmarked(t *testing.T) {
	src := filepath.Join("..", "..", "test", "integration", "testdata", "ecosystems", "go-components", "repo", "tools")
	files := map[string]string{}
	for rel, from := range map[string]string{
		"tools/go.mod":         "go.mod.fixture",
		"tools/go.sum":         "go.sum.fixture",
		"tools/api/main.go":    "api/main.go",
		"tools/worker/main.go": "worker/main.go",
	} {
		raw, err := os.ReadFile(filepath.Join(src, filepath.FromSlash(from))) // #nosec G304 -- a fixture file this test names
		if err != nil {
			t.Fatal(err)
		}
		files[rel] = string(raw)
	}
	dir := writeTree(t, files)
	results := []sarif.Result{depAt("tools/go.mod"), depAt("tools/go.sum")}
	markGoToolModules(results, dir, git.Scope{})
	for _, r := range results {
		if r.Aside != "" {
			t.Errorf("%s: aside %q, want none", r.Location.URI, r.Aside)
		}
	}
}

// Two repositories, each with a module at the same path: one builds only tools, the other a
// program it ships. The mark is read per checkout, so the second repository's module never takes
// the first's answer.
func TestRepoScanMarksToolModulesInEachRepository(t *testing.T) {
	trees := map[string]string{
		"https://example.com/lint.git": writeTree(t, map[string]string{
			"tools/go.mod":   "module example.com/lint/tools\n\ngo 1.22\n\nrequire golang.org/x/net v0.7.0\n",
			"tools/tools.go": toolsFile,
		}),
		"https://example.com/cli.git": writeTree(t, map[string]string{
			"tools/go.mod":      "module example.com/cli/tools\n\ngo 1.22\n\nrequire golang.org/x/net v0.7.0\n",
			"tools/gen/main.go": "package main\n\nimport _ \"golang.org/x/net/html\"\n\nfunc main() {}\n",
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
			r := depAt(filepath.Join(dir, "tools", "go.mod"))
			return sarif.Report{Results: []sarif.Result{r}}, nil
		},
	}
	for url, want := range map[string]string{
		"https://example.com/lint.git": sarif.AsideTooling,
		"https://example.com/cli.git":  "",
	} {
		rep, err := s.Scan(context.Background(), plugin.RepositoryTarget{URL: url}, plugin.Config{})
		if err != nil {
			t.Fatal(err)
		}
		if len(rep.Results) != 1 || rep.Results[0].Location.URI != "tools/go.mod" || rep.Results[0].Aside != want {
			t.Errorf("%s: results %+v, want one at tools/go.mod with aside %q", url, rep.Results, want)
		}
	}
}

// A file is a tool's only where its constraint, read where the go command reads it, keeps it out
// of every build that does not name the tools tag.
func TestNeedsToolsTag(t *testing.T) {
	cases := map[string]struct {
		src  string
		want bool
	}{
		"go:build tools":          {toolsFile, true},
		"after a comment":         {"// Package tools pins the linters.\n\n//go:build tools\n\npackage tools\n", true},
		"crlf":                    {"//go:build tools\r\n\r\npackage tools\r\n", true},
		"tools and a platform":    {"//go:build tools && linux\n\npackage tools\n", true},
		"either way needs tools":  {"//go:build tools || (tools && !windows)\n\npackage tools\n", true},
		"plus build":              {"// +build tools\n\npackage tools\n", true},
		"plus build lines anded":  {"// +build linux\n// +build tools\n\npackage tools\n", true},
		"no constraint":           {"package tools\n", false},
		"another tag":             {"//go:build linux\n\npackage tools\n", false},
		"ignore":                  {"//go:build ignore\n\npackage main\n", false},
		"tools or another":        {"//go:build tools || linux\n\npackage tools\n", false},
		"not tools":               {"//go:build !tools\n\npackage tools\n", false},
		"after the package":       {"package tools\n\n//go:build tools\n", false},
		"after a block comment":   {"/* license */\n//go:build tools\n\npackage tools\n", false},
		"does not parse":          {"//go:build tools &&\n\npackage tools\n", false},
		"two go:build lines":      {"//go:build tools\n//go:build tools\n\npackage tools\n", false},
		"plus build not parsed":   {"// +build !!tools\n\npackage tools\n", false},
		"plus build without gap":  {"// +build tools\npackage tools\n", false},
		"go:build wins over plus": {"//go:build linux\n// +build tools\n\npackage tools\n", false},
	}
	dir := t.TempDir()
	for name, c := range cases {
		p := filepath.Join(dir, strings.ReplaceAll(name, " ", "_")+".go")
		if err := os.WriteFile(p, []byte(c.src), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := needsToolsTag(p); got != c.want {
			t.Errorf("%s: needsToolsTag = %v, want %v", name, got, c.want)
		}
	}
	if needsToolsTag(filepath.Join(dir, "missing.go")) {
		t.Error("a file that cannot be read needs the tools tag")
	}
}

// An expression naming more tags than can be tried is left unread, and so does not count as a
// tool's.
func TestRequiresTagLeavesALargeExpressionUnread(t *testing.T) {
	tags := []string{"tools"}
	for i := range maxConstraintTags + 1 {
		tags = append(tags, "t"+string(rune('a'+i)))
	}
	x, err := constraint.Parse("//go:build " + strings.Join(tags, " && "))
	if err != nil {
		t.Fatal(err)
	}
	if requiresTag(x, toolsTag) {
		t.Error("an expression with more tags than can be tried was read as needing tools")
	}
	small, err := constraint.Parse("//go:build " + strings.Join(tags[:maxConstraintTags+1], " && "))
	if err != nil {
		t.Fatal(err)
	}
	if !requiresTag(small, toolsTag) {
		t.Error("an expression at the limit was not read")
	}
}

// A module holding a symbolic link, or one whose go.mod cannot be read, is not judged.
func TestGoToolsOnlyRefusesWhatItCannotRead(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"linked/go.mod":   "module example.com/linked\n",
		"linked/tools.go": toolsFile,
		"elsewhere/x.go":  "package x\n",
	})
	if err := os.Symlink(filepath.Join(dir, "elsewhere"), filepath.Join(dir, "linked", "pkg")); err != nil {
		t.Skip("symbolic links unavailable:", err)
	}
	if goToolsOnly(filepath.Join(dir, "linked")) {
		t.Error("a module holding a symbolic link was judged tools-only")
	}
	if goToolsOnly(filepath.Join(dir, "missing")) {
		t.Error("a module with no go.mod was judged tools-only")
	}
}
