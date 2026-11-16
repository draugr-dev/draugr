package scanners

import (
	"bufio"
	"errors"
	"go/build/constraint"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"golang.org/x/mod/modfile"

	"github.com/draugr-dev/draugr/internal/git"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// toolsTag is the build tag a Go file names to keep itself out of every build but one that asks
// for the developer tools it imports.
const toolsTag = "tools"

// maxConstraintTags bounds the distinct tags a build constraint may name and still be read. Whether
// a constraint needs the tools tag is decided by trying every assignment of the others, and an
// expression naming more is left unread rather than tried.
const maxConstraintTags = 12

// markGoToolModules marks each dependency finding in a Go module's go.mod or go.sum where the module
// builds nothing but developer tools, so the report lists it after the application's own and names
// it as a tool's. It still counts at its priority: the tools run on developers' machines and in CI.
//
// A module builds nothing but tools when it has Go files and every one of them carries a build
// constraint that needs the `tools` tag, the `tools.go` convention, or when it has no Go file and
// its go.mod declares `tool` directives. The Go toolchain enforces both: a file behind
// `//go:build tools` is in no program built without that tag, and a module with no package builds
// nothing but the tools it names. A module's name and path decide nothing, because a module in a
// `tools` directory may build programs the project ships. A go.mod that declares `tool` directives
// beside packages of its own is not marked: since Go 1.24 the main module declares its tools that
// way, so the directives say nothing about its other requirements.
//
// Where the answer is uncertain, the module is not marked: a file that cannot be read, a go.mod or
// constraint that does not parse, a symbolic link inside the module, or a scope that may have left
// one of its files out of the checkout. A finding left unmarked is listed as the application's,
// which overstates it; one marked wrongly would be listed after the code it ships in.
//
// Every repository scanner's findings pass through, after their paths are repository-relative and
// while the checkout still exists. Only findings about a package are read, which in these two files
// are the dependency findings.
func markGoToolModules(results []sarif.Result, dir string, scope git.Scope) {
	if dir == "" {
		return
	}
	modules := map[string]bool{}
	for i := range results {
		res := &results[i]
		if res.Package == nil || res.Aside != "" || !insideCheckout(res.Location.URI) {
			continue
		}
		uri := path.Clean(res.Location.URI)
		if base := path.Base(uri); base != "go.mod" && base != "go.sum" {
			continue
		}
		module := path.Dir(uri)
		tools, read := modules[module]
		if !read {
			tools = scope.Whole(module) && goToolsOnly(filepath.Join(dir, filepath.FromSlash(module)))
			modules[module] = tools
		}
		if tools {
			res.Aside = sarif.AsideTooling
		}
	}
}

// errNotToolsOnly stops the walk of a module at the first file that settles it as not tools-only.
var errNotToolsOnly = errors.New("not a tools-only module")

// goToolsOnly reports whether the Go module rooted at root builds nothing but developer tools, as
// markGoToolModules describes. Its files are those in root's tree, apart from a directory holding a
// go.mod of its own, which is another module, and `vendor` and `testdata` directories, which no
// build of the module's own packages compiles.
func goToolsOnly(root string) bool {
	raw, err := os.ReadFile(filepath.Join(root, "go.mod")) // #nosec G304 -- a go.mod inside the checkout a scanner reported
	if err != nil {
		return false
	}
	mod, err := modfile.Parse("go.mod", raw, nil)
	if err != nil {
		return false
	}
	sawGo := false
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		switch {
		case err != nil:
			return err
		case d.Type()&fs.ModeSymlink != 0:
			// A link may stand for a package of the module's own, which the walk does not follow.
			return errNotToolsOnly
		case d.IsDir():
			return enterModuleDir(root, p, d.Name())
		case !strings.HasSuffix(d.Name(), ".go"):
			return nil
		}
		sawGo = true
		if !needsToolsTag(p) {
			return errNotToolsOnly
		}
		return nil
	})
	if err != nil {
		return false
	}
	return sawGo || len(mod.Tool) > 0
}

// enterModuleDir decides whether the walk of the module at root reads the directory p: fs.SkipDir
// for another module's directory, a vendor directory or a testdata directory, nil for the rest, and
// an error where whether p holds another module cannot be read.
func enterModuleDir(root, p, name string) error {
	if p == root {
		return nil
	}
	if name == "vendor" || name == "testdata" {
		return fs.SkipDir
	}
	_, err := os.Lstat(filepath.Join(p, "go.mod"))
	switch {
	case err == nil:
		return fs.SkipDir
	case errors.Is(err, fs.ErrNotExist):
		return nil
	}
	return err
}

// needsToolsTag reports whether the Go file at p carries a build constraint that no build without
// the tools tag satisfies. A file that cannot be read, has no constraint, or has one that does not
// parse or names too many tags to try, does not.
//
// The constraint is read from the file's leading run of blank lines and `//` comments, before the
// first line of anything else, which is where the go command reads it. A `//go:build` line decides
// it; without one, the `// +build` lines before the last blank line of that run do, together, as
// they did before Go 1.17. A constraint after a `/* */` comment is not read, so such a file does
// not count as a tool's.
func needsToolsTag(p string) bool {
	f, err := os.Open(p) // #nosec G304 -- a Go file inside the checkout a scanner reported
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	var goBuild constraint.Expr
	var plusBuild, pending []constraint.Expr
	lines := bufio.NewScanner(f)
	for lines.Scan() {
		line := strings.TrimSpace(strings.TrimSuffix(lines.Text(), "\r"))
		if line == "" {
			plusBuild = append(plusBuild, pending...)
			pending = nil
			continue
		}
		if !strings.HasPrefix(line, "//") {
			break
		}
		switch {
		case constraint.IsGoBuild(line):
			if goBuild != nil {
				return false // the go command refuses a file with two
			}
			if goBuild, err = constraint.Parse(line); err != nil {
				return false
			}
		case constraint.IsPlusBuild(line):
			x, err := constraint.Parse(line)
			if err != nil {
				return false
			}
			pending = append(pending, x)
		}
	}
	if lines.Err() != nil {
		return false
	}
	if goBuild == nil {
		for _, x := range plusBuild {
			if goBuild == nil {
				goBuild = x
			} else {
				goBuild = &constraint.AndExpr{X: goBuild, Y: x}
			}
		}
	}
	return goBuild != nil && requiresTag(goBuild, toolsTag)
}

// requiresTag reports whether x is false under every assignment of its tags that leaves tag unset,
// so that only a build naming tag can include the file. `tools`, `tools && linux` and
// `tools || (tools && !windows)` require it; `!tools`, `linux` and `tools || linux` do not.
func requiresTag(x constraint.Expr, tag string) bool {
	others := everyTag(x, map[string]bool{tag: true}, nil)
	if len(others) > maxConstraintTags {
		return false
	}
	for set := range 1 << len(others) {
		on := map[string]bool{}
		for i, t := range others {
			on[t] = set&(1<<i) != 0
		}
		if x.Eval(func(t string) bool { return on[t] }) {
			return false
		}
	}
	return true
}

// everyTag appends to out each tag x names that seen does not hold yet, in the order x names them,
// `ignore` included, unlike constraintTags: a file behind `//go:build ignore` is not a tool's.
// Read from the expression's tree rather than through Eval, which stops at the first operand that
// settles an `&&` or `||`.
func everyTag(x constraint.Expr, seen map[string]bool, out []string) []string {
	switch x := x.(type) {
	case *constraint.TagExpr:
		if !seen[x.Tag] {
			seen[x.Tag] = true
			out = append(out, x.Tag)
		}
	case *constraint.NotExpr:
		out = everyTag(x.X, seen, out)
	case *constraint.AndExpr:
		out = everyTag(x.Y, seen, everyTag(x.X, seen, out))
	case *constraint.OrExpr:
		out = everyTag(x.Y, seen, everyTag(x.X, seen, out))
	}
	return out
}
