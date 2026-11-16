package scanners

import (
	"errors"
	"io/fs"
	"path"
	"path/filepath"
	"strings"

	"github.com/draugr-dev/draugr/internal/git"
	"github.com/draugr-dev/draugr/internal/nonshipping"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// markGoTestModules labels each dependency finding in the go.mod or go.sum of a Go module whose
// every Go file is a test file, as a test's, so the report lists it after the shipped code's. It
// still counts at its priority.
//
// The Go toolchain never compiles a `_test.go` file into a program, so a module holding nothing
// else, an end-to-end suite in its own module, builds no program, and its requirements are the test
// harness's. The engine labels a test file by its name and a test directory by its path; a module
// like this is neither, so only its files can say so, and they are read here, while the checkout
// exists.
//
// Where the answer is uncertain, nothing is labeled: a module with no Go file, a file or directory
// that cannot be read, a symbolic link inside the module, or a scope whose paths or ignore could
// have left one of its files out of the checkout. The path never decides it.
func markGoTestModules(results []sarif.Result, dir string, scope git.Scope) {
	if dir == "" {
		return
	}
	modules := map[string]bool{}
	for i := range results {
		res := &results[i]
		if res.Package == nil || res.NonShipping != "" || !insideCheckout(res.Location.URI) {
			continue
		}
		uri := path.Clean(res.Location.URI)
		if base := path.Base(uri); base != "go.mod" && base != "go.sum" {
			continue
		}
		module := path.Dir(uri)
		tests, read := modules[module]
		if !read {
			tests = scope.Whole(module) && goTestsOnly(filepath.Join(dir, filepath.FromSlash(module)))
			modules[module] = tests
		}
		if tests {
			res.NonShipping = nonshipping.Test
		}
	}
}

// errNotTestsOnly stops the walk of a module at the first file that settles it as not tests-only.
var errNotTestsOnly = errors.New("not a tests-only module")

// goTestsOnly reports whether the Go module rooted at root has Go files and every one is a test
// file. Its files are those enterModuleDir walks: another module's directory, vendor and testdata
// are left out.
func goTestsOnly(root string) bool {
	sawGo := false
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		switch {
		case err != nil:
			return err
		case d.Type()&fs.ModeSymlink != 0:
			return errNotTestsOnly
		case d.IsDir():
			return enterModuleDir(root, p, d.Name())
		case !strings.HasSuffix(d.Name(), ".go"):
			return nil
		case !strings.HasSuffix(d.Name(), "_test.go"):
			return errNotTestsOnly
		}
		sawGo = true
		return nil
	})
	return err == nil && sawGo
}
