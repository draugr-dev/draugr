package scanners

import (
	"context"
	"errors"
	"go/version"
	"io/fs"
	"os"
	"path/filepath"
	"slices"

	"golang.org/x/mod/modfile"
)

// onGoWork runs govulncheck over a module in a workspace with GOWORK naming a copy of the
// workspace's go.work outside the checkout, and over a module the workspace does not use with
// GOWORK=off.
//
// The checkout is read-only, and in workspace mode the go command writes any checksum it is missing
// to the go.work.sum beside go.work. A repository that commits go.work without go.work.sum, or with
// one that lacks an entry, fails to load with "permission denied" on that file. The copy sits in a
// temporary directory the go command can write to, beside a copy of go.work.sum where one exists,
// with its use and relative replace paths made absolute so they name the checkout's modules. It is
// removed when the run ends, and nothing in the checkout changes.
//
// The go command refuses to build a module the workspace does not use while the workspace is in
// effect, and GOWORK=off is the only way it builds.
//
// A workspace the go command builds from its vendor directory needs no copy (see vendored).
//
// A GOWORK already set in the environment names the workspace, or none, and is left as it is.
func onGoWork(run func(ctx context.Context, dir string, argv, env []string) ([]byte, error)) func(ctx context.Context, dir string, argv []string) ([]byte, error) {
	return func(ctx context.Context, dir string, argv []string) ([]byte, error) {
		env, cleanup, err := goWorkEnv(dir, argv)
		if err != nil {
			return nil, err
		}
		defer cleanup()
		return run(ctx, dir, argv, env)
	}
}

// goWorkEnv is the environment a run of argv (`-C <module>`) in the checkout at root needs for the
// go.work governing the module, and what removes the copy it made. Empty where no go.work governs
// the module.
func goWorkEnv(root string, argv []string) (env []string, cleanup func(), err error) {
	cleanup = func() {}
	i := slices.Index(argv, "-C")
	if i < 0 || i+1 >= len(argv) {
		return nil, cleanup, nil
	}
	if gowork := os.Getenv("GOWORK"); gowork != "" && gowork != "auto" {
		return nil, cleanup, nil
	}
	mod := argv[i+1]
	work := governingGoWork(root, mod)
	if work == "" {
		return nil, cleanup, nil
	}
	raw, err := os.ReadFile(work) // #nosec G304 -- the go.work governing a module in the checkout
	if err != nil {
		return nil, cleanup, err
	}
	// Inside the checkout: with GOWORK unset, governingGoWork looks nowhere else.
	name, _ := relSlash(root, work)
	wf, err := modfile.ParseWork(name, raw, nil)
	if err != nil {
		return nil, cleanup, err
	}
	base := filepath.Dir(work)
	if !usesModule(wf, base, mod) {
		return []string{"GOWORK=off"}, cleanup, nil
	}
	if vendored(wf, base) {
		return nil, cleanup, nil
	}
	sum, err := os.ReadFile(work + ".sum") // #nosec G304 -- the go.work.sum beside that go.work
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, cleanup, err
	}

	absolute(wf, base)
	tmp, err := os.MkdirTemp("", "draugr-gowork-*")
	if err != nil {
		return nil, cleanup, err
	}
	cleanup = func() { _ = os.RemoveAll(tmp) }
	copied := filepath.Join(tmp, "go.work")
	if err := os.WriteFile(copied, modfile.Format(wf.Syntax), 0o600); err != nil {
		cleanup()
		return nil, func() {}, err
	}
	if sum != nil {
		if err := os.WriteFile(copied+".sum", sum, 0o600); err != nil {
			cleanup()
			return nil, func() {}, err
		}
	}
	return []string{"GOWORK=" + copied}, cleanup, nil
}

// usesModule reports whether the workspace at base lists the module at mod in a use directive.
func usesModule(wf *modfile.WorkFile, base, mod string) bool {
	for _, u := range wf.Use {
		if filepath.Clean(fromWorkspace(base, u.Path)) == filepath.Clean(mod) {
			return true
		}
	}
	return false
}

// vendored reports whether the go command builds the workspace at base from its vendor directory,
// which it does by default where vendor/modules.txt sits beside go.work and go.work declares go 1.22
// or later.
//
// A vendored build reads no checksums and writes no go.work.sum, so it loads from the read-only
// checkout as it is. A copy of go.work elsewhere would leave vendor/ behind, and the go command
// would resolve the workspace's dependencies from the module cache instead.
func vendored(wf *modfile.WorkFile, base string) bool {
	if wf.Go == nil || version.Compare("go"+wf.Go.Version, "go1.22") < 0 {
		return false
	}
	_, err := os.Stat(filepath.Join(base, "vendor", "modules.txt"))
	return err == nil
}

// absolute rewrites each use path, and each replacement that is a relative directory, as an
// absolute path from base, the directory of the go.work they were written against.
//
// The path is the last token of its line, whether the line stands alone or sits in a block: a use
// line ends with its directory, and a replacement by a directory carries no version after it.
func absolute(wf *modfile.WorkFile, base string) {
	for _, u := range wf.Use {
		setLastToken(u.Syntax, fromWorkspace(base, u.Path))
	}
	for _, r := range wf.Replace {
		if r.New.Version == "" && modfile.IsDirectoryPath(r.New.Path) && !filepath.IsAbs(r.New.Path) {
			setLastToken(r.Syntax, fromWorkspace(base, r.New.Path))
		}
	}
}

// fromWorkspace is path, as a go.work at base writes it, as an absolute path.
func fromWorkspace(base, path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(base, filepath.FromSlash(path))
}

// setLastToken replaces the last token of line with path, quoted where go.work syntax needs it.
func setLastToken(line *modfile.Line, path string) {
	line.Token[len(line.Token)-1] = modfile.AutoQuote(path)
}
