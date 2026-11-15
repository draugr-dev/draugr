package scanners

import (
	"context"
	"go/build"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
)

// goPlatform is a target the go command builds for, as GOOS and GOARCH.
type goPlatform struct {
	OS, Arch string
}

// String is the platform as the go command names it, "windows/amd64".
func (p goPlatform) String() string { return p.OS + "/" + p.Arch }

// hostGoPlatform is the platform the go command builds for on this machine, which a run of gosec or
// govulncheck with no GOOS or GOARCH set analyzes. A variable so a test can stand on another host.
var hostGoPlatform = goPlatform{runtime.GOOS, runtime.GOARCH}

// analyzedGoPlatforms are the platforms gosec and govulncheck run for beside the host, where a
// module holds code only they build: Linux, Windows and macOS, minus whichever the host is. One
// architecture each, the common one, so a file built for one architecture of these alone is read
// only where it is that architecture.
var analyzedGoPlatforms = []goPlatform{{"linux", "amd64"}, {"windows", "amd64"}, {"darwin", "arm64"}}

// goPorts are the platforms the go command builds for, as `go tool dist list` prints them for Go
// 1.27. A file the host skips is code for another platform when one of these builds it, and a file
// none builds is kept out by a tag such as `integration` or `ignore`, which is not a platform.
var goPorts = []goPlatform{
	{"aix", "ppc64"}, {"android", "386"}, {"android", "amd64"}, {"android", "arm"}, {"android", "arm64"},
	{"darwin", "amd64"}, {"darwin", "arm64"}, {"dragonfly", "amd64"}, {"freebsd", "386"},
	{"freebsd", "amd64"}, {"freebsd", "arm"}, {"freebsd", "arm64"}, {"illumos", "amd64"},
	{"ios", "amd64"}, {"ios", "arm64"}, {"js", "wasm"}, {"linux", "386"}, {"linux", "amd64"},
	{"linux", "arm"}, {"linux", "arm64"}, {"linux", "loong64"}, {"linux", "mips"}, {"linux", "mips64"},
	{"linux", "mips64le"}, {"linux", "mipsle"}, {"linux", "ppc64"}, {"linux", "ppc64le"},
	{"linux", "riscv64"}, {"linux", "s390x"}, {"netbsd", "386"}, {"netbsd", "amd64"}, {"netbsd", "arm"},
	{"netbsd", "arm64"}, {"openbsd", "386"}, {"openbsd", "amd64"}, {"openbsd", "arm"},
	{"openbsd", "arm64"}, {"openbsd", "ppc64"}, {"openbsd", "riscv64"}, {"plan9", "386"},
	{"plan9", "amd64"}, {"plan9", "arm"}, {"solaris", "amd64"}, {"wasip1", "wasm"}, {"windows", "386"},
	{"windows", "amd64"}, {"windows", "arm64"},
}

// platformBuild is what one platform beside the host builds of a module that the host does not.
type platformBuild struct {
	Platform goPlatform
	// Dirs are the directories of the packages holding such a file, sorted.
	Dirs []string
	// Files are those files, the non-test Go files the host skips and this platform builds, by
	// absolute path.
	Files map[string]bool
	// Imports says one of the files imports a package outside the standard library, which is what
	// govulncheck's run for the platform is for: a call into a dependency only that platform makes.
	Imports bool
}

// modulePlatforms is the code of a module the host does not build, by the platform that does.
type modulePlatforms struct {
	// Builds are the platforms of analyzedGoPlatforms, the host left out, that build a file the host
	// does not, in that order.
	Builds []platformBuild
	// Unbuilt are the files, by absolute path and sorted, that the host skips and no platform of
	// Builds builds, while some other platform of goPorts does.
	Unbuilt []string
}

// goModulePlatforms finds the code of the module at mod, as `go list ./...` would walk it, that the
// host does not build and another platform does, under the build tags given.
//
// Directories `./...` passes by are passed by here too: vendor/, testdata/, any whose name starts
// with `.` or `_`, and a module nested inside, which is planned on its own. Test files are left out,
// as gosec and govulncheck leave them out.
//
// A platform beside the host builds without cgo, as the go command does when it builds for another
// platform, so a file importing "C" is never counted as its code.
func goModulePlatforms(mod string, tags []string, host goPlatform) modulePlatforms {
	hostCtx := goBuildContext(host, tags)
	hostCtx.CgoEnabled = build.Default.CgoEnabled
	var targets []goPlatform
	for _, p := range analyzedGoPlatforms {
		if p.OS != host.OS {
			targets = append(targets, p)
		}
	}
	builds := make([]platformBuild, len(targets))
	for i, p := range targets {
		builds[i] = platformBuild{Platform: p, Files: map[string]bool{}}
	}
	var unbuilt []string
	_ = filepath.WalkDir(mod, func(p string, d fs.DirEntry, err error) error {
		switch {
		case err != nil:
			return filepath.SkipDir
		case d.IsDir():
			return walkModuleDir(mod, p, d)
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		dir := filepath.Dir(p)
		// A file whose constraints cannot be read is the host's to report, as govulncheck runs and says why.
		if match, err := hostCtx.MatchFile(dir, name); match || err != nil {
			return nil
		}
		built := false
		for i, t := range targets {
			ctx := goBuildContext(t, tags)
			if match, _ := ctx.MatchFile(dir, name); !match {
				continue
			}
			built = true
			b := &builds[i]
			b.Files[p] = true
			if !slices.Contains(b.Dirs, dir) {
				b.Dirs = append(b.Dirs, dir)
			}
			b.Imports = b.Imports || importsBeyondStd(p)
		}
		if !built && builtForAPort(dir, name, tags) {
			unbuilt = append(unbuilt, p)
		}
		return nil
	})
	var out modulePlatforms
	for _, b := range builds {
		if len(b.Files) > 0 {
			slices.Sort(b.Dirs)
			out.Builds = append(out.Builds, b)
		}
	}
	slices.Sort(unbuilt)
	out.Unbuilt = unbuilt
	return out
}

// walkModuleDir is goModulePlatforms' answer for a directory: skip the ones `go list ./...` does not
// enter in the module at mod.
func walkModuleDir(mod, p string, d fs.DirEntry) error {
	switch d.Name() {
	case "vendor", "testdata", ".git":
		return filepath.SkipDir
	}
	if p == mod {
		return nil
	}
	if strings.HasPrefix(d.Name(), ".") || strings.HasPrefix(d.Name(), "_") {
		return filepath.SkipDir
	}
	if _, err := os.Stat(filepath.Join(p, "go.mod")); err == nil {
		return filepath.SkipDir
	}
	return nil
}

// goBuildContext is the go command's build context for p, with tags and without cgo.
func goBuildContext(p goPlatform, tags []string) build.Context {
	ctx := build.Default
	ctx.GOOS, ctx.GOARCH = p.OS, p.Arch
	ctx.CgoEnabled = false
	ctx.BuildTags = tags
	return ctx
}

// builtForAPort reports whether any platform the go command builds for builds the file.
func builtForAPort(dir, name string, tags []string) bool {
	for _, p := range goPorts {
		ctx := goBuildContext(p, tags)
		if match, _ := ctx.MatchFile(dir, name); match {
			return true
		}
	}
	return false
}

// importsBeyondStd reports whether the Go file at path imports a package outside the standard
// library, one whose path starts with a domain. "C" is cgo's, and the standard library's own.
func importsBeyondStd(path string) bool {
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
	if err != nil {
		// A file that does not parse is one govulncheck's run will say why it could not load.
		return true
	}
	for _, imp := range f.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			continue
		}
		first, _, _ := strings.Cut(p, "/")
		if strings.Contains(first, ".") {
			return true
		}
	}
	return false
}

// goPlatformFlag marks a run planned for a platform beside the host. Draugr's, never a tool's:
// onGoPlatform takes it off the command line and sets GOOS and GOARCH in its place.
const goPlatformFlag = "-draugr-platform="

// withGoPlatform is argv for a run over p rather than the host.
func withGoPlatform(argv []string, p goPlatform) []string {
	return append([]string{argv[0], goPlatformFlag + p.String()}, argv[1:]...)
}

// goPlatformOf is the platform a run's argv is planned for, and false for the host.
func goPlatformOf(argv []string) (goPlatform, bool) {
	for _, a := range argv {
		if v, ok := strings.CutPrefix(a, goPlatformFlag); ok {
			goos, goarch, _ := strings.Cut(v, "/")
			return goPlatform{goos, goarch}, true
		}
	}
	return goPlatform{}, false
}

// goPlatformKey carries a run's platform beside the host in its context, for a step that changes
// what it runs over with it (onGosecPackages).
type goPlatformKey struct{}

// runGoPlatform is the platform the run in ctx is for, and false for the host.
func runGoPlatform(ctx context.Context) (goPlatform, bool) {
	p, ok := ctx.Value(goPlatformKey{}).(goPlatform)
	return p, ok
}

// onGoPlatform runs a command planned for a platform beside the host with goPlatformFlag taken off
// and GOOS and GOARCH set to that platform, and CGO_ENABLED=0, as the go command builds for another
// platform. A command planned for the host runs as it is.
func onGoPlatform(run func(ctx context.Context, dir string, argv, env []string) ([]byte, error)) func(ctx context.Context, dir string, argv, env []string) ([]byte, error) {
	return func(ctx context.Context, dir string, argv, env []string) ([]byte, error) {
		p, ok := goPlatformOf(argv)
		if !ok {
			return run(ctx, dir, argv, env)
		}
		argv = slices.DeleteFunc(slices.Clone(argv), func(a string) bool { return strings.HasPrefix(a, goPlatformFlag) })
		env = append(slices.Clip(env), "GOOS="+p.OS, "GOARCH="+p.Arch, "CGO_ENABLED=0")
		return run(context.WithValue(ctx, goPlatformKey{}, p), dir, argv, env)
	}
}
