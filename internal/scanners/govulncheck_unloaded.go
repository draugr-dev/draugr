package scanners

import (
	"context"
	"encoding/json"
	"errors"
	"go/ast"
	"go/build"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	pathpkg "path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// govulncheckUnloaded is a Go module govulncheck could not load, as Draugr records it in the stream.
type govulncheckUnloaded struct {
	// GoMod is the module's go.mod, relative to the checkout.
	GoMod string `json:"goMod"`
	// Reason is why it did not load, from govulncheck's diagnostics.
	Reason string `json:"reason"`
}

// onUnloaded turns a run over a module govulncheck could not load into a record of that module, so
// the modules that loaded keep their verdicts.
//
// One module that does not compile, needs a C library the machine lacks, or holds generated code
// nobody generated says nothing about the others in the repository, and failing the job over it
// would discard every analysis already made. The module is named instead as a file the analysis did
// not cover, and its findings keep the band the manifest scanner gave them, with no verdict.
//
// Only a load failure is recorded this way. Anything else govulncheck fails on, a database it
// cannot reach or a flag it refuses, holds for every module, and still fails the job.
func onUnloaded(run func(ctx context.Context, root string, argv []string) ([]byte, error)) func(ctx context.Context, root string, argv []string) ([]byte, error) {
	return func(ctx context.Context, root string, argv []string) ([]byte, error) {
		out, err := run(ctx, root, argv)
		i := slices.Index(argv, "-C")
		stderr, ok := govulncheckLoadFailure(err)
		if !ok || i < 0 || i+1 >= len(argv) {
			return out, err
		}
		mod := argv[i+1]
		gomod := "go.mod"
		if rel, ok := relSlash(root, mod); ok && rel != "." {
			gomod = rel + "/go.mod"
		}
		// The run's own output is left out: it is a config message for a run that analyzed nothing.
		msg, err := json.Marshal(govulncheckMessage{Unloaded: &govulncheckUnloaded{
			GoMod: gomod, Reason: unloadedReason(root, mod, stderr),
		}})
		if err != nil {
			return nil, err
		}
		return append(msg, '\n'), nil
	}
}

// govulncheckLoadFailure returns govulncheck's stderr where err is its exit over a module whose
// packages did not load, and false for any other error.
func govulncheckLoadFailure(err error) (string, bool) {
	exit, ok := errors.AsType[*exec.ExitError](err)
	if !ok {
		return "", false
	}
	stderr := string(exit.Stderr)
	if strings.Contains(stderr, "govulncheck: loading packages:") ||
		strings.Contains(stderr, "govulncheck: no packages matched the provided patterns") {
		return stderr, true
	}
	return "", false
}

// unloadedReason is the caveat's reason for a module that did not load, mod in the checkout at root:
// what to do about it, where govulncheck's diagnostics show what is missing, and otherwise its first
// diagnostic.
//
// The action leads, because the console cuts a long reason short. Three causes have one:
//
//   - A cgo package whose C header or pkg-config library is not installed. The fix is the library's
//     development package; building without cgo is not, because the packages behind the cgo files
//     then fail on identifiers those files declare.
//   - An identifier a file of the package declares behind a build tag, a stub for generated assets
//     being the common case. GOFLAGS carries the tag to the go command govulncheck runs.
//   - An identifier nothing in the checkout declares, which is code the build generates. Draugr
//     cannot generate it, so the one setting that changes the outcome is the analyzer itself.
//
// Any other cause is reported as the diagnostic alone: a line that names no action is better than
// one that names the wrong one.
func unloadedReason(root, mod, stderr string) string {
	const lead = "not loaded by govulncheck: "
	if action, ok := cgoAction(stderr); ok {
		return lead + action
	}
	if action, ok := undefinedAction(root, mod, stderr); ok {
		return lead + action
	}
	return lead + firstLoadDiagnostic(root, stderr)
}

// missingHeader is the C compiler's report of a header it could not find.
var missingHeader = regexp.MustCompile(`fatal error: (\S+): No such file or directory`)

// missingPkgConfig is pkg-config's report of a library it has no .pc file for, in either of the
// two forms it prints.
var missingPkgConfig = regexp.MustCompile(`^Package '?([^'\s]+?)'?(?: was not found in the pkg-config search path|, required by '[^']*', not found)`)

// cgoAction names what a cgo package needs installed: the first package in stderr that names a
// missing header or pkg-config library, with what it is missing. False where stderr holds no cgo
// failure, or one that names nothing to install.
func cgoAction(stderr string) (string, bool) {
	if !strings.Contains(stderr, "could not import C") {
		return "", false
	}
	pkg, needer, header := "", "", ""
	var libs []string
	for _, line := range strings.Split(stderr, "\n") {
		line = strings.TrimSpace(line)
		if p, ok := strings.CutPrefix(line, "-: # "); ok {
			if needer != "" {
				break
			}
			pkg = p
			continue
		}
		if m := missingHeader.FindStringSubmatch(line); m != nil && header == "" {
			needer, header = pkg, m[1]
		}
		if m := missingPkgConfig.FindStringSubmatch(line); m != nil && !slices.Contains(libs, m[1]) {
			needer, libs = pkg, append(libs, m[1])
		}
	}
	var what, verb string
	switch {
	case header != "":
		what, verb = "install the development package for "+header, " includes"
	case len(libs) == 1:
		what, verb = "install the development package for "+libs[0], " needs"
	case len(libs) > 1:
		what, verb = "install the development packages for "+strings.Join(libs, ", "), " needs"
	default:
		return "", false
	}
	if needer != "" {
		what += ", which " + needer + verb
	}
	return what, true
}

// undefinedDiagnostic is a type checker's report of an identifier no file in the build declares, as
// `file.go:line:col: undefined: pkg.Name` or `undefined: Name`.
var undefinedDiagnostic = regexp.MustCompile(`(?m)^\s*(\S+\.go):\d+:\d+: undefined: (?:(\w+)\.)?(\w+)\s*$`)

// undefinedAction names the build tag that brings in a declaration the build is missing, or, where
// no file in the checkout declares it behind a tag, offers taking govulncheck out of the analysis.
// False where stderr reports no undefined identifier.
func undefinedAction(root, mod, stderr string) (string, bool) {
	first := ""
	for _, m := range undefinedDiagnostic.FindAllStringSubmatch(stderr, -1) {
		file, qualifier, name := m[1], m[2], m[3]
		if !filepath.IsAbs(file) {
			file = filepath.Join(mod, file)
		}
		if first == "" {
			first = trimLoadPaths(root, strings.TrimSpace(m[0]))
		}
		if decl, tag, ok := taggedDeclaration(root, file, qualifier, name); ok {
			ident := name
			if qualifier != "" {
				ident = qualifier + "." + name
			}
			declRel, _ := relSlash(root, decl)
			return "set GOFLAGS=-tags=" + tag + ", under which " + declRel + " declares " + ident, true
		}
	}
	if first == "" {
		return "", false
	}
	return first + "; to stop analyzing Go, remove govulncheck from config.reachability.analyzers", true
}

// taggedDeclaration finds the file that declares name in the package file refers to by qualifier,
// or in file's own package for none, and that a build tag keeps out of the default build. It returns
// that file and the tag. Only a package inside the checkout at root is read.
func taggedDeclaration(root, file, qualifier, name string) (decl, tag string, ok bool) {
	if _, inside := relSlash(root, file); !inside {
		return "", "", false
	}
	dir := filepath.Dir(file)
	if qualifier != "" {
		if dir, ok = importedDir(root, file, qualifier); !ok {
			return "", "", false
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", "", false
	}
	ctx := build.Default
	ctx.BuildTags = goflagsTags(os.Getenv("GOFLAGS"))
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		if in, err := ctx.MatchFile(dir, n); err != nil || in {
			continue
		}
		path := filepath.Join(dir, n)
		for _, t := range buildTags(path) {
			with := ctx
			with.BuildTags = append(slices.Clone(ctx.BuildTags), t)
			if in, err := with.MatchFile(dir, n); err == nil && in && declares(path, name) {
				return path, t, true
			}
		}
	}
	return "", "", false
}

// importedDir is the directory, inside the checkout at root, of the package file imports under
// qualifier: the import named so, or whose last path element is.
func importedDir(root, file, qualifier string) (string, bool) {
	f, err := parser.ParseFile(token.NewFileSet(), file, nil, parser.ImportsOnly)
	if err != nil {
		return "", false
	}
	for _, imp := range f.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			continue
		}
		// A package is named for the last element of its path, the one before a major version suffix.
		local := pathpkg.Base(path)
		if majorSuffix.MatchString(local) {
			local = pathpkg.Base(pathpkg.Dir(path))
		}
		if imp.Name != nil {
			local = imp.Name.Name
		}
		if local != qualifier {
			continue
		}
		modDir, modPath, ok := enclosingModule(root, filepath.Dir(file))
		if !ok {
			return "", false
		}
		if path == modPath {
			return modDir, true
		}
		if rest, ok := strings.CutPrefix(path, modPath+"/"); ok {
			return filepath.Join(modDir, filepath.FromSlash(rest)), true
		}
		return "", false
	}
	return "", false
}

// majorSuffix is the last element of a module path at major version 2 or later, such as v2.
var majorSuffix = regexp.MustCompile(`^v([2-9]|[1-9]\d+)$`)

// enclosingModule is the directory and path of the module dir belongs to, looking no higher than
// root.
func enclosingModule(root, dir string) (string, string, bool) {
	for d := dir; ; d = filepath.Dir(d) {
		if _, inside := relSlash(root, d); !inside {
			return "", "", false
		}
		if p := goModulePath(filepath.Join(d, "go.mod")); p != "" {
			return d, p, true
		}
		if filepath.Dir(d) == d {
			return "", "", false
		}
	}
}

// buildTags lists the tags a file's `//go:build` line names, apart from `ignore`, which marks a file
// never meant to be built.
func buildTags(path string) []string {
	raw, err := os.ReadFile(path) // #nosec G304 -- a Go file in the checkout
	if err != nil {
		return nil
	}
	var tags []string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "package ") {
			break
		}
		if !constraint.IsGoBuild(line) {
			continue
		}
		expr, err := constraint.Parse(line)
		if err != nil {
			return nil
		}
		tags = constraintTags(expr, tags)
	}
	return tags
}

// constraintTags appends the tags expr names to tags, each once and in the order written.
func constraintTags(expr constraint.Expr, tags []string) []string {
	switch e := expr.(type) {
	case *constraint.TagExpr:
		if e.Tag != "ignore" && !slices.Contains(tags, e.Tag) {
			tags = append(tags, e.Tag)
		}
	case *constraint.NotExpr:
		tags = constraintTags(e.X, tags)
	case *constraint.AndExpr:
		tags = constraintTags(e.Y, constraintTags(e.X, tags))
	case *constraint.OrExpr:
		tags = constraintTags(e.Y, constraintTags(e.X, tags))
	}
	return tags
}

// declares reports whether the Go file at path declares name at package level.
func declares(path, name string) bool {
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
	if err != nil {
		return false
	}
	for _, d := range f.Decls {
		switch d := d.(type) {
		case *ast.FuncDecl:
			if d.Recv == nil && d.Name.Name == name {
				return true
			}
		case *ast.GenDecl:
			for _, s := range d.Specs {
				switch s := s.(type) {
				case *ast.TypeSpec:
					if s.Name.Name == name {
						return true
					}
				case *ast.ValueSpec:
					for _, n := range s.Names {
						if n.Name == name {
							return true
						}
					}
				}
			}
		}
	}
	return false
}

// firstLoadDiagnostic is the first thing govulncheck's stderr says went wrong: the first compiler
// diagnostic, `file.go:line:col: message`, or else the first line that is not part of its framing,
// with the checkout and the module cache taken off each path.
func firstLoadDiagnostic(root, stderr string) string {
	first := ""
	for _, line := range strings.Split(stderr, "\n") {
		line = strings.TrimSpace(line)
		if rest, ok := strings.CutPrefix(line, "govulncheck:"); ok {
			line = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(rest), "loading packages:"))
		}
		switch {
		case line == "", strings.HasPrefix(line, "#"), strings.HasPrefix(line, "-: #"),
			line == "There are errors with the provided package patterns:",
			strings.HasPrefix(line, "For details on package patterns"):
			continue
		case goDiagnosticLine.MatchString(line):
			return trimLoadPaths(root, line)
		case first == "":
			first = line
		}
	}
	if first == "" {
		return "no diagnostic"
	}
	return trimLoadPaths(root, first)
}

// goDiagnosticLine is a compiler diagnostic: `file.go:line:col: message`, or `file.go:line: message`.
var goDiagnosticLine = regexp.MustCompile(`^\S+\.go:\d+(?::\d+)?: `)

// moduleCachePath is a path into the module cache, up to the module it names.
var moduleCachePath = regexp.MustCompile(`\S*/pkg/mod/`)

// trimLoadPaths makes the paths in a diagnostic readable on another machine: a file in the checkout
// relative to it, and a file in the module cache from the module path on.
func trimLoadPaths(root, line string) string {
	if root != "" {
		line = strings.ReplaceAll(line, strings.TrimSuffix(root, "/")+"/", "")
	}
	return moduleCachePath.ReplaceAllString(line, "")
}
