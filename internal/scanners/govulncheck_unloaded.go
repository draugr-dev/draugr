package scanners

import (
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"regexp"
	"slices"
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
			GoMod: gomod, Reason: unloadedReason(root, stderr),
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

// unloadedReason is the caveat's reason for a module that did not load: its first diagnostic.
func unloadedReason(root, stderr string) string {
	return "not loaded by govulncheck: " + firstLoadDiagnostic(root, stderr)
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
