package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/draugr-dev/draugr/internal/builtins"
	"github.com/draugr-dev/draugr/internal/sagafetch"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// sagaGlob is what Draugr recognises as a Saga: the file *type*, not one filename. A repo
// commonly holds several — one per service, or per environment.
const sagaGlob = "*.saga.yaml"

func newValidateCommand() *cobra.Command {
	var resolved bool
	cmd := &cobra.Command{
		Use:   "validate [saga.yaml | glob ...]",
		Short: "Validate one or more Saga descriptors against the schema",
		Long: "Parse each Saga descriptor, resolve ${{ VAR }} references, and check it against\n" +
			"the schema — without running any scanners. Fast and dependency-free, so it fits\n" +
			"a pre-commit hook, a CI lint step, or an editor.\n\n" +
			"Accepts paths and globs, and with no arguments discovers *.saga.yaml (and .yml)\n" +
			"beneath the current directory. Reports every file, then exits non-zero if any\n" +
			"one of them is invalid.",
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if resolved {
				return runResolved(args, cmd.OutOrStdout())
			}
			return runValidate(args, cmd.OutOrStdout())
		},
	}
	cmd.Flags().BoolVar(&resolved, "resolved", false,
		"print the descriptor with every fragment merged, instead of validating quietly")
	return cmd
}

// runResolved prints one descriptor as it stands after resolution.
//
// Deliberately one file. The output is itself a valid descriptor, and concatenating several would
// produce a stream that is not — the one property that makes this worth piping.
func runResolved(args []string, w io.Writer) error {
	paths, err := resolveSagaPaths(args)
	if err != nil {
		return err
	}
	switch {
	case len(paths) == 0:
		return fmt.Errorf("no Saga files found (looked for %s); pass a path explicitly", sagaGlob)
	case len(paths) > 1:
		return fmt.Errorf("--resolved prints one descriptor, but %d matched — name the one you "+
			"want, since the output is itself a descriptor and several concatenated would not be",
			len(paths))
	}
	fetcher := sagafetch.New(context.Background())
	defer fetcher.Close()

	res, err := saga.ResolveFile(paths[0], fetcher)
	if err != nil {
		return err
	}
	if err := checkControlNames(builtins.Registry(), res.Model); err != nil {
		return err
	}
	return printResolved(w, res)
}

// runValidate validates every Saga the arguments resolve to. Each file is reported on its own
// line so a failure in one doesn't hide the others, and the command fails if any did.
func runValidate(args []string, w io.Writer) error {
	paths, err := resolveSagaPaths(args)
	if err != nil {
		return err
	}
	if len(paths) == 0 {
		return fmt.Errorf("no Saga files found (looked for %s); pass a path explicitly", sagaGlob)
	}

	// One file keeps the original shape: the loader's error is returned as-is, so the CLI prints
	// it as `draugr: <problem>`. Fanning out to a per-file report only helps when there are files
	// to tell apart.
	if len(paths) == 1 {
		if err := loadAndCheck(paths[0]); err != nil {
			return err
		}
		_, _ = fmt.Fprintf(w, "✓ %s is valid\n", paths[0])
		return nil
	}

	var failed int
	for _, p := range paths {
		if err := loadAndCheck(p); err != nil {
			failed++
			// Strip the loader's own path prefix: the file is already the line's subject.
			_, _ = fmt.Fprintf(w, "✗ %s\n    %s\n", p, strings.TrimPrefix(err.Error(), p+": "))
			continue
		}
		_, _ = fmt.Fprintf(w, "✓ %s is valid\n", p)
	}

	if failed > 0 {
		return fmt.Errorf("%d of %d Saga file(s) invalid", failed, len(paths))
	}
	if len(paths) > 1 {
		_, _ = fmt.Fprintf(w, "\n%d Saga file(s) valid\n", len(paths))
	}
	return nil
}

// resolveSagaPaths expands arguments into a de-duplicated, ordered list of files. A literal
// path is taken as-is (so a mistyped filename reports "not found" rather than silently matching
// nothing); anything containing a glob metacharacter is expanded; no arguments means discover.
func resolveSagaPaths(args []string) ([]string, error) {
	if len(args) == 0 {
		return discoverSagas(".")
	}
	seen := map[string]bool{}
	var out []string
	for _, arg := range args {
		if !strings.ContainsAny(arg, "*?[") {
			if !seen[arg] {
				seen[arg] = true
				out = append(out, arg)
			}
			continue
		}
		matches, err := filepath.Glob(arg)
		if err != nil {
			return nil, fmt.Errorf("bad pattern %q: %w", arg, err)
		}
		if len(matches) == 0 {
			return nil, fmt.Errorf("no files match %q", arg)
		}
		sort.Strings(matches)
		for _, m := range matches {
			if !seen[m] {
				seen[m] = true
				out = append(out, m)
			}
		}
	}
	return out, nil
}

// discoverSagas walks root for *.saga.yaml / *.saga.yml, skipping directories that never hold
// hand-written config so a large repo doesn't pay for the walk.
func discoverSagas(root string) ([]string, error) {
	skip := map[string]bool{".git": true, "node_modules": true, "vendor": true, "dist": true}
	var out []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skip[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if name := d.Name(); isSagaFile(name) || IsFragmentFile(name) {
			out = append(out, filepath.Clean(path))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(out)
	return out, nil
}

// loadAndCheck is what `draugr validate` asks of a descriptor: that it parses, and that every
// control it names is one this build can run.
//
// Separate from loadSaga because validate *is* the check — loadSaga's error tells the reader to
// run validate, which would be circular here.
func loadAndCheck(path string) error {
	// A fragment is checked as a fragment. Held to the Saga's rules it would fail on a missing
	// release, which every valid fragment lacks — and a fragment that only validates once merged
	// is one nobody can check before merging it.
	if IsFragmentFile(filepath.Base(path)) {
		data, err := os.ReadFile(path) // #nosec G304 -- operator-provided path, by design
		if err != nil {
			return fmt.Errorf("read fragment %q: %w", path, err)
		}
		_, err = saga.LoadFragment(data, path)
		return err
	}
	fetcher := sagafetch.New(context.Background())
	defer fetcher.Close()

	res, err := saga.ResolveFile(path, fetcher)
	if err != nil {
		return err
	}
	return checkControlNames(builtins.Registry(), res.Model)
}

// isSagaFile reports whether a filename is a Saga descriptor.
func isSagaFile(name string) bool {
	return strings.HasSuffix(name, ".saga.yaml") || strings.HasSuffix(name, ".saga.yml")
}

// IsFragmentFile reports whether a filename is a Saga fragment.
//
// A distinct file type rather than a convention, because editors decide which schema to apply
// from the name: the Saga schema requires a release, so a fragment named `*.saga.yaml` would be
// flagged as invalid in every editor that reads the published catalogue.
func IsFragmentFile(name string) bool {
	return strings.HasSuffix(name, ".saga-fragment.yaml") || strings.HasSuffix(name, ".saga-fragment.yml")
}
