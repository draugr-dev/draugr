// Command npm-audit turns what `npm audit --json` writes into a Draugr converter file, for an
// import with format draugr-converter.
//
// npm audit writes no SARIF, and Draugr has no reader for its JSON, so a converter is the route by
// which its findings reach a report. This one sets each finding's package, with its installed
// version from package-lock.json, the version that fixes it and its package URL, and the CWE ids the
// advisory names. Draugr never runs it: a CI step does, and Draugr reads the file it writes.
//
// Usage:
//
//	npm audit --json > npm-audit.json
//	go run github.com/draugr-dev/draugr/contrib/converters/npm-audit \
//	  -audit npm-audit.json -lock package-lock.json -commit "$GITHUB_SHA" -o npm-audit.draugr.json
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/draugr-dev/draugr/pkg/converter"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, time.Now))
}

// run is the command, with its output and clock passed in so a test drives it: 0 when the file is
// written, 1 when a file could not be read or converted, 2 for a usage error.
func run(args []string, stdout, stderr io.Writer, now func() time.Time) int {
	fs := flag.NewFlagSet("npm-audit", flag.ContinueOnError)
	fs.SetOutput(stderr)
	auditPath := fs.String("audit", "", "the JSON npm audit --json wrote (required)")
	lockPath := fs.String("lock", "package-lock.json", "the lockfile npm audit read, relative to the repository's root")
	commit := fs.String("commit", "", "the commit npm audit ran on, such as $GITHUB_SHA (required)")
	repository := fs.String("repository", "", "the repository npm audit ran in, where the importing component has several")
	out := fs.String("o", "", "the file to write; standard output when empty")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *auditPath == "" || *commit == "" {
		_, _ = fmt.Fprintln(stderr, "npm-audit: -audit and -commit are required")
		fs.Usage()
		return 2
	}
	if err := write(*auditPath, *lockPath, *commit, *repository, *out, stdout, now); err != nil {
		_, _ = fmt.Fprintln(stderr, "npm-audit:", err)
		return 1
	}
	return 0
}

// write converts the audit and writes the file, after reading it back as Draugr will: a file this
// converter writes is one the import accepts, or no file is written.
func write(auditPath, lockPath, commit, repository, out string, stdout io.Writer, now func() time.Time) error {
	auditData, err := os.ReadFile(auditPath) // #nosec G304 -- the file the CI step names
	if err != nil {
		return err
	}
	lockData, err := os.ReadFile(lockPath) // #nosec G304 -- the file the CI step names
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	doc, err := convert(auditData, lockData, options{
		auditPath: filepath.ToSlash(auditPath), lockPath: filepath.ToSlash(filepath.Clean(lockPath)),
		commit: commit, repository: repository,
		written: now().UTC().Truncate(time.Second).Format(time.RFC3339),
	})
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if _, err := converter.Read(data, sets); err != nil {
		return fmt.Errorf("the file breaks the contract, %w", err)
	}
	if out == "" {
		_, err = stdout.Write(data)
		return err
	}
	return os.WriteFile(out, data, 0o600) // #nosec G703 -- the file the CI step names with -o
}
