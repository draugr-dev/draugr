package scanners

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/draugr-dev/draugr/internal/tools"
)

//go:embed gitleaks_rules.toml
var gitleaksRules string

// gitleaksExtendDefault tells Gitleaks to keep its own ruleset and add ours to it.
const gitleaksExtendDefault = "[extend]\nuseDefault = true"

// gitleaksRepoConfig is the file Gitleaks reads from the root of the tree it scans when it is given
// no --config.
const gitleaksRepoConfig = ".gitleaks.toml"

// gitleaksRepoRuleset returns the absolute path of the scanned tree's own .gitleaks.toml, or ""
// when the tree holds none.
//
// Gitleaks reads that file only when it is given no --config, and every scan gives it Draugr's, so
// the composed ruleset extends it by name or the repository's own rules and allowlist never apply.
//
// A link is followed only while it stays inside the tree. The file is the repository's to write,
// so a link out of it would have the scan read a file on the machine running it, and quote it back
// in a parse error to whoever can read the job's log. An error says why the file was not used.
func gitleaksRepoRuleset(dir string) (string, error) {
	if dir == "" {
		return "", nil
	}
	root, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	path := filepath.Join(root, gitleaksRepoConfig)
	if _, err := os.Lstat(path); errors.Is(err, fs.ErrNotExist) {
		return "", nil
	} else if err != nil {
		return "", err
	}
	if root, err = filepath.EvalSymlinks(root); err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("%s is a link to nothing", gitleaksRepoConfig)
	}
	if rel, err := filepath.Rel(root, resolved); err != nil || !filepath.IsLocal(rel) {
		return "", fmt.Errorf("%s links outside the repository", gitleaksRepoConfig)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a file", gitleaksRepoConfig)
	}
	return resolved, nil
}

// gitleaksConfigFor materializes the ruleset a scan should run with, and returns its path. base is
// the ruleset it extends: the file the descriptor named, the repository's own, or "" for Gitleaks'
// built-in rules.
//
// Draugr's own rule is added whatever base is. Replacing the user's ruleset would lose their rules;
// ignoring ours when they have one would mean the token this exists to catch is undetected in
// exactly the repositories somebody has configured most carefully. Gitleaks can extend from a
// file, so both are true at once.
//
// Written under the tools data directory rather than a temp file with a lifetime: it is a public
// ruleset, not a secret, and one stable path means a scan does not leave a file behind per run.
func gitleaksConfigFor(base string) (string, error) {
	extend := gitleaksExtendDefault
	if base != "" {
		abs, err := filepath.Abs(base)
		if err != nil {
			return "", fmt.Errorf("gitleaks config %q: %w", base, err)
		}
		// Named by absolute path, because Gitleaks resolves it relative to its own working directory
		// rather than to ours, and a relative path here silently extends nothing.
		extend = fmt.Sprintf("[extend]\npath = %q", abs)
	}
	// A placeholder that cannot occur in prose. The obvious spelling matched the word inside this
	// file's own header comment, which produced a configuration Gitleaks refused to parse.
	const placeholder = "@@EXTEND@@"
	if !strings.Contains(gitleaksRules, placeholder) {
		return "", fmt.Errorf("gitleaks ruleset has no %s placeholder", placeholder)
	}
	body := strings.Replace(gitleaksRules, placeholder, extend, 1)

	dir, err := gitleaksConfigDir()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil { // #nosec G301 -- a public ruleset, read by the scanner
		return "", fmt.Errorf("gitleaks config dir: %w", err)
	}
	// One file per distinct configuration, so two projects or two repositories with different
	// rulesets in one process do not overwrite each other's between planning and running.
	name := "draugr.toml"
	if base != "" {
		name = fmt.Sprintf("draugr-%s.toml", configFingerprint(body))
	}
	path := filepath.Join(dir, name)

	// Rewritten only when it differs, so a scan does not touch the file on every run.
	if existing, err := os.ReadFile(path); err == nil && string(existing) == body { // #nosec G304 -- a path this function composed
		return path, nil
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil { // #nosec G306 -- a public ruleset, read by the scanner
		return "", fmt.Errorf("write gitleaks config: %w", err)
	}
	return path, nil
}

// gitleaksConfigDir is where the composed ruleset lives.
func gitleaksConfigDir() (string, error) {
	dir := tools.ScanDataDir("gitleaks")
	if dir == "" {
		return "", fmt.Errorf("gitleaks config dir: no home directory")
	}
	return dir, nil
}

// configFingerprint names a composed configuration by its content.
func configFingerprint(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:4])
}
