package scanners

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/draugr-dev/draugr/internal/tools"
)

//go:embed gitleaks_rules.toml
var gitleaksRules string

// gitleaksExtendDefault tells Gitleaks to keep its own ruleset and add ours to it.
const gitleaksExtendDefault = "[extend]\nuseDefault = true"

// gitleaksConfigFor materializes the ruleset a scan should run with, and returns its path.
//
// Draugr's own rule is added whether or not the descriptor named a configuration. Replacing the
// user's ruleset would lose their rules; ignoring ours when they have one would mean the token
// this exists to catch is undetected in exactly the repositories somebody has configured most
// carefully. Gitleaks can extend from a file, so both are true at once.
//
// Written under the tools data directory rather than a temp file with a lifetime: it is a public
// ruleset, not a secret, and one stable path means a scan does not leave a file behind per run.
func gitleaksConfigFor(userConfig string) (string, error) {
	extend := gitleaksExtendDefault
	if userConfig != "" {
		abs, err := filepath.Abs(userConfig)
		if err != nil {
			return "", fmt.Errorf("gitleaks config %q: %w", userConfig, err)
		}
		// Named by absolute path, because Gitleaks resolves it relative to its own working
		// directory rather than to ours — and a relative path here silently extends nothing.
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
	// One file per distinct configuration, so two projects with different rulesets in one process
	// do not overwrite each other's between planning and running.
	name := "draugr.toml"
	if userConfig != "" {
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
	root, err := tools.DataRoot()
	if err != nil {
		return "", fmt.Errorf("gitleaks config dir: %w", err)
	}
	return filepath.Join(root, "gitleaks"), nil
}

// configFingerprint names a composed configuration by its content.
func configFingerprint(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:4])
}
