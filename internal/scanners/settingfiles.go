package scanners

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/draugr-dev/draugr/pkg/plugin"
)

// What a scanner's settings and its checkout's configuration files decide about what it finds.
//
// A ruleset a setting names is read from where Draugr runs, and the configuration files at the root
// of a checkout are read by the tool on its own. Neither is the descriptor, and both change what a
// scan finds: a ruleset edited in place under the setting that names it, an allowlist added to
// `.gitleaks.toml`. So each scanner names the files its settings point it at (plugin.SettingFiler),
// and the files at the root of its checkout it honors without listing what they keep from it, and
// the engine records both.

// settingPaths are the entries of a setting that names files, trimmed, empty ones left out.
func settingPaths(values ...string) []string {
	var out []string
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// gitleaksSettingFiles is the ruleset config names, where it names one.
func gitleaksSettingFiles(cfg plugin.Config) []string {
	v, _ := cfg["config"].(string)
	return settingPaths(v)
}

// semgrepSettingFiles is the ruleset config names where it is a file or directory on disk. A
// registry ruleset or a URL is Semgrep's to fetch, and nothing here can read it.
func semgrepSettingFiles(cfg plugin.Config) []string {
	v, _ := cfg["config"].(string)
	if _, remote := semgrepRemoteHost(strings.TrimSpace(v)); remote {
		return nil
	}
	return settingPaths(v)
}

// trivyConfigSettingFiles are the check files and directories checks names.
func trivyConfigSettingFiles(cfg plugin.Config) []string {
	return settingPaths(stringList(cfg, "checks")...)
}

// SettingFiles are the template files and directories templates names (implements
// plugin.SettingFiler). A URL is refused before a scan runs, so it is never one of them.
func (s nucleiScanner) SettingFiles(cfg plugin.Config) []string {
	var out []string
	for _, p := range settingPaths(stringList(cfg, "templates")...) {
		if !strings.Contains(p, "://") {
			out = append(out, p)
		}
	}
	return out
}

// semgrepIgnoreFile is the file Semgrep reads for paths to leave out of the scan, at the root of the
// tree it scans and in every directory below it, as git reads a .gitignore.
const semgrepIgnoreFile = ".semgrepignore"

// semgrepUnlisted names every .semgrepignore the checkout holds, by its path from the root, sorted.
// Semgrep leaves the files each one names out of the scan and its report says nothing of what they
// held. A directory that cannot be read is one Semgrep cannot read either.
func semgrepUnlisted(dir string, _ plugin.Config) []string {
	var out []string
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		switch {
		case err != nil:
			return nil
		case d.IsDir() && d.Name() == ".git":
			return filepath.SkipDir
		case d.IsDir() || d.Name() != semgrepIgnoreFile:
			return nil
		}
		if info, err := os.Stat(path); err != nil || !info.Mode().IsRegular() {
			return nil
		}
		if rel, err := filepath.Rel(dir, path); err == nil {
			out = append(out, filepath.ToSlash(rel))
		}
		return nil
	})
	slices.Sort(out)
	return out
}

// gitleaksUnlisted names .gitleaks.toml where the scan extends it and it holds an allowlist.
// Gitleaks drops what an allowlist matches before writing its report, so the allowed findings are
// in no run's output; the extra runs that record allow comments and .gitleaksignore cannot see
// them either, since the allowlist holds in every run. A ruleset the descriptor names replaces the
// file, and then it is not read at all.
func gitleaksUnlisted(dir string, cfg plugin.Config) []string {
	if configPath(cfg, "config") != "" {
		return nil
	}
	path, err := gitleaksRepoRuleset(dir)
	if err != nil || path == "" {
		return nil
	}
	b, err := os.ReadFile(path) // #nosec G304 -- the checkout's own ruleset, resolved inside it
	if err != nil || !gitleaksDeclaresAllowlist(b) {
		return nil
	}
	return []string{gitleaksRepoConfig}
}

// gitleaksDeclaresAllowlist reports whether a Gitleaks TOML ruleset declares an allowlist: a table
// header naming one, `[allowlist]`, `[[allowlists]]`, `[rules.allowlist]` or
// `[[rules.allowlists]]`, or a key that sets one, `allowlist = { … }` or `allowlist.paths = […]`.
// A comment that mentions the word declares nothing.
//
// Read line by line rather than parsed, with no TOML parser among the dependencies. A line inside a
// multi-line string that reads like a declaration counts as one, which errs toward saying the file
// may have kept something.
func gitleaksDeclaresAllowlist(toml []byte) bool {
	names := func(dotted string) bool {
		for part := range strings.SplitSeq(dotted, ".") {
			part = strings.Trim(strings.TrimSpace(part), `"'`)
			if part == "allowlist" || part == "allowlists" {
				return true
			}
		}
		return false
	}
	for line := range bytes.Lines(toml) {
		text := strings.TrimSpace(string(line))
		switch {
		case text == "" || strings.HasPrefix(text, "#"):
			continue
		case strings.HasPrefix(text, "["):
			header, _, _ := strings.Cut(strings.Trim(text, "[ "), "]")
			if names(header) {
				return true
			}
		default:
			if key, _, ok := strings.Cut(text, "="); ok && names(key) {
				return true
			}
		}
	}
	return false
}
