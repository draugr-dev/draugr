package scanners

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/git"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// writeInto writes one file, by its path from dir.
func writeInto(t *testing.T, dir, path, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, path), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// configDetail is what a report's provenance records under prefix, by the path after it.
func configDetail(rep sarif.Report, prefix string) map[string]string {
	out := map[string]string{}
	for _, p := range rep.Provenance {
		for _, d := range p.Detail {
			if name, ok := strings.CutPrefix(d.Key, prefix); ok {
				out[name] = d.Value
			}
		}
	}
	return out
}

// A repository scan records the scanners' configuration files at the root of the checkout it read,
// by a digest of each, from a real checkout of each of two repositories. A component scoped to a
// subtree still has the root's files, which the tools read, and a file of the same name in the
// subtree is not one the tools read there. A file that is not there is not recorded.
func TestARepositoryScanRecordsTheConfigFilesItsCheckoutHeld(t *testing.T) {
	api := writeTree(t, map[string]string{
		".trivyignore":              "CVE-2024-0001\n",
		".grype/config.yaml":        "ignore: []\n",
		".grype/other.yaml":         "not read\n",
		".semgrepignore":            "tests/\n",
		"services/api/.trivyignore": "CVE-2024-0002\n",
		"services/api/main.py":      "print('x')\n",
		"services/web/main.py":      "print('y')\n",
	})
	web := writeTree(t, map[string]string{".gitleaksignore": "abc:def:1\n", "main.go": "package main\n"})
	repoAt(t, api)
	repoAt(t, web)

	s := repoScanner{
		info:     plugin.ScannerInfo{Name: "semgrep"},
		args:     func(dir string, _ plugin.Config) []string { return []string{"semgrep", dir} },
		checkout: git.Checkout,
		run: func(context.Context, string, []string) ([]byte, error) {
			return []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"semgrep"}},"results":[]}]}`), nil
		},
		unlisted: semgrepUnlisted,
	}
	rep, err := s.Scan(context.Background(), plugin.RepositoryTarget{URL: api, Paths: []string{"services/api"}}, plugin.Config{})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		".trivyignore":       git.ContentDigest([]byte("CVE-2024-0001\n")),
		".grype/config.yaml": git.ContentDigest([]byte("ignore: []\n")),
		".semgrepignore":     git.ContentDigest([]byte("tests/\n")),
	}
	if got := configDetail(rep, sarif.DetailConfigFile); !reflect.DeepEqual(got, want) {
		t.Errorf("api's files = %v\nwant %v", got, want)
	}
	if got := configDetail(rep, sarif.DetailUnlistedSetAside); !reflect.DeepEqual(got, map[string]string{".semgrepignore": "semgrep"}) {
		t.Errorf("api's unlisted = %v", got)
	}

	rep, err = s.Scan(context.Background(), plugin.RepositoryTarget{URL: web}, plugin.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if got := configDetail(rep, sarif.DetailConfigFile); !reflect.DeepEqual(got, map[string]string{".gitleaksignore": git.ContentDigest([]byte("abc:def:1\n"))}) {
		t.Errorf("web's files = %v", got)
	}
	if got := configDetail(rep, sarif.DetailUnlistedSetAside); len(got) != 0 {
		t.Errorf("web holds no .semgrepignore and records %v", got)
	}
}

// A run that fails over one module still records the files its checkout held, beside the files it
// left unread.
func TestAFailedRunRecordsTheConfigFiles(t *testing.T) {
	dir := writeTree(t, map[string]string{".trivyignore": "CVE-1\n"})
	s := repoScanner{info: plugin.ScannerInfo{Name: "gosec"}, checkout: func(context.Context, string, string, git.Scope) (git.Tree, func(), error) {
		return git.Tree{Dir: dir}, func() {}, nil
	}}
	rep, err := s.failedRun(dir, plugin.RepositoryTarget{URL: "r/api"}, git.Tree{Dir: dir}, nil, os.ErrClosed)
	if err == nil || len(rep.Provenance) != 0 {
		t.Fatalf("a scanner that names no unread files returns the failure alone: %+v, %v", rep, err)
	}
	s.unreadOnFailure = func(string, error) []sarif.Input { return []sarif.Input{{Path: "go.mod", Unread: "failed"}} }
	rep, _ = s.failedRun(dir, plugin.RepositoryTarget{URL: "r/api"}, git.Tree{Dir: dir}, nil, os.ErrClosed)
	if got := configDetail(rep, sarif.DetailConfigFile); got[".trivyignore"] != git.ContentDigest([]byte("CVE-1\n")) {
		t.Errorf("files = %v", got)
	}
}

// Each scanner whose settings name a file on disk says which, as written, and leaves out a ruleset
// it fetches.
func TestScannersNameTheFilesTheirSettingsPointAt(t *testing.T) {
	for _, tc := range []struct {
		name    string
		scanner plugin.Scanner
		cfg     plugin.Config
		want    []string
	}{
		{"gitleaks config", NewGitleaks(), plugin.Config{"config": " security/gitleaks.toml "}, []string{"security/gitleaks.toml"}},
		{"gitleaks without config", NewGitleaks(), plugin.Config{}, nil},
		{"semgrep ruleset on disk", NewSemgrep(), plugin.Config{"config": "rules/x.yml"}, []string{"rules/x.yml"}},
		{"semgrep registry ruleset", NewSemgrep(), plugin.Config{"config": "p/default"}, nil},
		{"semgrep ruleset at a URL", NewSemgrep(), plugin.Config{"config": "https://example.com/rules.yml"}, nil},
		{"trivy-config checks", NewTrivyConfig(), plugin.Config{"checks": []any{"checks/a.rego", " ", "checks/b"}},
			[]string{"checks/a.rego", "checks/b"}},
		{"nuclei templates", NewNuclei(), plugin.Config{"templates": []any{"templates/", "https://example.com/t.yaml"}},
			[]string{"templates/"}},
		{"a scanner whose settings name no file", NewTrivyFS(), plugin.Config{"config": "x"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			filer, ok := tc.scanner.(plugin.SettingFiler)
			if !ok {
				t.Fatalf("%s does not name the files its settings point at", tc.scanner.Info().Name)
			}
			if got := filer.SettingFiles(tc.cfg); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("files = %q, want %q", got, tc.want)
			}
		})
	}
}

// .semgrepignore and a .gitleaks.toml allowlist keep findings from their scanner without listing
// them, so each is named where the checkout holds it and the scanner reads it.
func TestTheFilesThatKeepFindingsUnlistedAreNamed(t *testing.T) {
	dir := t.TempDir()
	if got := semgrepUnlisted(dir, nil); got != nil {
		t.Errorf("semgrep with no .semgrepignore: %v", got)
	}
	if got := gitleaksUnlisted(dir, plugin.Config{}); got != nil {
		t.Errorf("gitleaks with no .gitleaks.toml: %v", got)
	}
	writeInto(t, dir, ".semgrepignore", "tests/\n")
	writeInto(t, dir, ".gitleaks.toml", "[extend]\nuseDefault = true\n")
	if got := semgrepUnlisted(dir, nil); !reflect.DeepEqual(got, []string{".semgrepignore"}) {
		t.Errorf("semgrep = %v", got)
	}
	if got := gitleaksUnlisted(dir, plugin.Config{}); got != nil {
		t.Errorf("a .gitleaks.toml without an allowlist: %v", got)
	}
	writeInto(t, dir, ".gitleaks.toml", "[extend]\nuseDefault = true\n[allowlist]\npaths = ['''x''']\n")
	if got := gitleaksUnlisted(dir, plugin.Config{}); !reflect.DeepEqual(got, []string{".gitleaks.toml"}) {
		t.Errorf("a .gitleaks.toml with an allowlist: %v", got)
	}
	if got := gitleaksUnlisted(dir, plugin.Config{"config": "shared/gitleaks.toml"}); got != nil {
		t.Errorf("a ruleset the descriptor names replaces the file, and still: %v", got)
	}
}
