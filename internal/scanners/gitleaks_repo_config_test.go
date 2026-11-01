package scanners

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
)

// composedBody returns the ruleset an argv's --config names.
func composedBody(t *testing.T, argv []string) string {
	t.Helper()
	i := slices.Index(argv, "--config")
	if i < 0 || i+1 >= len(argv) {
		t.Fatalf("--config not passed: %v", argv)
	}
	return read(t, argv[i+1])
}

// repoWithRuleset makes a scanned tree holding its own .gitleaks.toml, and returns the tree and the
// file's resolved path, which is what the composed ruleset names.
func repoWithRuleset(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, ".gitleaks.toml")
	if err := os.WriteFile(path, []byte("title = \"theirs\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	return dir, resolved
}

// Gitleaks reads a tree's .gitleaks.toml only when it is given no --config, and every scan is given
// Draugr's. Two repositories in one run are the case worth checking: each has to be scanned with its
// own ruleset, and the one without a file with the built-in rules rather than its neighbor's.
func TestEachRepositorysOwnRulesetIsExtended(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	withFile, theirs := repoWithRuleset(t)
	without := t.TempDir()
	cfg := plugin.Config{"history": true}

	for pass, args := range map[string]func(string, plugin.Config) []string{
		"tree":    gitleaksArgs,
		"history": gitleaksHistoryArgs,
	} {
		t.Run(pass, func(t *testing.T) {
			own := composedBody(t, args(withFile, cfg))
			if !strings.Contains(own, "path = \""+theirs+"\"") {
				t.Errorf("the repository's .gitleaks.toml is not extended:\n%s", own)
			}
			if strings.Contains(own, "useDefault") {
				t.Error("the built-in rules were added over the repository's own choice about them")
			}
			if !strings.Contains(own, "draugr-ingest-token") {
				t.Error("Draugr's rule was dropped when the repository has its own ruleset")
			}

			plain := composedBody(t, args(without, cfg))
			if strings.Contains(plain, theirs) {
				t.Error("one repository's ruleset reached a repository that has none")
			}
			if !strings.Contains(plain, "useDefault = true") {
				t.Error("a repository with no ruleset must be scanned with Gitleaks' built-in rules")
			}
		})
	}
}

// A ruleset the descriptor names replaces the repository's, as --config does for Gitleaks run by
// hand. The schema says so, and this holds it to that.
func TestTheDescriptorsRulesetReplacesTheRepositorys(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir, theirs := repoWithRuleset(t)
	shared := filepath.Join(t.TempDir(), "shared.toml")
	if err := os.WriteFile(shared, []byte("title = \"shared\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	body := composedBody(t, gitleaksArgs(dir, plugin.Config{"config": shared}))
	if !strings.Contains(body, shared) {
		t.Errorf("the descriptor's ruleset is not extended:\n%s", body)
	}
	if strings.Contains(body, theirs) {
		t.Error("the repository's ruleset was read though the descriptor named one")
	}
}

// The file is the repository's to write, so a link in it could otherwise have the scan read a file
// on the machine running it and quote it back in a parse error.
func TestARepositoryRulesetIsReadOnlyInsideTheTree(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "elsewhere.toml")
	if err := os.WriteFile(outside, []byte("title = \"elsewhere\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	for name, tc := range map[string]struct {
		make    func(t *testing.T, dir string)
		want    string // the file returned, relative to the tree; "" for none
		refused string // the reason, when the file is not used
	}{
		"no file": {
			make: func(*testing.T, string) {},
		},
		"a file": {
			make: func(t *testing.T, dir string) {
				write(t, filepath.Join(dir, ".gitleaks.toml"))
			},
			want: ".gitleaks.toml",
		},
		"a link to a file inside the tree": {
			make: func(t *testing.T, dir string) {
				write(t, filepath.Join(dir, "config", "gitleaks.toml"))
				link(t, filepath.Join("config", "gitleaks.toml"), filepath.Join(dir, ".gitleaks.toml"))
			},
			want: filepath.Join("config", "gitleaks.toml"),
		},
		"a link outside the tree": {
			make: func(t *testing.T, dir string) {
				link(t, outside, filepath.Join(dir, ".gitleaks.toml"))
			},
			refused: "links outside the repository",
		},
		"a link to nothing": {
			make: func(t *testing.T, dir string) {
				link(t, "missing.toml", filepath.Join(dir, ".gitleaks.toml"))
			},
			refused: "a link to nothing",
		},
		"a directory": {
			make: func(t *testing.T, dir string) {
				if err := os.Mkdir(filepath.Join(dir, ".gitleaks.toml"), 0o750); err != nil {
					t.Fatal(err)
				}
			},
			refused: "not a file",
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			tc.make(t, dir)
			got, err := gitleaksRepoRuleset(dir)
			if tc.refused != "" {
				if err == nil || !strings.Contains(err.Error(), tc.refused) {
					t.Fatalf("error = %v, want one saying %q", err, tc.refused)
				}
				if got != "" {
					t.Errorf("returned %q alongside the refusal", got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			want := ""
			if tc.want != "" {
				root, err := filepath.EvalSymlinks(dir)
				if err != nil {
					t.Fatal(err)
				}
				want = filepath.Join(root, tc.want)
			}
			if got != want {
				t.Errorf("got %q, want %q", got, want)
			}
		})
	}

	if got, err := gitleaksRepoRuleset(""); got != "" || err != nil {
		t.Errorf("no tree gave %q, %v; want nothing", got, err)
	}
}

// A refused file is not a reason to skip the scan, and the composed ruleset is still passed, so
// Gitleaks does not go on to read the link itself.
func TestARefusedRepositoryRulesetScansWithTheBuiltInRules(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	outside := filepath.Join(t.TempDir(), "elsewhere.toml")
	write(t, outside)
	dir := t.TempDir()
	link(t, outside, filepath.Join(dir, ".gitleaks.toml"))

	var logged bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logged, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	cfg := plugin.Config{"history": true}
	for _, argv := range [][]string{gitleaksArgs(dir, cfg), gitleaksHistoryArgs(dir, cfg)} {
		body := composedBody(t, argv)
		if strings.Contains(body, outside) {
			t.Error("a ruleset outside the repository was extended")
		}
		if !strings.Contains(body, "useDefault = true") {
			t.Error("the scan should fall back to Gitleaks' built-in rules")
		}
	}

	if n := strings.Count(logged.String(), ".gitleaks.toml not read"); n != 1 {
		t.Errorf("warned %d times for one checkout, want once:\n%s", n, logged.String())
	}
	if !strings.Contains(logged.String(), "links outside the repository") {
		t.Errorf("the warning does not say why:\n%s", logged.String())
	}
}

// When the composed ruleset cannot be written, the scan still runs with the one it would have
// extended, which for a repository with its own file is that file.
func TestWithNoHomeTheRepositorysRulesetIsPassedDirectly(t *testing.T) {
	t.Setenv("HOME", "")
	dir, theirs := repoWithRuleset(t)
	argv := gitleaksArgs(dir, nil)
	i := slices.Index(argv, "--config")
	if i < 0 || i+1 >= len(argv) {
		t.Fatalf("--config not passed: %v", argv)
	}
	if argv[i+1] != theirs {
		t.Errorf("--config %s, want the repository's own %s", argv[i+1], theirs)
	}
}

func write(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("title = \"x\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func link(t *testing.T, target, at string) {
	t.Helper()
	if err := os.Symlink(target, at); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
}
