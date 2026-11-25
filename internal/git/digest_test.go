package git

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// A file is named by its content and a directory by every file under it, so an edit, an addition
// or a rename anywhere under it gives another name. Nothing there is not named.
func TestPathDigestNamesAFileOrADirectory(t *testing.T) {
	dir := t.TempDir()
	write := func(rel, body string) {
		t.Helper()
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("rules.yml", "rules: []")
	write("rules/a.yml", "rules: [a]")
	write("rules/sub/b.yml", "rules: [b]")

	file, ok := PathDigest(filepath.Join(dir, "rules.yml"))
	if !ok || file != ContentDigest([]byte("rules: []")) || len(file) != 16 {
		t.Errorf("file digest = %q, %v", file, ok)
	}
	if _, ok := PathDigest(filepath.Join(dir, "missing.yml")); ok {
		t.Error("a missing file was named")
	}

	names := map[string]bool{}
	name := func() string {
		t.Helper()
		d, ok := PathDigest(filepath.Join(dir, "rules"))
		if !ok || len(d) != 16 {
			t.Fatalf("directory digest = %q, %v", d, ok)
		}
		names[d] = true
		return d
	}
	first := name()
	if again := name(); again != first {
		t.Errorf("one directory named %q then %q", first, again)
	}
	write("rules/sub/b.yml", "rules: [c]")
	name()
	write("rules/c.yml", "rules: [c]")
	name()
	if err := os.Rename(filepath.Join(dir, "rules/c.yml"), filepath.Join(dir, "rules/d.yml")); err != nil {
		t.Fatal(err)
	}
	name()
	if len(names) != 4 {
		t.Errorf("%d names for four states of the directory", len(names))
	}

	// A file under it that cannot be read still stands in its listing.
	if err := os.Chmod(filepath.Join(dir, "rules/d.yml"), 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(dir, "rules/d.yml"), 0o600) })
	if os.Getuid() != 0 {
		if d, _ := PathDigest(filepath.Join(dir, "rules")); names[d] {
			t.Error("an unreadable file named the directory as before")
		}
		if d, ok := PathDigest(filepath.Join(dir, "rules/d.yml")); !ok || d != ContentDigest([]byte(unreadable)) {
			t.Errorf("an unreadable file = %q, %v", d, ok)
		}
	}
}

// The scanners' configuration names every file a tool reads from the root of its tree, and a scoped
// checkout keeps the directory that holds one, with nothing else in it.
func TestRootConfigIsKeptByAScopedCheckout(t *testing.T) {
	names := RootConfig()
	if !slices.Contains(names, ".grype/config.yaml") || !slices.Contains(names, ".trivyignore") {
		t.Errorf("root config = %v", names)
	}
	names[0] = "changed"
	if RootConfig()[0] == "changed" {
		t.Error("RootConfig hands out the list itself")
	}
	keep := []string{"services/api"}
	for _, tc := range []struct {
		rel   string
		isDir bool
		want  bool
	}{
		{".grype", true, true},
		{".grype/config.yaml", false, true},
		{".grype/other.yaml", false, false},
		{".github", true, false},
		{"services/api/.trivyignore", false, true},
		{"services/web/.trivyignore", false, false},
	} {
		if got := withinPaths(tc.rel, keep, tc.isDir); got != tc.want {
			t.Errorf("withinPaths(%q) = %v, want %v", tc.rel, got, tc.want)
		}
	}
}
