package git

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestIsLocalPath(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "f")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cases := map[string]bool{
		"":                                   false,
		"https://github.com/acme/web.git":    false,
		"ssh://git@github.com/acme/web.git":  false,
		"git@github.com:acme/web.git":        false,
		dir:                                  true,
		file:                                 false, // a file is not a checkout
		filepath.Join(dir, "does-not-exist"): false,
	}
	for url, want := range cases {
		if got := IsLocalPath(url); got != want {
			t.Errorf("IsLocalPath(%q) = %v, want %v", url, got, want)
		}
	}
}

func TestUncommittedFiles(t *testing.T) {
	ctx := context.Background()
	repo, _ := initRepo(t)

	if n := UncommittedFiles(ctx, repo); n != 0 {
		t.Errorf("clean repository: got %d, want 0", n)
	}

	// Modified and untracked both count: neither is in the revision that gets scanned.
	if err := os.WriteFile(filepath.Join(repo, "file.txt"), []byte("two\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "b.txt"), []byte("new\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if n := UncommittedFiles(ctx, repo); n != 2 {
		t.Errorf("dirty repository: got %d, want 2", n)
	}

	// A URL has no working tree, and a directory that is not a repository cannot answer —
	// neither is an error, because this only ever decorates a warning.
	if n := UncommittedFiles(ctx, "https://github.com/acme/web.git"); n != 0 {
		t.Errorf("remote url: got %d, want 0", n)
	}
	if n := UncommittedFiles(ctx, t.TempDir()); n != 0 {
		t.Errorf("not a repository: got %d, want 0", n)
	}
}
