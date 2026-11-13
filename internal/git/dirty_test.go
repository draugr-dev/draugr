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

	// A URL has no working tree, and a directory that is not a repository cannot answer.
	// Neither is an error, because this only ever decorates a warning.
	if n := UncommittedFiles(ctx, "https://github.com/acme/web.git"); n != 0 {
		t.Errorf("remote url: got %d, want 0", n)
	}
	if n := UncommittedFiles(ctx, t.TempDir()); n != 0 {
		t.Errorf("not a repository: got %d, want 0", n)
	}
}

// Reports Draugr writes inside the repository are its own output, not work the scan left out: the
// default folder whether or not this run writes there, and the folder this run writes to. A file
// the reader added beside them still counts, and a folder outside the repository changes nothing.
func TestUncommittedFilesLeavesOutDraugrsOwnReports(t *testing.T) {
	repo, _ := initRepo(t)
	write := func(rel string) {
		t.Helper()
		p := filepath.Join(repo, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(".draugr/out/report.json")
	write("reports/results.sarif")
	ctx := WithOwnOutput(context.Background(), filepath.Join(repo, "reports"), t.TempDir(), "")
	if n := UncommittedFiles(ctx, repo); n != 0 {
		t.Errorf("only Draugr's reports: got %d, want 0", n)
	}
	if n := UncommittedFiles(context.Background(), repo); n != 1 {
		t.Errorf("a folder this run does not write to: got %d, want 1", n)
	}
	write(".draugr/fragments/web.yaml")
	if n := UncommittedFiles(ctx, repo); n != 1 {
		t.Errorf("a fragment beside the reports: got %d, want 1", n)
	}
}
