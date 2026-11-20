package git

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// A file is named by its path from the root of the work tree the directory is in, whichever
// directory of it that is, and a file in another work tree, or in none, is not named.
func TestRepositoryPathsNamesFilesInTheSameWorkTree(t *testing.T) {
	repo, _ := initRepo(t)
	nested := filepath.Join(repo, "deploy", "saga")
	if err := os.MkdirAll(nested, 0o750); err != nil {
		t.Fatal(err)
	}
	other, _ := initRepo(t)
	outside := t.TempDir()
	for _, dir := range []string{repo, nested} {
		in := RepositoryPaths(context.Background(), dir)
		for file, want := range map[string]string{
			filepath.Join(repo, "draugr.saga.yaml"):         "draugr.saga.yaml",
			filepath.Join(nested, "api.saga-fragment.yaml"): "deploy/saga/api.saga-fragment.yaml",
			filepath.Join(other, "draugr.saga.yaml"):        "",
			filepath.Join(outside, "draugr.saga.yaml"):      "",
		} {
			got, ok := in(file)
			if got != want || ok != (want != "") {
				t.Errorf("from %s, %s: %q, %v; want %q", dir, file, got, ok, want)
			}
		}
	}
	none := RepositoryPaths(context.Background(), outside)
	if got, ok := none(filepath.Join(repo, "draugr.saga.yaml")); ok {
		t.Errorf("from a directory in no work tree: %q", got)
	}
}
