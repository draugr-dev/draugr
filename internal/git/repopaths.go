package git

import (
	"context"
	"path"
	"path/filepath"
)

// RepositoryPaths returns a function naming a file by its path in the work tree that holds dir,
// slash-separated, and saying false for a file outside that work tree, or for any file when dir is
// in none.
//
// Answered by git rather than by comparing strings, so a symbolic link, a relative path and a
// working directory below the root all name the file the way the repository does. Git is asked
// nothing until a file is named, and about each directory once.
func RepositoryPaths(ctx context.Context, dir string) func(file string) (string, bool) {
	type answer struct {
		root, rel string
		ok        bool
	}
	asked := map[string]answer{}
	ask := func(d string) answer {
		a, seen := asked[d]
		if !seen {
			a.root, a.rel, a.ok = Subdirectory(ctx, d)
			asked[d] = a
		}
		return a
	}
	return func(file string) (string, bool) {
		home := ask(dir)
		at := ask(filepath.Dir(file))
		if !home.ok || !at.ok || at.root != home.root {
			return "", false
		}
		return path.Join(at.rel, filepath.Base(file)), true
	}
}
