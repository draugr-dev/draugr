package git

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// layout is a repository whose root is a Go module holding two services and the code they share,
// a frontend with no Go code, a nested module of its own, and vendored and testdata trees that
// hold go.mod files no build reads.
var layout = []string{
	"go.mod",
	"go.sum",
	"cmd/api/main.go",
	"cmd/admin/main.go",
	"internal/store/store.go",
	"web/package.json",
	"web/src/app.ts",
	"tools/lint/go.mod",
	"tools/lint/main.go",
	"vendor/example.com/dep/go.mod",
	"vendor/example.com/dep/dep.go",
	"internal/store/testdata/fixture/go.mod",
	"",
}

func TestModuleRootsIn(t *testing.T) {
	for _, tc := range []struct {
		name  string
		paths []string
		want  []string
	}{
		{"a directory of Go code selects its module", []string{"cmd/api/**"}, []string{"."}},
		{"two directories in one module select it once", []string{"cmd/api", "cmd/admin"}, []string{"."}},
		{"a file selected by name", []string{"cmd/api/main.go"}, []string{"."}},
		{"a directory with no Go code selects nothing", []string{"web/**"}, nil},
		{"a go.mod named alone selects its module", []string{"go.mod"}, []string{"."}},
		{"a nested module is its own", []string{"tools/lint/**"}, []string{"tools/lint"}},
		{"a manifest and code across two modules", []string{"go.mod", "tools/lint"}, []string{".", "tools/lint"}},
		{"vendored and testdata manifests are not modules", []string{"vendor/example.com/dep/**", "internal/store/testdata/**"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := moduleRootsIn(layout, "go.mod", selected(tc.paths))
			if !slices.Equal(got, tc.want) {
				t.Errorf("moduleRootsIn(%v) = %v, want %v", tc.paths, got, tc.want)
			}
		})
	}
}

func TestModuleRootsInNoModule(t *testing.T) {
	if got := moduleRootsIn([]string{"main.go", "web/app.ts"}, "go.mod", []string{"main.go"}); got != nil {
		t.Errorf("a repository with no go.mod: got %v, want nil", got)
	}
}

func TestInnermostModule(t *testing.T) {
	modules := []string{".", "tools/lint", "tools/lint/sub"}
	for file, want := range map[string]string{
		"cmd/api/main.go":          ".",
		"tools/lint/main.go":       "tools/lint",
		"tools/lint/sub/x.go":      "tools/lint/sub",
		"tools/lintx/main.go":      ".",
		"tools/lint/sub/deep/a.go": "tools/lint/sub",
	} {
		if got, ok := InnermostModule(file, modules); !ok || got != want {
			t.Errorf("InnermostModule(%q) = %q, %v; want %q", file, got, ok, want)
		}
	}
	if _, ok := InnermostModule("cmd/api/main.go", []string{"tools/lint"}); ok {
		t.Error("a file in no module was placed in one")
	}
}

// modulesRepo commits layout, then leaves an uncommitted module on disk.
func modulesRepo(t *testing.T) (dir, head string) {
	t.Helper()
	dir, _ = initRepo(t)
	for _, f := range layout {
		if f == "" {
			continue
		}
		if err := os.MkdirAll(filepath.Join(dir, filepath.Dir(f)), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	runGit(t, dir, "add", ".")
	runGit(t, dir, "commit", "-q", "-m", "modules")
	out := runGit(t, dir, "rev-parse", "HEAD")
	head = string(out[:len(out)-1])
	if err := os.MkdirAll(filepath.Join(dir, "cmd", "new"), 0o750); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"cmd/new/go.mod", "cmd/new/main.go"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir, head
}

func TestModuleRoots(t *testing.T) {
	ctx := context.Background()
	dir, head := modulesRepo(t)

	for name, rev := range map[string]string{"pinned": head, "branch": "main", "default": ""} {
		t.Run(name, func(t *testing.T) {
			got, err := ModuleRoots(ctx, dir, rev, false, "go.mod", []string{"cmd/api/**", "tools/lint/**", "cmd/new/**"})
			if err != nil {
				t.Fatal(err)
			}
			// cmd/new is on disk and not in the commit, so a committed scan does not see it.
			if want := []string{".", "tools/lint"}; !slices.Equal(got, want) {
				t.Errorf("roots = %v, want %v", got, want)
			}
		})
	}

	t.Run("working tree", func(t *testing.T) {
		got, err := ModuleRoots(ctx, dir, "", true, "go.mod", []string{"cmd/new/**"})
		if err != nil {
			t.Fatal(err)
		}
		if want := []string{"cmd/new"}; !slices.Equal(got, want) {
			t.Errorf("roots = %v, want %v", got, want)
		}
	})

	t.Run("not widened", func(t *testing.T) {
		for name, args := range map[string]struct {
			url      string
			manifest string
			paths    []string
		}{
			"remote":      {"file://" + dir, "go.mod", []string{"cmd/api"}},
			"no manifest": {dir, "", []string{"cmd/api"}},
			"root":        {dir, "go.mod", []string{"."}},
			"no paths":    {dir, "go.mod", nil},
		} {
			got, err := ModuleRoots(ctx, args.url, "", false, args.manifest, args.paths)
			if err != nil || got != nil {
				t.Errorf("%s: got %v, %v; want nil, nil", name, got, err)
			}
		}
	})

	t.Run("unknown revision", func(t *testing.T) {
		if _, err := ModuleRoots(ctx, dir, "no-such-ref", false, "go.mod", []string{"cmd/api"}); err == nil {
			t.Error("an unreadable revision returned no error")
		}
	})
}
