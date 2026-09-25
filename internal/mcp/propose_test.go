package mcp

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/draugr-dev/draugr/internal/builtins"
	"github.com/draugr-dev/draugr/internal/sagatest"
)

// tree writes files under root, creating their directories.
func tree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for rel, content := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// listing is every path under root, so a test can tell whether a call wrote anything.
func listing(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(root, func(path string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		out = append(out, path)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// propose calls the handler and holds what it returns to validate_saga and the editor schema, the
// two things the descriptor meets next.
func propose(t *testing.T, root string, in ProposeInput) ProposeOutput {
	t.Helper()
	_, out, err := ProposeSagaTool(root)(context.Background(), nil, in)
	if err != nil {
		t.Fatal(err)
	}
	_, v, err := ValidateSagaTool(context.Background(), nil, ValidateInput{Content: out.Saga})
	if err != nil {
		t.Fatal(err)
	}
	if !v.Valid {
		t.Fatalf("propose_saga returned a descriptor validate_saga refuses: %s\n%s", v.Error, out.Saga)
	}
	sagatest.EditorAccepts(t, []byte(out.Saga), false)
	return out
}

// A Go module and a package.json propose the controls init enables for them, and the tool writes
// nothing.
func TestProposeSagaReturnsWhatInitWouldWrite(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "Shop.API")
	tree(t, dir, map[string]string{
		"go.mod":       "module shop\n\nrequire golang.org/x/text v0.3.0\n",
		"main.go":      "package main\n",
		"package.json": `{"dependencies": {"left-pad": "1.0.0"}}`,
	})
	before := listing(t, root)

	out := propose(t, root, ProposeInput{Path: "Shop.API"})

	if want := []string{"iac", "sast", "sca", "secrets"}; !slices.Equal(out.Controls, want) {
		t.Errorf("controls = %v, want %v", out.Controls, want)
	}
	if !slices.Equal(out.Components, []string{"shop-api"}) {
		t.Errorf("components = %v, want the directory's name folded to a project name", out.Components)
	}
	for _, want := range []string{
		"project: shop-api\n",
		"analyzers: [govulncheck]",
		"gosec:\n        enabled: true     # Go-specific checks · go.mod\n",
		"# Unread · package.json no lockfile",
	} {
		if !strings.Contains(out.Saga, want) {
			t.Errorf("descriptor missing %q:\n%s", want, out.Saga)
		}
	}
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(resolved, "draugr.saga.yaml"); out.Path != want {
		t.Errorf("path = %q, want %q", out.Path, want)
	}
	if len(out.Existing) != 0 || !strings.Contains(out.Note, "not written to disk") ||
		!strings.Contains(out.Note, "validate_saga") || out.Warning != "" {
		t.Errorf("a fresh directory should get the next step and nothing else: %+v", out)
	}
	if after := listing(t, root); !slices.Equal(before, after) {
		t.Errorf("propose_saga wrote to disk:\nbefore %v\nafter  %v", before, after)
	}
}

// Two directories with their own dependency files give two components beside the root one, each
// scoped to its directory.
func TestProposeSagaPerDirectoryGivesAComponentPerDirectory(t *testing.T) {
	root := t.TempDir()
	tree(t, root, map[string]string{
		"shop/api/go.mod":            "module api\n\nrequire golang.org/x/net v0.1.0\n",
		"shop/web/package.json":      `{"dependencies": {"left-pad": "1.0.0"}}`,
		"shop/web/package-lock.json": `{"lockfileVersion": 3, "packages": {}}`,
	})
	out := propose(t, root, ProposeInput{Path: "shop", PerDirectory: true})
	if want := []string{"shop", "api", "web"}; !slices.Equal(out.Components, want) {
		t.Errorf("components = %v, want %v", out.Components, want)
	}
	for _, want := range []string{"paths: [api]", "paths: [web]", "ignore: [api/, web/]"} {
		if !strings.Contains(out.Saga, want) {
			t.Errorf("descriptor missing %q:\n%s", want, out.Saga)
		}
	}

	// Without perDirectory the same tree is one component.
	if one := propose(t, root, ProposeInput{Path: "shop"}); len(one.Components) != 1 {
		t.Errorf("without perDirectory: components = %v", one.Components)
	}
}

// perDirectory on a tree with no directory to split cannot do what it was asked, and says so.
func TestProposeSagaPerDirectoryWithNothingToSplitSaysSo(t *testing.T) {
	root := filepath.Join(t.TempDir(), "shop")
	tree(t, root, map[string]string{"go.mod": "module shop\n\nrequire golang.org/x/text v0.3.0\n"})
	out := propose(t, root, ProposeInput{PerDirectory: true})
	if len(out.Components) != 1 || !strings.Contains(out.Warning, "one component") {
		t.Errorf("want one component and a warning saying why: %+v", out)
	}
}

// A directory that already holds a descriptor still gets a proposal, and the answer names the file
// that is there, so it does not read as a replacement for it.
func TestProposeSagaReportsAnExistingDescriptor(t *testing.T) {
	root := filepath.Join(t.TempDir(), "shop")
	tree(t, root, map[string]string{
		"go.mod":           "module shop\n",
		"draugr.saga.yaml": "project: shop\ncomponents:\n  - name: shop\n",
		"sub/x.saga.yaml":  "project: nested\n",
	})
	out := propose(t, root, ProposeInput{})
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{filepath.Join(resolved, "draugr.saga.yaml")}; !slices.Equal(out.Existing, want) {
		t.Errorf("existing = %v, want %v", out.Existing, want)
	}
	if !strings.Contains(out.Note, "already holds a descriptor") || !strings.Contains(out.Note, "validate_saga") {
		t.Errorf("the note should name the existing descriptor and point at validate_saga: %q", out.Note)
	}
}

// A path that leaves the directory the server was started in is refused, whether it is absolute,
// climbs out with .., or follows a symlink out.
func TestProposeSagaRefusesAPathOutsideTheRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "root")
	outside := t.TempDir()
	tree(t, root, map[string]string{"go.mod": "module shop\n"})
	tree(t, outside, map[string]string{"go.mod": "module elsewhere\n"})
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	climb, err := filepath.Rel(root, outside)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{outside, "..", climb, "link"} {
		_, _, err := ProposeSagaTool(root)(context.Background(), nil, ProposeInput{Path: path})
		if err == nil || !strings.Contains(err.Error(), "outside") {
			t.Errorf("path %q: err = %v, want a refusal naming the root", path, err)
		}
	}
}

// A path that is missing, or is a file, is an error naming the path.
func TestProposeSagaNeedsADirectory(t *testing.T) {
	root := t.TempDir()
	tree(t, root, map[string]string{"go.mod": "module shop\n"})
	for path, want := range map[string]string{"missing": "missing", "go.mod": "is a file"} {
		_, _, err := ProposeSagaTool(root)(context.Background(), nil, ProposeInput{Path: path})
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("path %q: err = %v, want %q", path, err, want)
		}
	}
	if _, _, err := ProposeSagaTool(filepath.Join(root, "gone"))(context.Background(), nil, ProposeInput{}); err == nil {
		t.Error("a root that does not exist should be an error")
	}
}

// Over a session, with no path, the tool reads the root the server was given.
func TestProposeSagaDefaultsToTheServerRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "payments")
	tree(t, root, map[string]string{"go.mod": "module payments\n"})
	sess := connect(t, Options{Registry: builtins.Registry(), Root: root})
	res, err := sess.CallTool(context.Background(), &mcp.CallToolParams{Name: "propose_saga"})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("propose_saga errored: %+v", res.Content)
	}
	var out ProposeOutput
	decode(t, res, &out)
	if !strings.Contains(out.Saga, "project: payments\n") {
		t.Errorf("the descriptor should describe the server root:\n%s", out.Saga)
	}
}
