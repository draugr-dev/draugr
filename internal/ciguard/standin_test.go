package ciguard

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestTestsWriteExecutablesThroughStandin keeps a test from writing a script with os.WriteFile and
// then running it.
//
// That pair fails now and then with "text file busy": another test starting a program at the same
// moment forks a child that holds the half-written file open until it execs, and Linux will not run
// a file that is open for writing. The failure is rare enough to pass a pull request and then fail a
// merge-queue run for a change that had nothing to do with it. standin.Write writes the file so that
// no fork can catch it open.
//
// The check reads every test file for os.WriteFile with a literal mode that sets an execute bit.
func TestTestsWriteExecutablesThroughStandin(t *testing.T) {
	t.Parallel()

	root := repoPath("")
	var read int
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// testdata holds fixture repositories, vendored code among them, that are scanned rather
			// than compiled with this module.
			if name := d.Name(); name == ".git" || name == "vendor" || name == "testdata" || name == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		if filepath.ToSlash(filepath.Dir(rel)) == "internal/standin" {
			return nil
		}
		read++
		for _, line := range executableWrites(t, path) {
			t.Errorf("%s:%d writes an executable with os.WriteFile; use standin.Write, which a "+
				"program started at the same moment by another test cannot catch half-written", rel, line)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk the tree: %v", err)
	}
	if read < 100 {
		t.Fatalf("read %d test files, which means the walk is in the wrong tree and would pass whatever "+
			"the tests did", read)
	}
}

// executableWrites returns the lines of path that call os.WriteFile with a literal mode carrying an
// execute bit.
func executableWrites(t *testing.T, path string) []int {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Errorf("parse %s: %v", path, err)
		return nil
	}
	var lines []int
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 3 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "WriteFile" {
			return true
		}
		if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "os" {
			return true
		}
		lit, ok := call.Args[2].(*ast.BasicLit)
		if !ok || lit.Kind != token.INT {
			return true
		}
		if mode, err := strconv.ParseUint(lit.Value, 0, 32); err == nil && mode&0o111 != 0 {
			lines = append(lines, fset.Position(call.Pos()).Line)
		}
		return true
	})
	return lines
}

// The check finds the call it exists for, and leaves an ordinary file alone.
func TestExecutableWritesFindsTheCall(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "x_test.go")
	src := "package x\n\nimport \"os\"\n\nfunc f() {\n" +
		"\t_ = os.WriteFile(\"a\", nil, 0o600)\n" +
		"\t_ = os.WriteFile(\"b\", nil, 0o700)\n" +
		"\t_ = os.WriteFile(\"c\", nil, 0755)\n}\n"
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := executableWrites(t, path); len(got) != 2 || got[0] != 7 || got[1] != 8 {
		t.Errorf("executableWrites = %v, want [7 8]", got)
	}
}
