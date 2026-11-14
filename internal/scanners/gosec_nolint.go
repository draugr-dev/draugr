package scanners

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// A Go project that runs gosec through golangci-lint marks a line it reviewed with a `nolint` comment
// naming gosec, the directive golangci-lint reads, and gosec run on its own reads only `#nosec`. Left
// as it is, every line the maintainer already reviewed comes back as a new finding, with nothing to
// say a decision exists. So a gosec result a `//nolint` covering gosec reaches is marked suppressed in
// source, as a `#nosec` result is, with the text after the directive as its justification.
//
// The directive reaches less here than in golangci-lint, which applies one above a function or above
// `package` to everything inside it. A comment's say-so can set aside the line it names and no more,
// or a single line above a function would silence every finding in it. So a directive, bare, `:all`
// or naming gosec among its linters, covers:
//
//   - the line it ends, as a trailing comment;
//   - alone on its line, the first line of the statement or declaration that starts on the line
//     directly below it. A later line of that statement, a function's body, a file, and a line under
//     a blank line or another comment are not covered.
//
// `//nolint:` naming only other linters covers nothing.

// nolintDirective is golangci-lint's test for a nolint comment, applied after the leading slashes
// and spaces are trimmed.
var nolintDirective = regexp.MustCompile(`^nolint( |:|$)`)

// gosecLinterNames are the names golangci-lint accepts for gosec in a `//nolint:` list.
var gosecLinterNames = map[string]bool{"gosec": true, "gas": true, "all": true}

// markNolintSuppressed marks each unsuppressed result in rep on a line a `//nolint` covering gosec
// reaches as suppressed in source. Locations are relative to dir. A file that cannot be read or
// parsed leaves its results as they are: unmarked is the reading that claims nothing.
func markNolintSuppressed(rep *sarif.Report, dir string) {
	if dir == "" {
		return
	}
	files := map[string]map[int]string{}
	for i := range rep.Results {
		r := &rep.Results[i]
		uri := r.Location.URI
		if r.Suppression != nil || r.Location.StartLine == 0 || !filepath.IsLocal(filepath.FromSlash(uri)) {
			continue
		}
		lines, seen := files[uri]
		if !seen {
			lines = nolintLines(filepath.Join(dir, filepath.FromSlash(uri)))
			files[uri] = lines
		}
		if why, ok := lines[r.Location.StartLine]; ok {
			r.Suppression = &sarif.Suppression{Kind: "inSource", Justification: why, Origin: sarif.OriginTool}
		}
	}
}

// nolintLines reads the Go file at path and returns each line a nolint directive covering gosec
// reaches, with the directive's justification. Nil where it holds none or cannot be read.
func nolintLines(path string) map[int]string {
	src, err := os.ReadFile(path) // #nosec G304 -- a file gosec reported a result in, under the checkout
	if err != nil {
		return nil
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, parser.ParseComments|parser.SkipObjectResolution)
	if err != nil {
		return nil
	}
	tf := fset.File(f.Pos())
	lines := map[int]string{}
	var above map[int]string // directive line + 1 -> justification, for a directive alone on its line
	for _, g := range f.Comments {
		for _, c := range g.List {
			why, ok := nolintCoversGosec(c.Text)
			if !ok {
				continue
			}
			at := fset.Position(c.Pos())
			lineStart := tf.Offset(tf.LineStart(at.Line))
			if strings.TrimSpace(string(src[lineStart:at.Offset])) != "" {
				lines[at.Line] = why
				continue
			}
			if above == nil {
				above = map[int]string{}
			}
			above[at.Line+1] = why
		}
	}
	if len(above) == 0 {
		return lines
	}
	ast.Inspect(f, func(n ast.Node) bool {
		switch n.(type) {
		case ast.Stmt, ast.Decl, ast.Spec:
			line := fset.Position(n.Pos()).Line
			if why, ok := above[line]; ok {
				lines[line] = why
			}
		}
		return true
	})
	return lines
}

// nolintCoversGosec reports whether the comment text is a nolint directive that covers gosec, and
// the justification written after it.
func nolintCoversGosec(text string) (why string, ok bool) {
	text = strings.TrimLeft(text, "/ ")
	if !nolintDirective.MatchString(text) {
		return "", false
	}
	directive, why, _ := strings.Cut(text, "//")
	why = strings.TrimSpace(why)
	list, named := strings.CutPrefix(directive, "nolint:")
	if !named {
		// Bare `//nolint`, which covers every linter. Text after it is its reason.
		if why == "" {
			why = strings.TrimSpace(strings.TrimPrefix(directive, "nolint"))
		}
		return why, true
	}
	for item := range strings.SplitSeq(list, ",") {
		if gosecLinterNames[strings.ToLower(strings.TrimSpace(item))] {
			return why, true
		}
	}
	return "", false
}
