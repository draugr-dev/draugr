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
// naming gosec, the directive golangci-lint reads, and gosec run on its own reads only `#nosec`. Left as it is,
// every line the maintainer already reviewed comes back as a new finding, with nothing to say a
// decision exists. So a gosec result under a `//nolint` that covers gosec is marked suppressed in
// source, as a `#nosec` result is, with the text after the directive as its justification.
//
// Where the directive reaches follows golangci-lint, so a line counts as reviewed here exactly when
// it does there:
//
//   - A comment `//nolint` or `// nolint`, bare, `:all`, or naming gosec among its linters, covers
//     the lines of its comment group.
//   - A comment group that ends on the line before a node starting at the group's own column covers
//     that node too: a function, a statement, a declaration, or the whole file above `package`.
//   - `//nolint:` naming only other linters covers nothing here.

// nolintDirective is golangci-lint's test for a nolint comment, applied after the leading slashes
// and spaces are trimmed.
var nolintDirective = regexp.MustCompile(`^nolint( |:|$)`)

// gosecLinterNames are the names golangci-lint accepts for gosec in a `//nolint:` list.
var gosecLinterNames = map[string]bool{"gosec": true, "gas": true, "all": true}

// nolintRange is the lines of a file a nolint directive covering gosec reaches.
type nolintRange struct {
	from, to int
	// why is the text after the directive, empty where the comment gave none.
	why string
}

// markNolintSuppressed marks each unsuppressed result in rep that lies on a line a `//nolint`
// covering gosec reaches as suppressed in source. Locations are relative to dir. A file that cannot
// be read or parsed leaves its results as they are: unmarked is the reading that claims nothing.
func markNolintSuppressed(rep *sarif.Report, dir string) {
	if dir == "" {
		return
	}
	files := map[string][]nolintRange{}
	for i := range rep.Results {
		r := &rep.Results[i]
		uri := r.Location.URI
		if r.Suppression != nil || r.Location.StartLine == 0 || !filepath.IsLocal(filepath.FromSlash(uri)) {
			continue
		}
		ranges, seen := files[uri]
		if !seen {
			ranges = nolintRanges(filepath.Join(dir, filepath.FromSlash(uri)))
			files[uri] = ranges
		}
		for _, nr := range ranges {
			if r.Location.StartLine >= nr.from && r.Location.StartLine <= nr.to {
				r.Suppression = &sarif.Suppression{Kind: "inSource", Justification: nr.why, Origin: sarif.OriginTool}
				break
			}
		}
	}
}

// nolintRanges reads the Go file at path and returns the ranges its nolint directives covering
// gosec reach, nil where it holds none or cannot be read.
func nolintRanges(path string) []nolintRange {
	src, err := os.ReadFile(path) // #nosec G304 -- a file gosec reported a result in, under the checkout
	if err != nil {
		return nil
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, parser.ParseComments|parser.SkipObjectResolution)
	if err != nil {
		return nil
	}
	type inline struct {
		nolintRange
		col int
	}
	var groups []inline
	for _, g := range f.Comments {
		for _, c := range g.List {
			why, ok := nolintCoversGosec(c.Text)
			if !ok {
				continue
			}
			start := fset.Position(g.Pos())
			groups = append(groups, inline{nolintRange{start.Line, fset.Position(g.End()).Line, why}, start.Column})
		}
	}
	if len(groups) == 0 {
		return nil
	}
	ranges := make([]nolintRange, 0, len(groups))
	for _, g := range groups {
		ranges = append(ranges, g.nolintRange)
	}
	ast.Inspect(f, func(n ast.Node) bool {
		if n == nil {
			return false
		}
		start := fset.Position(n.Pos())
		for _, g := range groups {
			if g.to == start.Line-1 && g.col == start.Column {
				ranges = append(ranges, nolintRange{g.from, max(g.to, fset.Position(n.End()).Line), g.why})
			}
		}
		return true
	})
	return ranges
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
