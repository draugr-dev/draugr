package sarif

import (
	"path"
	"regexp"
	"strings"
)

// Symbol names the frame as Go's tools print one in a trace: the package's name, then the function,
// qualified by its receiver where it is a method, as in gzip.Writer.Close.
//
// A function name alone is ambiguous in a path: Close on a writer and Close on the connection it
// wraps are two different calls, and printed bare they read as one call made twice.
func (f CallFrame) Symbol() string {
	name := packageName(f.Package)
	if name == "" {
		return f.Function
	}
	return name + "." + f.Function
}

// String renders the path as one line of symbols, the calling code first.
func (p CallPath) String() string {
	names := make([]string, 0, len(p.Frames))
	for _, f := range p.Frames {
		names = append(names, f.Symbol())
	}
	return strings.Join(names, " → ")
}

// ShortestCallPath returns the path with the fewest frames, which is the one a reader checks first,
// and false when there is none.
//
// Between paths of equal length it returns the one whose line sorts first. An analyzer may report
// its paths in a different order on each run, and the path a report prints is evidence a reader
// compares between runs, so the same paths give the same answer in any order.
func ShortestCallPath(paths []CallPath) (CallPath, bool) {
	var (
		best     CallPath
		bestLine string
		found    bool
	)
	for _, p := range paths {
		if len(p.Frames) == 0 {
			continue
		}
		line := p.String()
		switch {
		case !found, len(p.Frames) < len(best.Frames):
		case len(p.Frames) == len(best.Frames) && line < bestLine:
		default:
			continue
		}
		best, bestLine, found = p, line, true
	}
	return best, found
}

// majorVersion is an import path's major-version element, which is not the package's name.
var majorVersion = regexp.MustCompile(`^v[0-9]+$`)

// packageName is the name a package is referred to by in code, read from its import path: the last
// element, or the one before it where the last is a major version (github.com/x/y/v2 is y).
func packageName(importPath string) string {
	if importPath == "" {
		return ""
	}
	base := path.Base(importPath)
	if dir := path.Dir(importPath); majorVersion.MatchString(base) && dir != "." {
		base = path.Base(dir)
	}
	return base
}
