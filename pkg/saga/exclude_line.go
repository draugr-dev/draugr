package saga

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ExcludeLineErrors refuses exclusion paths that name a line in a file, such as
// `deploy/rbac.yaml:18`, the way a finding's location is printed.
//
// `config.exclude[].paths` matches a finding's file, so a pattern carrying a line matches nothing.
// The trap is that it is exactly what a reader copies from the console, and it reads as handled:
// the descriptor says the finding is set aside, review agrees, and the gate keeps counting it.
// Unlike a pattern written ahead of the file it covers, this one cannot be right about the future,
// because the file it names is already there under the shorter name. So it is an error rather than
// a warning.
//
// roots are the trees whose files the exclusions are matched against: every repository of the
// descriptor that is on this machine, at the root findings' paths are relative to. Exclusions are
// not scoped to a repository, so an entry is refused only when the part before the line names a
// file in one of them and the whole entry names nothing in any of them. A file whose real name
// ends in `:18` is legal on most filesystems and is left alone. With no roots, a descriptor whose
// repositories are remote or not checked out here, nothing is refused: a pattern is only a mistake
// against a tree, and the scan's own report still names an exclusion that matched nothing.
func (m *Model) ExcludeLineErrors(roots []string) []error {
	if len(roots) == 0 {
		return nil
	}
	// Each entry is numbered within the file it was written in, so the index is the one the author
	// counts to. The file is named only where the exclusions came from more than one.
	sources := map[string]int{}
	index := make([]int, len(m.Config.Exclude))
	for i, e := range m.Config.Exclude {
		index[i] = sources[e.Source]
		sources[e.Source]++
	}
	var errs []error
	for i, e := range m.Config.Exclude {
		where := fmt.Sprintf("config.exclude[%d]", index[i])
		if len(sources) > 1 && e.Source != "" {
			where += " in " + e.Source
		}
		for j, p := range e.Paths {
			if file, ok := namesALine(roots, p); ok {
				errs = append(errs, fmt.Errorf(
					"%s: paths[%d] %q names a line, and paths match files. Write %q, which covers %s in that file",
					where, j, p, file, everyFinding(e.Rules)))
			}
		}
	}
	return errs
}

// namesALine reports whether a pattern is a file's path with `:<digits>` after it, where the path
// names a file in one of roots and the whole pattern names nothing in any of them, and returns the
// path without the line.
//
// A glob is left alone: it is written to match several paths, and a `:` in one is the author's to
// mean. So is a pattern ending in `/`, which names a directory.
func namesALine(roots []string, pattern string) (string, bool) {
	p := strings.TrimSpace(pattern)
	if strings.ContainsAny(p, "*?[") || strings.HasSuffix(p, "/") {
		return "", false
	}
	i := strings.LastIndexByte(p, ':')
	if i <= 0 || i == len(p)-1 || strings.Trim(p[i+1:], "0123456789") != "" {
		return "", false
	}
	file := p[:i]
	for _, root := range roots {
		if _, err := os.Lstat(filepath.Join(root, filepath.FromSlash(p))); err == nil {
			return "", false
		}
	}
	for _, root := range roots {
		if info, err := os.Stat(filepath.Join(root, filepath.FromSlash(file))); err == nil && info.Mode().IsRegular() {
			return file, true
		}
	}
	return "", false
}

// everyFinding says what an entry without the line would cover in the file: every finding of its
// rules, or every finding at all when it names none.
func everyFinding(rules []string) string {
	switch len(rules) {
	case 0:
		return "every finding"
	case 1:
		return "every " + rules[0] + " finding"
	}
	return "every " + strings.Join(rules[:len(rules)-1], ", ") + " or " + rules[len(rules)-1] + " finding"
}
