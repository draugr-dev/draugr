package saga

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// GlobMatch reports whether rel matches pattern, with `**` crossing separators.
//
// One glob dialect for the whole descriptor: `paths:`, `ignore:` and `fragments:` all mean the
// same thing by the same pattern. path.Match handles a single segment; `**` is split on and each
// side matched around it, so `**/testdata/**` and `vendor/**` both behave the way the person
// writing them expects.
//
// Lives here rather than beside either caller because the dialect is part of the Saga language —
// it is what a descriptor means by a pattern, so it belongs with the rest of the descriptor's
// definition. Two copies would be two dialects the moment one of them was fixed.
func GlobMatch(pattern, rel string) bool {
	if !strings.Contains(pattern, "**") {
		ok, err := path.Match(pattern, rel)
		return err == nil && ok
	}
	head, tail, _ := strings.Cut(pattern, "**")
	head, tail = strings.TrimSuffix(head, "/"), strings.TrimPrefix(tail, "/")

	if head != "" {
		if !strings.HasPrefix(rel, head+"/") && rel != head {
			return false
		}
		rel = strings.TrimPrefix(strings.TrimPrefix(rel, head), "/")
	}
	if tail == "" {
		return true // `prefix/**` takes everything below prefix
	}
	// The remainder of the pattern may start at any depth.
	for {
		if GlobMatch(tail, rel) {
			return true
		}
		_, rest, found := strings.Cut(rel, "/")
		if !found {
			return false
		}
		rel = rest
	}
}

// globFiles returns the files matching pattern, as paths relative to base.
//
// Sorted, because the result decides merge order and two machines resolving the same commit
// differently would make a descriptor irreproducible — the one property the whole tool rests on.
// Directory entries never match: a pattern selects files to read.
//
// The walk starts at the pattern's literal prefix rather than at base. That is what lets a
// fragment reach a shared file above its own directory (`../shared/*.saga-fragment.yaml`), which
// a monorepo wants, and it means `services/web/**` does not walk the rest of the tree to discard
// it.
func globFiles(base, pattern string) ([]string, error) {
	prefix, rest := splitGlobPrefix(pattern)
	root := filepath.Join(base, filepath.FromSlash(prefix))

	// A pattern with nothing to expand names one file; asking the filesystem is both cheaper and
	// exact, and it keeps a path that climbs out of the tree working.
	if rest == "" {
		if info, err := os.Stat(root); err == nil && !info.IsDir() {
			return []string{path.Join(prefix)}, nil
		}
		return nil, nil
	}

	var out []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			// A prefix that does not exist is not an error here: the caller reports a pattern
			// that matched nothing, which says more than a stat failure would.
			if os.IsNotExist(err) {
				return filepath.SkipAll
			}
			return err
		}
		if d.IsDir() {
			// .git holds no descriptors and can be enormous; walking it is pure cost.
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		rel, relErr := filepath.Rel(root, p)
		if relErr != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if GlobMatch(rest, rel) {
			out = append(out, path.Join(prefix, rel))
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("expand %q: %w", pattern, err)
	}
	sort.Strings(out)
	return out, nil
}

// splitGlobPrefix separates the leading segments that contain no wildcard from the rest.
//
// `services/**/draugr.saga-fragment.yaml` splits into `services` and `**/draugr.saga-fragment.yaml`;
// `../shared/x.saga-fragment.yaml` is entirely literal and splits into itself and "".
func splitGlobPrefix(pattern string) (prefix, rest string) {
	segs := strings.Split(pattern, "/")
	i := 0
	for ; i < len(segs); i++ {
		if strings.ContainsAny(segs[i], "*?[") {
			break
		}
	}
	return strings.Join(segs[:i], "/"), strings.Join(segs[i:], "/")
}
