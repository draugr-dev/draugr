package sealed

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Annotation is an expectation written in a fixture's own code, the way Semgrep tests its rules: a
// comment naming a rule that must (`ruleid:`) or must not (`ok:`) report the next line of code.
type Annotation struct {
	// File is relative to the repository, with any fixture suffix removed.
	File string
	// Line is the line the annotation is about: the first line after it that is neither blank nor
	// another annotation.
	Line int
	Rule string
	// Want is true for `ruleid:` and false for `ok:`.
	Want bool
}

// annotationPattern matches `ruleid: a, b` and `ok: a` after a line or block comment marker.
var annotationPattern = regexp.MustCompile(`(?:#|//|/\*)\s*(ruleid|ok):\s*([A-Za-z0-9_.\-]+(?:\s*,\s*[A-Za-z0-9_.\-]+)*)`)

// ReadAnnotations collects the annotations in every file under dir, skipping vendor/ and
// node_modules/, which hold other people's code.
func ReadAnnotations(dir string) ([]Annotation, error) {
	var out []Annotation
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); name == "vendor" || name == "node_modules" || name == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		found, err := annotationsIn(path, filepath.ToSlash(strings.TrimSuffix(rel, FixtureSuffix)))
		out = append(out, found...)
		return err
	})
	return out, err
}

func annotationsIn(path, rel string) ([]Annotation, error) {
	f, err := os.Open(path) // #nosec G304 -- walking a fixture directory
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var out, pending []Annotation
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		if m := annotationPattern.FindStringSubmatch(line); m != nil {
			for _, rule := range strings.Split(m[2], ",") {
				pending = append(pending, Annotation{File: rel, Rule: strings.TrimSpace(rule), Want: m[1] == "ruleid"})
			}
			continue
		}
		if strings.TrimSpace(line) == "" || len(pending) == 0 {
			continue
		}
		for _, a := range pending {
			a.Line = n
			out = append(out, a)
		}
		pending = nil
	}
	return out, sc.Err()
}
