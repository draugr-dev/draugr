package sealed

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Structure is what a scan found, reduced to the part an advisory published tomorrow does not
// change: each package and the scanners that reported it, grouped by ecosystem, and each file a
// result without a package was reported in. It is what the live tier asserts, because against the
// live databases the advisories themselves move every day.
type Structure struct {
	// Packages maps an ecosystem (npm, gomod, pip) to the packages found in it.
	Packages map[string][]PackageStructure `yaml:"packages,omitempty"`
	// Files are the files a result with no package was reported in: a secret, a SAST result, a
	// misconfiguration.
	Files []FileStructure `yaml:"files,omitempty"`
}

// PackageStructure is one package at one location and the scanners that reported it.
type PackageStructure struct {
	Name    string `yaml:"name"`
	Version string `yaml:"version"`
	// In is the file the package was reported in, relative to the repository.
	In string `yaml:"in"`
	// FoundBy are the control/scanner pairs that reported it, sorted.
	FoundBy []string `yaml:"foundBy,flow"`
}

// FileStructure is one file and the control/scanner pairs that reported a result in it.
type FileStructure struct {
	File    string   `yaml:"file"`
	FoundBy []string `yaml:"foundBy,flow"`
}

// Summarize reduces findings to their structure. The advisory, the rule and the line are dropped;
// what is kept is which package or file, and which scanner found it.
func Summarize(found []Finding) Structure {
	type pkgKey struct{ eco, name, version, in string }
	pkgs := map[pkgKey]map[string]bool{}
	files := map[string]map[string]bool{}
	add := func(m map[string]bool, f Finding) map[string]bool {
		if m == nil {
			m = map[string]bool{}
		}
		m[f.Control+"/"+f.Tool] = true
		return m
	}
	for _, f := range found {
		if f.Package == "" {
			files[f.File] = add(files[f.File], f)
			continue
		}
		eco, name, version := splitPackage(f.Package)
		k := pkgKey{eco, name, version, f.File}
		pkgs[k] = add(pkgs[k], f)
	}

	var s Structure
	for k, by := range pkgs {
		if s.Packages == nil {
			s.Packages = map[string][]PackageStructure{}
		}
		s.Packages[k.eco] = append(s.Packages[k.eco], PackageStructure{
			Name: k.name, Version: k.version, In: k.in, FoundBy: sortedKeys(by),
		})
	}
	for eco := range s.Packages {
		list := s.Packages[eco]
		sort.Slice(list, func(i, j int) bool {
			a, b := list[i], list[j]
			if a.Name != b.Name {
				return a.Name < b.Name
			}
			if a.Version != b.Version {
				return a.Version < b.Version
			}
			return a.In < b.In
		})
	}
	for file, by := range files {
		s.Files = append(s.Files, FileStructure{File: file, FoundBy: sortedKeys(by)})
	}
	sort.Slice(s.Files, func(i, j int) bool { return s.Files[i].File < s.Files[j].File })
	return s
}

// splitPackage reads the "ecosystem name version" Observe writes.
func splitPackage(p string) (eco, name, version string) {
	first, last := strings.Index(p, " "), strings.LastIndex(p, " ")
	if first < 0 {
		return p, "", ""
	}
	if first == last {
		return p[:first], p[first+1:], ""
	}
	return p[:first], p[first+1 : last], p[last+1:]
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// structureHeader opens every structure file, so a reader who meets one in a pull request knows
// what wrote it and what it asserts.
const structureHeader = `# What a scan finds against the latest advisory databases and real registries: each package and
# the scanners that reported it, and each file a result without a package was reported in. The
# advisories are left out because they move every day; this is the part that should not.
#
# Written by the live tier (go test -tags integration -run TestLive -update-live with
# DRAUGR_LIVE=1). A nightly run that finds a difference proposes it as a pull request.
`

// Marshal renders the structure as the file the live tier keeps.
func (s Structure) Marshal() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString(structureHeader)
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(s); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// LoadStructure reads a structure file. A file that does not exist is reported as absent rather
// than as an empty structure, because a scenario nobody has recorded is not one that finds nothing.
func LoadStructure(path string) (s Structure, exists bool, err error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- a structure file under testdata
	if errors.Is(err, fs.ErrNotExist) {
		return Structure{}, false, nil
	}
	if err != nil {
		return Structure{}, false, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&s); err != nil && !errors.Is(err, io.EOF) {
		return Structure{}, true, fmt.Errorf("%s: %w", path, err)
	}
	return s, true, nil
}

// lines flattens a structure to one line per package or file and scanner, so a difference names
// exactly which scanner stopped or started reporting what.
func (s Structure) lines() map[string]bool {
	out := map[string]bool{}
	for eco, list := range s.Packages {
		for _, p := range list {
			for _, by := range p.FoundBy {
				out[fmt.Sprintf("%s %s %s in %s, found by %s", eco, p.Name, p.Version, p.In, by)] = true
			}
		}
	}
	for _, f := range s.Files {
		for _, by := range f.FoundBy {
			out[fmt.Sprintf("a result in %s, found by %s", f.File, by)] = true
		}
	}
	return out
}

// Drift compares a recorded structure with an observed one, one line per difference: `-` for what
// the recording has and the scan no longer found, `+` for what the scan found that it does not.
func Drift(recorded, observed Structure) []string {
	was, now := recorded.lines(), observed.lines()
	var out []string
	for l := range was {
		if !now[l] {
			out = append(out, "- "+l)
		}
	}
	for l := range now {
		if !was[l] {
			out = append(out, "+ "+l)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i][2:] != out[j][2:] {
			return out[i][2:] < out[j][2:]
		}
		return out[i] < out[j]
	})
	return out
}

// Lost names every ecosystem and every control the recording has findings for and the observed
// structure has none for. That is never drift: the fixtures pin versions with known advisories,
// so a language or a control going to zero is a scanner that stopped reading something, which
// looks like success and must fail instead of being written down as the new expectation.
func Lost(recorded, observed Structure) []string {
	var out []string
	for eco, list := range recorded.Packages {
		if len(list) > 0 && len(observed.Packages[eco]) == 0 {
			out = append(out, "ecosystem "+eco+": packages were found before and none are now")
		}
	}
	had, has := recorded.controls(), observed.controls()
	for c := range had {
		if !has[c] {
			out = append(out, "control "+c+": results were reported before and none are now")
		}
	}
	sort.Strings(out)
	return out
}

// controls is the set of controls anything in the structure was found by.
func (s Structure) controls() map[string]bool {
	out := map[string]bool{}
	mark := func(by []string) {
		for _, b := range by {
			out[strings.SplitN(b, "/", 2)[0]] = true
		}
	}
	for _, list := range s.Packages {
		for _, p := range list {
			mark(p.FoundBy)
		}
	}
	for _, f := range s.Files {
		mark(f.FoundBy)
	}
	return out
}
