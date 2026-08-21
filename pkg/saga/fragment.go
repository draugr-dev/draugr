package saga

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// maxFragmentDepth bounds how far `fragments:` may nest.
//
// A limit rather than trusting cycle detection alone: a fan-out that is acyclic can still be
// unbounded (a generated tree, a glob that keeps matching one level deeper), and failing with a
// stated limit is a better answer than exhausting memory.
const maxFragmentDepth = 8

// Source is one file that contributed to a resolved descriptor.
//
// Kept beside the merged Model rather than folded into it, so a report can say where each part
// came from. Splitting a descriptor is only safe if the result is still answerable — a suppression
// nobody can trace to a file is worse than one in a long file.
type Source struct {
	// Path is the file, as written in the descriptor that named it (or the root's own path).
	Path string
	// URL is the repository it came from, empty for a local file.
	URL string
	// Revision is what the descriptor asked for, and Resolved is the commit that turned out to
	// be. Both empty for a local file.
	Revision string
	Resolved string
	// Root marks the descriptor the resolution started from.
	Root bool
}

// String renders a source the way a report or an error should name it.
func (s Source) String() string {
	if s.URL == "" {
		return s.Path
	}
	rev := s.Revision
	if s.Resolved != "" && s.Resolved != s.Revision {
		rev = fmt.Sprintf("%s (%s)", s.Revision, short(s.Resolved))
	}
	return fmt.Sprintf("%s@%s %s", s.URL, rev, s.Path)
}

func short(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}

// Resolved is a descriptor with every fragment merged in, plus where each part came from.
type Resolved struct {
	Model   *Model
	Sources []Source
}

// Fetcher materializes a remote fragment reference as a local directory.
//
// An interface because fetching means git, which lives in internal/ and cannot be imported from
// pkg/. The same shape as sbom.Generator: the package declares what it needs, and the wiring
// supplies something that can do it. A nil Fetcher makes a remote reference an error naming it,
// rather than a descriptor that quietly contains less than it says.
type Fetcher interface {
	// Fetch returns a directory holding the repository at the requested revision, the commit it
	// resolved to, and a cleanup.
	Fetch(url, revision string) (dir, resolved string, cleanup func(), err error)
}

// resolver carries the state one resolution needs: what has been loaded, how deep it is, and
// what to do about remote references.
type resolver struct {
	fetcher Fetcher
	// seen keys every file already loaded, so a diamond loads once. Two patterns legitimately
	// overlap, and loading a fragment twice would double its exclusions in the report's counts.
	seen map[string]bool
	// stack is the chain currently being loaded, so a cycle can be reported as the path that
	// caused it rather than as the fact that one exists.
	stack   []string
	sources []Source
}

// ResolveFile loads a descriptor and merges every fragment it names.
//
// The root is the merge base and fragments are applied after it, which is the opposite of the
// usual "most specific wins" layering and is deliberate. Components merge by union keeping the
// first value for scalars, so making the root the base is what keeps the file someone opened
// authoritative about a component's classification. Fragments are applied later and win less,
// which is right because they are additive.
func ResolveFile(path string, fetcher Fetcher) (*Resolved, error) {
	model, err := loadModelFile(path)
	if err != nil {
		return nil, err
	}
	r := &resolver{fetcher: fetcher, seen: map[string]bool{}}
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	r.seen[abs] = true
	r.sources = append(r.sources, Source{Path: path, Root: true})
	stampExclusions(model.Config.Exclude, path)

	if err := r.apply(model, model.Fragments, filepath.Dir(path), 0); err != nil {
		return nil, err
	}
	if err := model.Validate(); err != nil {
		return nil, err
	}
	return &Resolved{Model: model, Sources: r.sources}, nil
}

// apply merges every fragment the refs name into model.
func (r *resolver) apply(model *Model, refs []FragmentRef, base string, depth int) error {
	if len(refs) == 0 {
		return nil
	}
	if depth >= maxFragmentDepth {
		return fmt.Errorf("fragments nest more than %d deep at %q — check for a fragment that "+
			"includes its own directory", maxFragmentDepth, strings.Join(r.stack, " → "))
	}
	for _, ref := range refs {
		dir, src, cleanup, err := r.locate(ref, base)
		if err != nil {
			return err
		}
		err = r.mergeFrom(model, ref, dir, src, depth)
		cleanup()
		if err != nil {
			return err
		}
	}
	return nil
}

// locate turns a reference into a directory to expand its pattern against.
func (r *resolver) locate(ref FragmentRef, base string) (dir string, src Source, cleanup func(), err error) {
	if !ref.Remote() {
		return base, Source{Path: ref.Path}, func() {}, nil
	}
	if r.fetcher == nil {
		return "", Source{}, nil, fmt.Errorf(
			"fragments: %q reads from a repository, which this command cannot do — "+
				"use `draugr scan` or `draugr validate`, or give the fragment a local `path`", ref)
	}
	dir, resolved, cleanup, err := r.fetcher.Fetch(ref.URL, ref.Revision)
	if err != nil {
		return "", Source{}, nil, fmt.Errorf("fragments: fetch %s: %w", ref, err)
	}
	return dir, Source{Path: ref.Path, URL: ref.URL, Revision: ref.Revision, Resolved: resolved}, cleanup, nil
}

// mergeFrom expands one reference's pattern under dir and merges every file it matches.
func (r *resolver) mergeFrom(model *Model, ref FragmentRef, dir string, src Source, depth int) error {
	matches, err := globFiles(dir, ref.Path)
	if err != nil {
		return fmt.Errorf("fragments: %w", err)
	}
	// A pattern that matches nothing is a descriptor scanning less than it claims. Somebody wrote
	// the line on purpose, so silence from it is indistinguishable from a typo — and a quietly
	// smaller scan is the failure this tool exists to prevent.
	if len(matches) == 0 {
		return fmt.Errorf("fragments: %q matched no files — "+
			"remove the entry if this product has none, or fix the pattern", ref)
	}
	for _, rel := range matches {
		full := filepath.Join(dir, rel)
		key := full
		if abs, absErr := filepath.Abs(full); absErr == nil {
			key = abs
		}
		if ref.Remote() {
			// A remote fragment's identity is the repository and revision it came from, not the
			// temporary directory it was cloned into — which differs on every run.
			key = ref.URL + "@" + src.Resolved + "/" + rel
		}
		if r.seen[key] {
			continue
		}
		r.seen[key] = true

		named := src
		named.Path = rel
		if !ref.Remote() {
			named.Path = filepath.ToSlash(full)
		}

		frag, err := loadFragmentFile(full)
		if err != nil {
			return err
		}
		r.sources = append(r.sources, named)
		stampExclusions(frag.Config.Exclude, named.String())
		Merge(model, frag)

		r.stack = append(r.stack, named.String())
		err = r.apply(model, frag.Fragments, filepath.Dir(full), depth+1)
		r.stack = r.stack[:len(r.stack)-1]
		if err != nil {
			return err
		}
	}
	return nil
}

// stampExclusions records which file each rule came from, so the report can attribute it.
func stampExclusions(rules []ExcludeRule, source string) {
	for i := range rules {
		rules[i].Source = source
	}
}

// Merge folds a fragment into a model: components by name, exclusions appended.
//
// Components upsert and union rather than replace, so two fragments describing one component —
// a shared one naming its repository and a per-product one adding its image — end up as a single
// component with both. That is the same merge a Surveyor's fragment goes through.
func Merge(model *Model, frag Fragment) {
	for _, comp := range frag.Components {
		model.Components = UpsertComponent(model.Components, comp)
	}
	model.Config.Exclude = append(model.Config.Exclude, frag.Config.Exclude...)
}

// loadFragmentFile reads and decodes one fragment.
func loadFragmentFile(path string) (Fragment, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path came from the descriptor, by design
	if err != nil {
		return Fragment{}, fmt.Errorf("read fragment %q: %w", path, err)
	}
	return LoadFragment(data, path)
}

// LoadFragment parses a Saga fragment, substituting ${{ VAR }} from the environment.
//
// Validated as a fragment rather than as a Saga. A fragment has no `release:` and that is
// correct, so checking it against the Saga's rules would reject every valid one; and a fragment
// that is only meaningful once merged is a fragment nobody can check on its own.
func LoadFragment(data []byte, path string) (Fragment, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return Fragment{}, fmt.Errorf("parse fragment %q: %w", path, err)
	}
	if missing := substituteEnv(&root); len(missing) > 0 {
		return Fragment{}, fmt.Errorf("undefined environment variable(s) referenced in fragment %q: %s",
			path, strings.Join(missing, ", "))
	}
	var f Fragment
	if root.Kind != 0 {
		substituted, err := yaml.Marshal(&root)
		if err != nil {
			return Fragment{}, fmt.Errorf("parse fragment %q: %w", path, err)
		}
		dec := yaml.NewDecoder(bytes.NewReader(substituted))
		dec.KnownFields(true)
		if err := dec.Decode(&f); err != nil {
			return Fragment{}, fmt.Errorf("parse fragment %q: %w", path, fragmentFieldHint(err))
		}
	}
	if err := f.Validate(); err != nil {
		return Fragment{}, fmt.Errorf("fragment %q: %w", path, err)
	}
	return f, nil
}

// fragmentFieldHint explains the sections a fragment may not carry, rather than reporting them as
// unknown fields. They are known fields of a Saga, so "unknown" would be a lie about why.
func fragmentFieldHint(err error) error {
	match := unknownField.FindStringSubmatch(err.Error())
	if match == nil {
		return err
	}
	switch field := match[1]; field {
	case "release":
		return fmt.Errorf("a fragment has no `release:` — it is part of a product rather than a " +
			"product of its own, and the descriptor that names it supplies the release")
	case "gate", "controllers", "reports", "publishers", "sbom", "vex", "exploitability",
		"reachability":
		return fmt.Errorf("a fragment may not set `config.%s` — a fragment adds scope and "+
			"suppressions, and policy stays in the descriptor that names it, where a reviewer "+
			"sees it", field)
	default:
		return unknownFieldHint(err)
	}
}

// Validate checks a fragment on its own terms.
func (f Fragment) Validate() error {
	var errs []error
	errs = append(errs, validateComponents(f.Components)...)
	errs = append(errs, validateExclusions(f.Config.Exclude, "config.exclude")...)
	errs = append(errs, validateFragmentRefs(f.Fragments, "fragments")...)
	return joinErrs(errs)
}
