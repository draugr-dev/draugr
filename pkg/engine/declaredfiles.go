package engine

import (
	"cmp"
	"maps"
	"path/filepath"
	"slices"
	"strings"

	"github.com/draugr-dev/draugr/internal/git"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// takeConfigFiles reads, from each repository job's report, the scanners' configuration files the
// checkout held and those a scanner honored without listing what they kept, as the repository
// scanner recorded them while its checkout existed, and takes both records out of the report.
//
// Keyed by the repository's URL as the descriptor writes it, which the job carries, and by the
// file's path from the root of the checkout. A file two components read at two revisions keeps
// both digests. A cached report carries the record its scan wrote, since the cache stores the
// report the scanner returned and its key covers these files.
func takeConfigFiles(planned []PlannedJob, reports []*sarif.Report) ([]DeclaredFile, []UnlistedSetAside) {
	type key struct{ repository, path string }
	digests := map[key][]string{}
	var unlisted []UnlistedSetAside
	for i, pj := range planned {
		rep := reports[i]
		if rep == nil {
			continue
		}
		repo, isRepo := pj.Job.Target.(plugin.RepositoryTarget)
		provenance := make([]sarif.Provenance, 0, len(rep.Provenance))
		for _, p := range rep.Provenance {
			detail := make([]sarif.Field, 0, len(p.Detail))
			for _, d := range p.Detail {
				if name, ok := strings.CutPrefix(d.Key, sarif.DetailConfigFile); ok {
					if isRepo {
						k := key{repo.URL, name}
						if !slices.Contains(digests[k], d.Value) {
							digests[k] = append(digests[k], d.Value)
						}
					}
					continue
				}
				if name, ok := strings.CutPrefix(d.Key, sarif.DetailUnlistedSetAside); ok {
					u := UnlistedSetAside{Repository: repo.URL, File: name, Scanner: d.Value}
					if isRepo && !slices.Contains(unlisted, u) {
						unlisted = append(unlisted, u)
					}
					continue
				}
				detail = append(detail, d)
			}
			if len(detail) == 0 {
				detail = nil
			}
			p.Detail = detail
			provenance = append(provenance, p)
		}
		// A copy, never the slice in place: a report shared by two jobs, or held by a cache, is the
		// same backing array.
		taken := *rep
		taken.Provenance = provenance
		reports[i] = &taken
	}
	files := make([]DeclaredFile, 0, len(digests))
	for k, ds := range digests {
		slices.Sort(ds)
		files = append(files, DeclaredFile{Kind: FileScanner, Repository: k.repository, Path: k.path, Digests: ds})
	}
	slices.SortFunc(unlisted, func(a, b UnlistedSetAside) int {
		return cmp.Or(cmp.Compare(a.Repository, b.Repository), cmp.Compare(a.File, b.File), cmp.Compare(a.Scanner, b.Scanner))
	})
	return files, unlisted
}

// vexFiles are the VEX documents this run read, for the components it covers and the project. A
// document on disk is recorded with its digest, since a change can edit it; one fetched from a URL
// or read from another repository is recorded by where it is, since a change cannot edit it and the
// base already chose to trust it. Each is named as the descriptor wrote it, a `${{ }}` reference as
// the reference.
func (e *Engine) vexFiles(model *saga.Model) []DeclaredFile {
	docs := slices.Clone(e.vex.Project)
	for _, name := range slices.Sorted(maps.Keys(e.vex.ByComponent)) {
		if e.scope.IncludesComponent(name) {
			docs = append(docs, e.vex.ByComponent[name]...)
		}
	}
	var out []DeclaredFile
	for _, d := range docs {
		location, _ := model.AsWritten(d.Provenance.Location).(string)
		f := DeclaredFile{Kind: FileVEX, Path: location}
		if d.Provenance.Kind == "path" {
			sum := strings.TrimPrefix(d.Provenance.Digest, "sha256:")
			f.Digests = []string{sum[:min(len(sum), 16)]}
		}
		if !slices.ContainsFunc(out, func(o DeclaredFile) bool { return o.Path == f.Path }) {
			out = append(out, f)
		}
	}
	return out
}

// settingFiles are the files and directories the planned jobs' settings point their scanners at,
// read where Draugr runs as the scanners read them, each by the path the setting gives as the
// descriptor wrote it, a `${{ }}` reference as the reference. One that is not there is not
// recorded; the scan that reads it fails on its own.
func (e *Engine) settingFiles(planned []PlannedJob, model *saga.Model) []DeclaredFile {
	var out []DeclaredFile
	for _, pj := range planned {
		sc, ok := e.reg.Scanner(pj.Job.Scanner)
		if !ok {
			continue
		}
		filer, ok := sc.(plugin.SettingFiler)
		if !ok {
			continue
		}
		for _, path := range filer.SettingFiles(pj.Job.Config) {
			written, _ := model.AsWritten(path).(string)
			if slices.ContainsFunc(out, func(o DeclaredFile) bool { return o.Path == written }) {
				continue
			}
			abs, err := filepath.Abs(path)
			if err != nil {
				continue
			}
			if digest, ok := git.PathDigest(abs); ok {
				out = append(out, DeclaredFile{Kind: FileSetting, Path: written, Digests: []string{digest}})
			}
		}
	}
	return out
}

// sortDeclaredFiles puts files in the order a declaration records them: by kind, repository and
// path.
func sortDeclaredFiles(files []DeclaredFile) {
	slices.SortFunc(files, func(a, b DeclaredFile) int {
		return cmp.Or(cmp.Compare(a.Kind, b.Kind), cmp.Compare(a.Repository, b.Repository), cmp.Compare(a.Path, b.Path))
	})
}
