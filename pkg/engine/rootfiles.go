package engine

import (
	"strings"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// rootOwnership decides which component a file at a repository's root belongs to, when several
// components are carved out of that repository with `paths:`.
//
// A scoped checkout keeps every root file, because the lockfile, the go.mod and the scanners' own
// ignore files live there and a scanner that cannot see them reports less without failing. So each
// component's scan reads the root, and without an owner a root lockfile's vulnerability or a leaked
// root secret is reported once per component, under every one of them.
//
// A root file belongs to, in order:
//
//  1. a component that claims the root: no `paths:`, `.` among them, or the file itself named;
//  2. the only component scanning that repository, where there is one;
//  3. nobody. The finding is reported once, with no component, and ranked as the most exposed of
//     the components sharing the repository, since every one of them ships the file.
//
// Keyed on the repository and revision, because two components on different revisions of one
// repository are reading different trees.
type rootOwnership map[string]*sharedRepository

// sharedRepository is every component scanning one repository at one revision.
type sharedRepository struct {
	// jobs holds one planned job per component, in plan order, for its classification.
	jobs []PlannedJob
	// whole names the components that own every root file.
	whole map[string]bool
	// files names, per root file, the components that name it in `paths:`.
	files map[string]map[string]bool
}

// rootDecision is what happens to one finding at a repository root.
type rootDecision int

const (
	// rootOwned keeps the finding under the job's component.
	rootOwned rootDecision = iota
	// rootElsewhere drops it from this job: another component owns the file and reports it.
	rootElsewhere
	// rootUnowned reports it once, under no component.
	rootUnowned
)

func repositoryKey(t plugin.RepositoryTarget) string { return t.Source() + "@" + t.Revision }

// newRootOwnership reads ownership from the planned jobs, which carry every component's scope.
func newRootOwnership(planned []PlannedJob) rootOwnership {
	out := rootOwnership{}
	for _, pj := range planned {
		repo, ok := pj.Job.Target.(plugin.RepositoryTarget)
		if !ok || pj.Component == "" {
			continue
		}
		key := repositoryKey(repo)
		sr := out[key]
		if sr == nil {
			sr = &sharedRepository{whole: map[string]bool{}, files: map[string]map[string]bool{}}
			out[key] = sr
		}
		if !sr.scans(pj.Component) {
			sr.jobs = append(sr.jobs, pj)
		}
		if claimsRoot(repo.Paths) {
			sr.whole[pj.Component] = true
		}
		for _, p := range repo.Paths {
			f := scopeEntry(p)
			if sr.files[f] == nil {
				sr.files[f] = map[string]bool{}
			}
			sr.files[f][pj.Component] = true
		}
	}
	return out
}

func (sr *sharedRepository) scans(component string) bool {
	for _, pj := range sr.jobs {
		if pj.Component == component {
			return true
		}
	}
	return false
}

// claimsRoot reports whether a scope covers the repository root: no paths, or `.` among them.
func claimsRoot(paths []string) bool {
	if len(paths) == 0 {
		return true
	}
	for _, p := range paths {
		if e := scopeEntry(p); e == "" || e == "." {
			return true
		}
	}
	return false
}

// scopeEntry normalizes a `paths:` entry the way the checkout reads it.
func scopeEntry(p string) string {
	p = strings.TrimSpace(p)
	p = strings.TrimSuffix(strings.TrimSuffix(p, "/**"), "/*")
	return strings.Trim(p, "/")
}

// isRootFile reports whether a repository-relative path names a file at the root.
func isRootFile(path string) bool { return path != "" && !strings.Contains(path, "/") }

// decide says what happens to a finding at path in a job's report.
func (o rootOwnership) decide(pj PlannedJob, path string) rootDecision {
	repo, ok := pj.Job.Target.(plugin.RepositoryTarget)
	if !ok || pj.Component == "" || !isRootFile(path) {
		return rootOwned
	}
	sr := o[repositoryKey(repo)]
	if sr == nil || len(sr.jobs) < 2 || sr.whole[pj.Component] || sr.files[path][pj.Component] {
		return rootOwned
	}
	if len(sr.whole) > 0 || len(sr.files[path]) > 0 {
		return rootElsewhere
	}
	return rootUnowned
}

// sharers are the components scanning the job's repository, for ranking an unowned finding.
func (o rootOwnership) sharers(pj PlannedJob) []PlannedJob {
	repo, _ := pj.Job.Target.(plugin.RepositoryTarget)
	if sr := o[repositoryKey(repo)]; sr != nil {
		return sr.jobs
	}
	return []PlannedJob{pj}
}

// attribute applies ownership to a job's findings and inputs. It drops what another component owns
// and reports, for each kept finding and input, whether it belongs to nobody. The report's slices
// are copied, never edited: a cached report is shared by every job that hit it.
func (o rootOwnership) attribute(report sarif.Report, pj PlannedJob) (out sarif.Report, unownedResults, unownedInputs []bool) {
	out = report
	// Empty rather than nil where the original was, so a report with no findings still says so.
	out.Results, out.Inputs = report.Results[:0:0], report.Inputs[:0:0]
	for _, r := range report.Results {
		d := o.decide(pj, r.Location.URI)
		if d == rootElsewhere {
			continue
		}
		out.Results = append(out.Results, r)
		unownedResults = append(unownedResults, d == rootUnowned)
	}
	for _, in := range report.Inputs {
		d := o.decide(pj, in.Path)
		if d == rootElsewhere {
			continue
		}
		out.Inputs = append(out.Inputs, in)
		unownedInputs = append(unownedInputs, d == rootUnowned)
	}
	return out, unownedResults, unownedInputs
}
