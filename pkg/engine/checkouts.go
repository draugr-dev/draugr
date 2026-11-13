package engine

import (
	"context"

	"github.com/draugr-dev/draugr/internal/git"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// declareCheckouts tells the run's checkout pool every use the run will make of each checkout: one
// per planned job reading a repository, and one per SBOM of a repository. It returns each job's key
// by its index in planned, for the job to end its use with when it stops.
//
// The pool belongs to the invocation, which decides how long a run's checkouts may live; the engine
// is the only one that knows which jobs will read them. A job that reads a checkout under a key
// nobody declared keeps it until the run ends, which is the safe direction to be wrong in.
func (e *Engine) declareCheckouts(ctx context.Context, planned []PlannedJob, model saga.Model) map[int]string {
	pool := git.PoolFrom(ctx)
	if pool == nil {
		return nil
	}
	keys := make(map[int]string)
	for i, pj := range planned {
		repo, ok := pj.Job.Target.(plugin.RepositoryTarget)
		if !ok {
			continue
		}
		// The scope a repository scanner checks out with: the target's paths, and history when the
		// scanner reads it, so a history scan and a tree scan of one repository are two checkouts.
		scope := git.Scope{Paths: repo.Paths, Ignore: repo.Ignore}
		if sc, ok := e.reg.Scanner(pj.Job.Scanner); ok {
			if hr, ok := sc.(plugin.HistoryReader); ok {
				scope.History = hr.ReadsHistory(pj.Job.Config)
			}
		}
		key := git.Key(repo.URL, repo.Revision, repo.WorkingTree, scope)
		pool.Expect(key)
		keys[i] = key
	}
	for _, st := range e.sbomTargets(model) {
		if key, ok := sbomCheckoutKey(st.target); ok {
			pool.Expect(key)
		}
	}
	return keys
}

// sbomTarget is one target an SBOM is generated for, and the first component that named it.
type sbomTarget struct {
	component string
	target    plugin.Target
}

// sbomTargets lists what generateSBOMs takes an inventory of, in descriptor order, each target once.
// Empty when the descriptor asks for no SBOM or nothing is configured to generate one.
func (e *Engine) sbomTargets(model saga.Model) []sbomTarget {
	if cfg := model.Config.SBOM; cfg == nil || !cfg.Enabled || e.sbomGen == nil {
		return nil
	}
	var out []sbomTarget
	seen := make(map[string]bool)
	for i := range model.Components {
		comp := &model.Components[i]
		var targets []plugin.Target
		for _, r := range comp.Repositories {
			targets = append(targets, plugin.RepositoryTarget{
				URL: r.URL, Revision: r.Revision, WorkingTree: e.workingTree,
				Paths: r.Paths, Ignore: r.Ignore,
			})
		}
		for _, img := range comp.Images {
			targets = append(targets, plugin.ImageTarget{Ref: img.Image, Digest: img.Digest})
		}
		for _, t := range targets {
			if seen[t.Identity()] {
				continue
			}
			seen[t.Identity()] = true
			out = append(out, sbomTarget{component: comp.Name, target: t})
		}
	}
	return out
}

// sbomCheckoutKey is the checkout an SBOM of t reads, which is the one a scanner reading t's tree
// reads too, so the inventory describes the tree the scan judged.
func sbomCheckoutKey(t plugin.Target) (string, bool) {
	repo, ok := t.(plugin.RepositoryTarget)
	if !ok {
		return "", false
	}
	return git.Key(repo.URL, repo.Revision, repo.WorkingTree, git.Scope{Paths: repo.Paths, Ignore: repo.Ignore}), true
}
