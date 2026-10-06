package engine

import (
	"context"
	"log/slog"
	"path"
	"slices"
	"strings"

	"github.com/draugr-dev/draugr/internal/git"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// ModuleResolver lists the directories holding manifest that a job over paths has to analyze
// whole, read at revision or, for a working-tree scan, from the files on disk. Nil, with no error,
// means the paths need no widening or the layout cannot be read, and the job keeps its paths.
//
// Injected for the reason WithTreeResolver is: answering means reading the repository, and the
// engine knows nothing about how one is fetched.
type ModuleResolver func(ctx context.Context, url, revision string, workingTree bool, manifest string, paths []string) ([]string, error)

// widenToModules points each scoped job of a whole-module scanner at the modules its paths belong
// to, and records what the job owns so its findings can be attributed after the scan.
//
// Two components carved out of one Go module, a public API and an internal admin service sharing
// `internal/`, each hold part of the module. A checkout of either part does not compile, so gosec
// and govulncheck analyze nothing. Widened, both jobs name the same target: the in-run dedupe runs
// the analysis once, the cache keys it on the module's tree, and each job keeps the findings
// whose files its own paths hold.
//
// The widened checkout keeps no `ignore`. An ignored directory can hold code the rest of the
// module imports, and the attribution honors the component's ignore list instead.
//
// A reachability analyzer is the exception to sharing. Its answer depends on where the call graph
// starts, and run over the whole module it reports one path per vulnerable function, so a
// component whose own code never makes the call could only be told unknown. Its widened target
// keeps the component's paths as Entry, which keys each component's analysis apart while the
// checkout stays shared, and the analyzer starts from them.
func (e *Engine) widenToModules(ctx context.Context, planned []PlannedJob, model saga.Model) []PlannedJob {
	if e.resolveModules == nil {
		return planned
	}
	type answer struct {
		roots []string
		err   error
	}
	memo := map[string]answer{}
	for i, pj := range planned {
		sc, ok := e.reg.Scanner(pj.Job.Scanner)
		if !ok || sc.Info().ModuleManifest == "" {
			continue
		}
		repo, ok := pj.Job.Target.(plugin.RepositoryTarget)
		if !ok || len(repo.Paths) == 0 {
			continue
		}
		manifest := sc.Info().ModuleManifest
		key := manifest + "\x00" + repo.Identity()
		a, seen := memo[key]
		if !seen {
			a.roots, a.err = e.resolveModules(ctx, repo.URL, repo.Revision, repo.WorkingTree, manifest, repo.Paths)
			memo[key] = a
		}
		if a.err != nil {
			slog.DebugContext(ctx, "module layout unreadable; scanning the paths as written",
				"scanner", pj.Job.Scanner, "target", repo.Identity(), "err", a.err)
			continue
		}
		if len(a.roots) == 0 {
			continue
		}
		widened := repo
		widened.Paths, widened.Ignore = a.roots, nil
		if sc.Info().Reachability {
			widened.Entry = repo.Paths
		}
		pj.Job.Target = widened
		pj.owner = &moduleOwner{
			manifest: manifest,
			modules:  a.roots,
			own:      git.Scope{Paths: repo.Paths, Ignore: repo.Ignore},
			claims:   repositoryClaims(model, repo),
		}
		planned[i] = pj
	}
	return planned
}

// repositoryClaims is every component's paths over repo, the job's own included.
//
// Read from the whole descriptor rather than from the jobs planned. A run narrowed to one
// component, or a component that does not enable this scanner, still owns the files its paths
// name, and a finding in them is not the job's to report as though nobody did.
func repositoryClaims(model saga.Model, repo plugin.RepositoryTarget) []git.Scope {
	var claims []git.Scope
	for _, c := range model.Components {
		for _, r := range c.Repositories {
			if r.URL == repo.URL && r.Revision == repo.Revision {
				claims = append(claims, git.Scope{Paths: r.Paths})
			}
		}
	}
	return claims
}

// moduleOwner decides which findings of a module-wide analysis belong to one job.
type moduleOwner struct {
	manifest string
	// modules are the module directories the analysis covered, "." for the repository root.
	modules []string
	// own is the job's scope as the descriptor wrote it.
	own git.Scope
	// claims are the paths of every component over the same repository, ignore lists left out:
	// a file a component ignores is still one it claimed and chose not to scan.
	claims []git.Scope
}

// owns reports whether a finding in file belongs to this job.
//
// A file the job's paths hold is its own. A file another component's paths hold is that
// component's. A file nobody's paths hold, shared code under `internal/` that each component
// imports and none names, belongs to every component whose paths name the manifest of the module
// it is in: each of them builds that code, and each ranks it by its own exposure. A finding with no
// file is kept, because nothing about it places it elsewhere.
func (o *moduleOwner) owns(file string) bool {
	if file == "" || o.own.Contains(file) {
		return true
	}
	for _, c := range o.claims {
		if c.Contains(file) {
			return false
		}
	}
	m, ok := git.InnermostModule(file, o.modules)
	return ok && o.own.Contains(path.Join(m, o.manifest))
}

// attribute returns the findings of report this job owns. A nil owner returns report unchanged.
//
// The report may be shared with other jobs through the cache or the in-run dedupe, so nothing in
// it is modified.
func (o *moduleOwner) attribute(report sarif.Report) sarif.Report {
	if o == nil || len(report.Results) == 0 {
		return report
	}
	out := report
	out.Results = make([]sarif.Result, 0, len(report.Results))
	for _, r := range report.Results {
		if kept, ok := o.keep(r); ok {
			out.Results = append(out.Results, kept)
		}
	}
	return out
}

// keep decides one finding, and narrows a reachability verdict to the call paths that start in
// code this job owns.
//
// A vulnerable dependency is declared once, in the module's manifest, and reached from wherever
// the code calling it lives. A route starting in another component's code is evidence about that
// component: carried here, it would rank this component's copy of the finding by a call it does not
// make. With none of its own left the verdict is undetermined rather than unreachable, because the
// analyzer reports a sample of the routes it found rather than every one.
func (o *moduleOwner) keep(r sarif.Result) (sarif.Result, bool) {
	reach := r.Reachability
	if reach == nil || len(reach.Paths) == 0 {
		return r, o.owns(r.Location.URI)
	}
	var mine []sarif.CallPath
	for _, p := range reach.Paths {
		if o.owns(entryFile(p, r.Location.URI)) {
			mine = append(mine, p)
		}
	}
	switch {
	case len(mine) == len(reach.Paths):
		return r, true
	case len(mine) > 0:
		narrowed := *reach
		narrowed.Paths = mine
		r.Reachability = &narrowed
		return r, true
	case o.owns(r.Location.URI):
		narrowed := *reach
		narrowed.State, narrowed.Paths = sarif.ReachabilityUnknown, nil
		r.Reachability = &narrowed
		return r, true
	}
	return r, false
}

// entryFile is the repository-relative file a call path starts in: its first frame with a file,
// which the analyzer reports relative to the module root, under the directory of the manifest the
// finding is located at. A path with no file is placed at the manifest itself.
func entryFile(p sarif.CallPath, manifest string) string {
	i := slices.IndexFunc(p.Frames, func(f sarif.CallFrame) bool { return f.File != "" })
	if i < 0 {
		return manifest
	}
	file := strings.TrimPrefix(p.Frames[i].File, "./")
	return path.Join(path.Dir(manifest), file)
}
