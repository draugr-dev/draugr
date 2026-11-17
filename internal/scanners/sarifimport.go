package scanners

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/draugr-dev/draugr/internal/english"
	"github.com/draugr-dev/draugr/internal/git"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// sarifImport reads a SARIF file another tool wrote about a component, in place of running a
// scanner: a commercial scanner a team already pays for, whose findings should be ranked by the
// component's exposure and criticality and judged by the same gate as everything Draugr runs.
//
// It runs nothing, so it has no tool to install and no third party's terms to read. What it owes
// the reader instead is an account of the file: whose it is, when it was written, which revision it
// describes, and where its severities came from, because Draugr did not produce any of that.
type sarifImport struct {
	// resolve turns a repository's revision into a commit, so a file that states the revision it
	// scanned can be held to the one this run reads. Injectable for tests.
	resolve func(ctx context.Context, url, revision string) (string, error)
}

// NewSARIFImport returns the scanner every import is planned for.
func NewSARIFImport() plugin.Scanner { return sarifImport{resolve: git.ResolveRevision} }

// Info describes the import scanner.
func (sarifImport) Info() plugin.ScannerInfo {
	return plugin.ScannerInfo{
		Name:         plugin.ImportScanner,
		Origin:       "draugr",
		TargetKinds:  []plugin.TargetKind{plugin.TargetFile},
		ConfigSchema: json.RawMessage(noScannerOptions),
	}
}

// importLog is the part of a SARIF log the import reads for itself: what FromForeignSARIF does not keep.
type importLog struct {
	Version string `json:"version"`
	Runs    []struct {
		Tool struct {
			Driver struct {
				Name    string `json:"name"`
				Version string `json:"version"`
				// SemanticVersion is the other place SARIF lets a tool put its version.
				SemanticVersion string `json:"semanticVersion"`
			} `json:"driver"`
		} `json:"tool"`
		Invocations []struct {
			EndTimeUTC string `json:"endTimeUtc"`
		} `json:"invocations"`
		VersionControlProvenance []struct {
			RepositoryURI string `json:"repositoryUri"`
			RevisionID    string `json:"revisionId"`
		} `json:"versionControlProvenance"`
		// Results are counted, not read: FromForeignSARIF returns every run's results in order, and
		// the count says which of them a run's provenance describes.
		Results []json.RawMessage `json:"results"`
	} `json:"runs"`
}

// notStated is the commit field's value for a file that names none, which the report lists as an
// unbound import.
const notStated = "not stated"

// Scan reads the file. Anything that keeps it from being read as SARIF 2.1.0 is an error, as for a
// scanner that could not run: a missing file contributes no findings, which is exactly what a clean
// one contributes, and the two must not look alike.
func (s sarifImport) Scan(ctx context.Context, target plugin.Target, _ plugin.Config) (sarif.Report, error) {
	ft, ok := target.(plugin.FileTarget)
	if !ok {
		return sarif.Report{}, fmt.Errorf("%s: unsupported target %T (want file)", plugin.ImportScanner, target)
	}
	data, err := os.ReadFile(ft.Path) // #nosec G304 -- the file the descriptor names for import
	if err != nil {
		return sarif.Report{}, fmt.Errorf("%s: read %s: %w", plugin.ImportScanner, ft.Path, err)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return sarif.Report{}, fmt.Errorf("%s: %s is empty", plugin.ImportScanner, ft.Path)
	}
	rep, outside, err := sarif.FromForeignSARIF(data, checkoutRoots(ft.Repositories))
	if err != nil {
		return sarif.Report{}, fmt.Errorf("%s: %s: %w", plugin.ImportScanner, ft.Path, err)
	}
	var meta importLog
	if err := json.Unmarshal(data, &meta); err != nil {
		return sarif.Report{}, fmt.Errorf("%s: %s: %w", plugin.ImportScanner, ft.Path, err)
	}
	rated, err := rateImported(&rep, data, ft.Severity)
	if err != nil {
		return sarif.Report{}, fmt.Errorf("%s: %s: %w", plugin.ImportScanner, ft.Path, err)
	}
	revision, err := s.bind(ctx, ft, meta)
	if err != nil {
		return sarif.Report{}, fmt.Errorf("%s: %w", plugin.ImportScanner, err)
	}
	placeImported(rep.Results, meta, ft.Repositories)
	keep, scoped := scopeImported(rep.Results, outside, ft.Repositories)
	rep.Results, rated = keepOnly(rep.Results, keep), keepOnly(rated, keep)

	sum := sha256.Sum256(data)
	// What a reader needs first leads, and the digest, which a reader checks rather than reads,
	// comes last: the console cuts a long line short from the end.
	fields := []sarif.Field{
		{Key: "tool", Value: toolsOf(meta)},
		{Key: "file", Value: ft.Path},
		{Key: "written", Value: writtenAt(ft.Path, meta)},
		{Key: "severity", Value: severitySource(rep, rated)},
		{Key: "commit", Value: revision},
	}
	if ft.Component != "" {
		fields = append(fields, sarif.Field{Key: "component", Value: ft.Component})
	}
	fields = append(fields, scoped.fields()...)
	fields = append(fields, sarif.Field{Key: "sha256", Value: hex.EncodeToString(sum[:])})
	rep.Provenance = append(rep.Provenance, sarif.Provenance{Tool: plugin.ImportScanner, Fields: fields, Detail: scoped.detail()})
	for _, p := range outside {
		rep.Inputs = append(rep.Inputs, sarif.Input{Scanner: plugin.ImportScanner, Path: p, Unread: outsideCheckout})
	}
	return rep, nil
}

// outsideCheckout is why a finding's path in an imported file could not be placed in the component.
// The finding still counts; what no longer applies to it is anything keyed on a path in the
// repository, an exclusion or a link to the line.
const outsideCheckout = "not in a local checkout of the component, so config.exclude paths skip it"

// checkoutRoots are the local directories of the repositories an imported file describes, which the
// file's absolute paths are made relative to. A repository named by a remote address has no local
// directory here, and the file's relative paths are read as relative to it.
func checkoutRoots(repos []plugin.RepositoryTarget) []string {
	var roots []string
	for _, r := range repos {
		if !git.IsLocalPath(r.URL) {
			continue
		}
		abs, err := filepath.Abs(r.URL)
		if err != nil {
			continue
		}
		roots = append(roots, abs)
	}
	return roots
}

// bind holds a file to the revision this run reads, where the file states the revision it scanned
// or the descriptor's import states it for the file.
//
// A file left from an old run reads exactly like a current scan, and the revision named for it is
// the only thing that tells them apart. A file named for a different commit is refused; a file
// named for none is read and reported as unbound, so a gate can choose to refuse it too.
//
// The descriptor's commit names a commit and no repository. A run whose file states no revision is
// held to it in the repository the run is about, established as placeImported establishes it: the
// component's one repository, or the one of several the run's provenance names. Where that cannot
// be told, the run is not bound, because holding the commit to a repository it may not be in would
// either refuse a current file or bind a stale one by chance.
func (s sarifImport) bind(ctx context.Context, ft plugin.FileTarget, meta importLog) (string, error) {
	var stated []string
	declared := ft.Commit
	for _, run := range meta.Runs {
		var named []string
		vouched := false
		for _, vcp := range run.VersionControlProvenance {
			if vcp.RepositoryURI != "" && !slices.Contains(named, vcp.RepositoryURI) {
				named = append(named, vcp.RepositoryURI)
			}
			if vcp.RevisionID == "" {
				continue
			}
			// Two statements of the commit that disagree: one is wrong, and neither can be trusted
			// to say which. Worded without a colon, which would cut the errors block's reason short.
			if declared != "" && !sameCommit(declared, vcp.RevisionID) {
				return "", fmt.Errorf("%s: names commit %s, the descriptor %s. One of them is wrong",
					ft.Path, short(vcp.RevisionID), short(declared))
			}
			repo, ok := matchRepository(vcp.RepositoryURI, ft.Repositories)
			if !ok {
				// The repository by name, not by address: the report's errors block keeps the last
				// clause of an error and cannot show one that is mostly a URL.
				return "", fmt.Errorf("%s: names repository %s, which component %s does not declare",
					ft.Path, repoName(vcp.RepositoryURI), ft.Component)
			}
			commit, err := s.holdTo(ctx, ft.Path, repo, vcp.RevisionID)
			if err != nil {
				return "", err
			}
			stated, vouched = append(stated, commit), true
		}
		if vouched || declared == "" {
			continue
		}
		repo, ok := repositoryOf(named, ft.Repositories)
		if !ok {
			continue
		}
		commit, err := s.holdTo(ctx, ft.Path, repo, declared)
		if err != nil {
			return "", err
		}
		stated = append(stated, commit)
	}
	if len(stated) == 0 {
		return unbound(ft), nil
	}
	slices.Sort(stated)
	return strings.Join(slices.Compact(stated), ", "), nil
}

// holdTo resolves the commit this run reads in repo and refuses a file named for another, returning
// the commit as the report shows it.
func (s sarifImport) holdTo(ctx context.Context, file string, repo plugin.RepositoryTarget, named string) (string, error) {
	revision := repo.Revision
	if repo.WorkingTree {
		revision = ""
	}
	commit, err := s.resolve(ctx, repo.URL, revision)
	if err != nil {
		return "", fmt.Errorf("%s: names commit %s, and the commit this run reads could not be resolved: %w",
			file, short(named), err)
	}
	if !sameCommit(commit, named) {
		// What to do, inside the errors block's width: the console keeps 80 characters of the
		// reason, and both commits and both remedies fit in it only this short.
		return "", fmt.Errorf("%s: scanned %s, not %s. Run the tool again, or remove the import",
			file, short(named), short(commit))
	}
	return short(commit), nil
}

// unbound is the commit field of a file nothing binds: notStated, and where the descriptor named a
// commit that could not bind it, why, so a reader who wrote one is not left wondering where it went.
// The report reads a value starting notStated as unbound.
func unbound(ft plugin.FileTarget) string {
	switch {
	case ft.CommitUnset != "":
		return notStated + ", ${{ " + ft.CommitUnset + " }} is not set"
	case ft.Commit != "":
		return notStated + ", the file does not say which repository " + short(ft.Commit) + " is in"
	}
	return notStated
}

// placeImported sets each finding's ImportedRepository to the repository of the component its run
// is about, which correlation joins it to its native copy in. results are FromForeignSARIF's, every
// run's in order.
//
// The repository comes from the descriptor and the file and from nothing else: the one the component
// declares, or where it declares several, the one a run's versionControlProvenance names, read as
// matchRepository reads it. A run that names none of several, or names more than one, is about no
// repository Draugr can establish, and its findings are placed in none and merge with nothing. A
// finding counted under a native copy it is not would take a flaw out of the count, so where the
// repository is in doubt both copies stay counted.
func placeImported(results []sarif.Result, meta importLog, repos []plugin.RepositoryTarget) {
	next := 0
	for _, run := range meta.Runs {
		var named []string
		for _, vcp := range run.VersionControlProvenance {
			if vcp.RepositoryURI != "" && !slices.Contains(named, vcp.RepositoryURI) {
				named = append(named, vcp.RepositoryURI)
			}
		}
		where := ""
		if repo, ok := repositoryOf(named, repos); ok {
			where = repo.Source()
		}
		for range run.Results {
			if next >= len(results) {
				return
			}
			results[next].ImportedRepository = where
			next++
		}
	}
}

// importScope counts what scopeImported did with one file's findings.
type importScope struct {
	// outsidePaths and ignored are the findings left out, by the half of the scope that left each out.
	outsidePaths, ignored int
	// notScoped are the findings kept whole because no one repository was established for them, in a
	// component whose repositories declare a scope.
	notScoped int
}

// fields are the provenance's statements of the counts, for a reader: none where nothing was left
// out or kept unscoped, so a file in an unscoped component reads as it always did.
func (s importScope) fields() []sarif.Field {
	var out []sarif.Field
	var left []string
	if s.outsidePaths > 0 {
		left = append(left, english.Count(s.outsidePaths, "finding")+" outside paths")
	}
	if s.ignored > 0 {
		n := english.Count(s.ignored, "finding")
		if len(left) > 0 {
			n = strconv.Itoa(s.ignored)
		}
		left = append(left, n+" matched by ignore")
	}
	if len(left) > 0 {
		out = append(out, sarif.Field{Key: "left out", Value: strings.Join(left, ", ") + ", not counted"})
	}
	if s.notScoped > 0 {
		out = append(out, sarif.Field{Key: "not scoped", Value: english.Count(s.notScoped, "finding") +
			", not in any one repository, so paths and ignore were not applied. Add versionControlProvenance to the file"})
	}
	return out
}

// detail is the counts for a consumer, under the keys report.json reads them by.
func (s importScope) detail() []sarif.Field {
	var out []sarif.Field
	for _, c := range []struct {
		key string
		n   int
	}{{sarif.ImportOutsidePaths, s.outsidePaths}, {sarif.ImportIgnored, s.ignored}, {sarif.ImportNotScoped, s.notScoped}} {
		if c.n > 0 {
			out = append(out, sarif.Field{Key: c.key, Value: strconv.Itoa(c.n)})
		}
	}
	return out
}

// scopeImported says which findings stay in the component: those inside the paths: and ignore: of
// the repository placeImported placed each in. outside are the paths FromForeignSARIF could not place
// in any checkout.
//
// The scope is read with git.Scope.Contains, the matcher a checkout and a history pass use, so an
// imported finding belongs to a component exactly when the same file would be in the tree its own
// scanners read. A tool that scans a whole monorepo writes one file for all of it, and without this
// each component importing that file would count every other component's findings as its own.
//
// Where the scope cannot be applied, the finding stays. A finding with no location, or a path outside
// every checkout, is somewhere nothing can place, and one with no placed repository could be in any
// of the component's repositories, each scoped differently. Leaving either out would drop a flaw on a
// guess. A component that lists one repository several times, a subtree each, keeps a finding inside
// any of them, as its checkouts together hold it.
func scopeImported(results []sarif.Result, outside []string, repos []plugin.RepositoryTarget) ([]bool, importScope) {
	var s importScope
	keep := make([]bool, len(results))
	scoped := slices.ContainsFunc(repos, func(r plugin.RepositoryTarget) bool { return len(r.Paths) > 0 || len(r.Ignore) > 0 })
	for i, r := range results {
		keep[i] = true
		uri := r.Location.URI
		if !scoped || uri == "" || uri == "." || slices.Contains(outside, uri) {
			continue
		}
		if r.ImportedRepository == "" {
			s.notScoped++
			continue
		}
		var scopes []git.Scope
		for _, repo := range repos {
			if repo.Source() == r.ImportedRepository {
				scopes = append(scopes, git.Scope{Paths: repo.Paths, Ignore: repo.Ignore})
			}
		}
		if len(scopes) == 0 || slices.ContainsFunc(scopes, func(sc git.Scope) bool { return sc.Empty() || sc.Contains(uri) }) {
			continue
		}
		keep[i] = false
		// Inside some entry's paths, so that entry's ignore is what removed it.
		if slices.ContainsFunc(scopes, func(sc git.Scope) bool { return git.Scope{Paths: sc.Paths}.Contains(uri) }) {
			s.ignored++
		} else {
			s.outsidePaths++
		}
	}
	return keep, s
}

// keepOnly is the items whose keep entry is true, in order. An item past the end of keep is kept.
func keepOnly[T any](items []T, keep []bool) []T {
	out := items[:0:0]
	for i, item := range items {
		if i >= len(keep) || keep[i] {
			out = append(out, item)
		}
	}
	return out
}

// repositoryOf is the one repository a run is about: the component's only one, whatever the run
// names, or the one of several that the run's one named repository is.
func repositoryOf(named []string, repos []plugin.RepositoryTarget) (plugin.RepositoryTarget, bool) {
	if len(repos) == 0 {
		return plugin.RepositoryTarget{}, false
	}
	uri := ""
	if len(named) == 1 {
		uri = named[0]
	}
	// Checked before matching: an empty address would be matched by name against a repository
	// declared as ".".
	if uri == "" && !singleCheckout(repos) {
		return plugin.RepositoryTarget{}, false
	}
	return matchRepository(uri, repos)
}

// singleCheckout reports whether repos are one repository, listed once or a subtree per entry.
func singleCheckout(repos []plugin.RepositoryTarget) bool {
	for _, r := range repos[1:] {
		if r.URL != repos[0].URL || r.Revision != repos[0].Revision || r.WorkingTree != repos[0].WorkingTree {
			return false
		}
	}
	return true
}

// matchRepository finds the repository a file's versionControlProvenance names. A component with
// one repository is the file's whichever address it gives, because a tool records the remote it saw
// and the descriptor may name the same repository by a local path. With several, the address has to
// name one of them.
//
// Entries naming one repository at one revision are one repository. A component may list a
// repository more than once, a subtree each, and the address in the file cannot pick between
// entries that are the same checkout.
func matchRepository(uri string, repos []plugin.RepositoryTarget) (plugin.RepositoryTarget, bool) {
	type checkout struct {
		url, revision string
		workingTree   bool
	}
	distinct := map[checkout]bool{}
	for _, r := range repos {
		distinct[checkout{r.URL, r.Revision, r.WorkingTree}] = true
	}
	if len(distinct) == 1 {
		return repos[0], true
	}
	want := repoName(uri)
	for _, r := range repos {
		if plugin.SourceURL(r.URL) == plugin.SourceURL(uri) || (want != "" && repoName(r.URL) == want) {
			return r, true
		}
	}
	return plugin.RepositoryTarget{}, false
}

// repoName is the last path segment of a repository address, without .git.
func repoName(raw string) string {
	raw = strings.TrimSuffix(strings.TrimRight(raw, "/"), ".git")
	return path.Base(strings.ReplaceAll(raw, ":", "/"))
}

// sameCommit compares two commit names, either of which may be abbreviated.
func sameCommit(a, b string) bool {
	a, b = strings.ToLower(a), strings.ToLower(b)
	if len(a) < 7 || len(b) < 7 {
		return a == b
	}
	return strings.HasPrefix(a, b) || strings.HasPrefix(b, a)
}

// short is a commit as a reader recognizes it.
func short(commit string) string {
	if len(commit) > 12 {
		return commit[:12]
	}
	return commit
}

// toolsOf names the tools that wrote the file, as the file states them.
func toolsOf(meta importLog) string {
	var tools []string
	for _, run := range meta.Runs {
		d := run.Tool.Driver
		name := d.Name
		if name == "" {
			name = "an unnamed tool"
		}
		if v := cmp.Or(d.Version, d.SemanticVersion); v != "" {
			name += " " + v
		}
		if !slices.Contains(tools, name) {
			tools = append(tools, name)
		}
	}
	return strings.Join(tools, ", ")
}

// writtenAt is when the file says its run ended, or else when the file was last written.
func writtenAt(file string, meta importLog) string {
	for _, run := range meta.Runs {
		for _, inv := range run.Invocations {
			if t, err := time.Parse(time.RFC3339, inv.EndTimeUTC); err == nil {
				return t.UTC().Format("2006-01-02 15:04 UTC")
			}
		}
	}
	if info, err := os.Stat(file); err == nil {
		return info.ModTime().UTC().Format("2006-01-02 15:04 UTC") + " (the file's modification time)"
	}
	return "unknown"
}

// severitySource says where the findings' severities came from: the numeric security-severity a
// tool scores them with, the tool's own rating read by its table or the descriptor's mapping, or the
// SARIF level, which a tool may use for something other than how bad a flaw is. A priority resting
// on a level should say so. rated names the rating each result was read from, "" for none.
func severitySource(rep sarif.Report, rated []string) string {
	if len(rep.Results) == 0 {
		return "no findings"
	}
	type source struct {
		name  string
		count int
	}
	sources := []source{{name: "security-severity"}}
	at := map[string]int{}
	leveled := 0
	for i, r := range rep.Results {
		switch {
		case r.HasScore:
			sources[0].count++
		case i < len(rated) && rated[i] != "":
			if _, seen := at[rated[i]]; !seen {
				at[rated[i]] = len(sources)
				sources = append(sources, source{name: rated[i]})
			}
			sources[at[rated[i]]].count++
		default:
			leveled++
		}
	}
	sources = append(sources, source{"SARIF level", leveled})
	var parts []string
	for _, s := range sources {
		if s.count == len(rep.Results) {
			return s.name
		}
		if s.count > 0 {
			parts = append(parts, fmt.Sprintf("%s for %d", s.name, s.count))
		}
	}
	return strings.Join(parts, ", ")
}
