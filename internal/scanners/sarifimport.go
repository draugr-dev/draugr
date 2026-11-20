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
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// sarifImport reads a SARIF file another tool wrote about a component, or a tool's own JSON where
// Draugr has a reader for it (importReaders), in place of running a scanner: a commercial scanner a
// team already pays for, whose findings should be ranked by the component's exposure and criticality
// and judged by the same gate as everything Draugr runs.
//
// It runs nothing, so it has no tool to install and no third party's terms to read. What it owes
// the reader instead is an account of the file: whose it is, when it was written, which revision it
// describes, and where its severities came from, because Draugr did not produce any of that.
type sarifImport struct {
	// resolve turns a repository's revision into a commit, so a file that states the revision it
	// scanned can be held to the one this run reads. Injectable for tests.
	resolve func(ctx context.Context, url, revision string) (string, error)
	// github reads the alerts an import names a GitHub source for. Injectable for tests, which
	// answer from recorded responses.
	github githubClient
}

// NewSARIFImport returns the scanner every import is planned for.
func NewSARIFImport() plugin.Scanner {
	return sarifImport{resolve: git.ResolveRevision, github: newGitHubClient()}
}

// Info describes the import scanner.
//
// Reading a file is no effect. Reading a source is: the scan sends GitHub a request for the
// repository's alerts, carrying the token, which an import of a file never does. Declared per source
// so the report records it only for a run that read one, and `draugr controls` lists it.
func (sarifImport) Info() plugin.ScannerInfo {
	return plugin.ScannerInfo{
		Name:         plugin.ImportScanner,
		Origin:       "draugr",
		TargetKinds:  []plugin.TargetKind{plugin.TargetFile},
		ConfigSchema: json.RawMessage(noScannerOptions),
		Effects: []plugin.Effect{
			{Kind: plugin.EffectNetwork, Source: saga.ImportSourceGitHubCodeScanning, Online: true,
				Detail: "asks GitHub's REST API for the repository's code-scanning alerts, with the import's token"},
			{Kind: plugin.EffectNetwork, Source: saga.ImportSourceGitHubDependabot, Online: true,
				Detail: "asks GitHub's REST API for the repository's Dependabot alerts, with the import's token"},
		},
	}
}

// importLog is the part of a SARIF log the import reads for itself: what FromForeignSARIF does not
// keep. A reader of a tool's own JSON writes one for the file, from what the file states.
type importLog struct {
	Version string      `json:"version"`
	Runs    []importRun `json:"runs"`
}

// importRun is one run of a tool, as importLog reads it.
type importRun struct {
	Tool struct {
		Driver importDriver `json:"driver"`
	} `json:"tool"`
	Invocations              []importInvocation `json:"invocations"`
	VersionControlProvenance []struct {
		RepositoryURI string `json:"repositoryUri"`
		RevisionID    string `json:"revisionId"`
	} `json:"versionControlProvenance"`
	// Results are counted, not read: FromForeignSARIF returns every run's results in order, and
	// the count says which of them a run's provenance describes.
	Results []json.RawMessage `json:"results"`
}

// importInvocation is one invocation of a run's tool, read for when it ended.
type importInvocation struct {
	EndTimeUTC string `json:"endTimeUtc"`
}

// importDriver is the tool a run names.
type importDriver struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	// SemanticVersion is the other place SARIF lets a tool put its version.
	SemanticVersion string `json:"semanticVersion"`
}

// notStated is the commit field's value for a file that names none, which the report lists as an
// unbound import.
const notStated = "not stated"

// importRead is what a format's reader makes of a file: the findings, and the account of the file the
// rest of the import holds it to.
type importRead struct {
	rep sarif.Report
	// outside are the findings' paths that are absolute and in no local checkout of the component.
	outside []string
	// meta is the file's runs, each with the tool, when it ended, the repository and commit it names,
	// and how many of rep's results are its own.
	meta importLog
	// rated names, for each result, the rating its severity was read from, "" for its level.
	rated []string
	// scored names where a result's numeric score came from, for the severity field.
	scored string
}

// importReader reads one format, given the file's contents and the import it is read for.
type importReader func(data []byte, ft plugin.FileTarget) (importRead, error)

// importReaders are the formats an import reads, by the name the descriptor gives them. A tool's own
// JSON is read with the parser Draugr's run of that tool uses, so a finding carries what a native one
// does; a new format is a reader here and a name in saga.ImportFormats.
var importReaders = map[string]importReader{
	saga.ImportFormatSARIF:           readSARIFImport,
	saga.ImportFormatTrivyJSON:       readTrivyImport,
	saga.ImportFormatGovulncheckJSON: readGovulncheckImport,
	saga.ImportFormatGrypeJSON:       readGrypeImport,
	saga.ImportFormatConverter:       readConverterImport,
}

// readImport reads data as the format ft names.
func readImport(data []byte, ft plugin.FileTarget) (importRead, error) {
	format := cmp.Or(ft.Format, saga.ImportFormatSARIF)
	read, ok := importReaders[format]
	if !ok {
		// The list is left out, which the errors block could not hold whole: draugr validate refuses
		// the format first, naming every one.
		return importRead{}, fmt.Errorf("format %s is not one Draugr reads. draugr validate lists them", format)
	}
	return read(data, ft)
}

// readSARIFImport reads a SARIF 2.1.0 log.
func readSARIFImport(data []byte, ft plugin.FileTarget) (importRead, error) {
	rep, outside, err := sarif.FromForeignSARIF(data, checkoutRoots(ft.Repositories))
	if err != nil {
		return importRead{}, err
	}
	var meta importLog
	if err := json.Unmarshal(data, &meta); err != nil {
		return importRead{}, err
	}
	rated, err := rateImported(&rep, data, ft.Severity)
	if err != nil {
		return importRead{}, err
	}
	return importRead{rep: rep, outside: outside, meta: meta, rated: rated, scored: "security-severity"}, nil
}

// Scan reads the file. Anything that keeps it from being read as its format is an error, as for a
// scanner that could not run: a missing file contributes no findings, which is exactly what a clean
// one contributes, and the two must not look alike.
func (s sarifImport) Scan(ctx context.Context, target plugin.Target, _ plugin.Config) (sarif.Report, error) {
	ft, ok := target.(plugin.FileTarget)
	if !ok {
		return sarif.Report{}, fmt.Errorf("%s: unsupported target %T (want file)", plugin.ImportScanner, target)
	}
	if ft.Source != "" {
		return s.scanGitHub(ctx, ft)
	}
	data, err := os.ReadFile(ft.Path) // #nosec G304 -- the file the descriptor names for import
	if err != nil {
		return sarif.Report{}, fmt.Errorf("%s: read %s: %w", plugin.ImportScanner, ft.Path, err)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return sarif.Report{}, fmt.Errorf("%s: %s is empty", plugin.ImportScanner, ft.Path)
	}
	read, err := readImport(data, ft)
	if err != nil {
		return sarif.Report{}, fmt.Errorf("%s: %s: %w", plugin.ImportScanner, ft.Path, err)
	}
	rep, meta, rated := read.rep, read.meta, read.rated
	revision, err := s.bind(ctx, ft, meta)
	if err != nil {
		return sarif.Report{}, fmt.Errorf("%s: %w", plugin.ImportScanner, err)
	}
	if strings.HasPrefix(revision, notStated) {
		undetermineAbsence(rep.Results)
	}
	placeImported(rep.Results, meta, ft.Repositories)
	toolsSuppressions(rep.Results, ft)
	keep, scoped := scopeImported(rep.Results, read.outside, ft.Repositories)
	rep.Results, rated = keepOnly(rep.Results, keep), keepOnly(rated, keep)
	keep, scoped.folded = foldRepeats(rep.Results)
	rep.Results, rated = keepOnly(rep.Results, keep), keepOnly(rated, keep)
	ownJSON := toolJSON(ft)
	// Beside the tool on every row that names who reported a finding: the format, or for a
	// converter's file, the converter, which is whose account the row's properties are.
	shown := ownJSON
	if ft.Converter != nil && ownJSON == saga.ImportFormatConverter {
		shown = "converter " + ft.Converter.Name
	}
	for i := range rep.Results {
		rep.Results[i].ImportFormat = shown
	}

	sum := sha256.Sum256(data)
	// What a reader needs first leads, and the digest, which a reader checks rather than reads,
	// comes last: the console cuts a long line short from the end. The format is beside the tool,
	// and only where it is the tool's own JSON, so a SARIF import reads as it always did.
	fields := []sarif.Field{{Key: "tool", Value: toolsOf(meta)}}
	if ownJSON != "" {
		fields = append(fields, sarif.Field{Key: "format", Value: ownJSON})
	}
	if ft.Converter != nil && ownJSON == saga.ImportFormatConverter {
		fields = append(fields, sarif.Field{Key: "converter", Value: converterNote(data, ft)})
	}
	fields = append(fields,
		sarif.Field{Key: "file", Value: ft.Path},
		sarif.Field{Key: "written", Value: writtenAt(ft.Path, meta)},
		sarif.Field{Key: "severity", Value: severitySource(rep, rated, read.scored)},
		sarif.Field{Key: "commit", Value: revision},
	)
	if ft.Component != "" {
		fields = append(fields, sarif.Field{Key: "component", Value: ft.Component})
	}
	scoped.ownJSON = ownJSON
	fields = append(fields, scoped.fields()...)
	fields = append(fields, sarif.Field{Key: "sha256", Value: hex.EncodeToString(sum[:])})
	rep.Provenance = append(rep.Provenance, sarif.Provenance{Tool: plugin.ImportScanner, Fields: fields, Detail: scoped.detail()})
	for _, p := range read.outside {
		rep.Inputs = append(rep.Inputs, sarif.Input{Scanner: plugin.ImportScanner, Path: p, Unread: outsideCheckout})
	}
	return rep, nil
}

// toolsSuppressions settles what a finding the file's tool suppressed does here, as the import's
// suppressions setting says.
//
// Honored, the default, it is set aside and names the file it was read from, so report.json says
// where the tool recorded the suppression as well as which tool. Counted, it counts, and its detail
// keeps what the tool recorded: the tool, where and why. Either way nothing the file said about the
// finding is lost, and the gate judges the findings the setting leaves counting.
func toolsSuppressions(results []sarif.Result, ft plugin.FileTarget) {
	for i := range results {
		r := &results[i]
		if r.Suppression == nil {
			continue
		}
		if !ft.CountSuppressed {
			// A tool's own JSON may already name the file it read the suppression from, such as
			// Trivy's .trivyignore, which says more than the import's file does.
			r.Suppression.Source = cmp.Or(r.Suppression.Source, ft.Path)
			continue
		}
		tool := cmp.Or(r.Tool, "the tool")
		// The setting last, as the key a reader edits to set these aside again: the console keeps the
		// end of a long detail and cuts the start, where the tool is named again on the line below.
		said := fmt.Sprintf("%s suppressed it %s · %s · counted, as the import says suppressions: count",
			tool, sarif.SuppressedIn(r.Suppression.Kind), sarif.GivenReason(r.Suppression.Justification))
		r.Suppression = nil
		r.Detail = strings.TrimPrefix(r.Detail+" · "+said, " · ")
	}
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
			// Two statements of the commit that disagree, and neither can be trusted to say which is
			// wrong, so the reason names both and both fixes. Worded without a colon, which would cut
			// the errors block's reason short.
			if declared != "" && !sameCommit(declared, vcp.RevisionID) {
				return "", fmt.Errorf("%s: file has %s, commit is %s. Fix commit, or run the tool again",
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
		// reason, which holds both commits and one remedy. Removing the import is in the docs.
		return "", fmt.Errorf("%s: scanned %s, this run reads %s. Run the tool again",
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
	case ft.Commit != "" && toolJSON(ft) != "":
		// A tool's own JSON names no repository, so with several nothing says which one commit is in.
		return notStated + ", " + toolJSON(ft) + " names no repository and the component has several"
	case ft.Commit != "":
		return notStated + ", the file names none or several of the component's repositories"
	}
	return notStated
}

// undetermineAbsence makes each unreachable verdict of a file bound to no commit undetermined, the
// state of a dependency no analysis of this code covered.
//
// Unreachable lowers a finding's band, and nothing shows that an unbound file's run analyzed the code
// this run reads: an older commit, or another repository, can lack a call this one makes. Lowering on
// it would take the safer reading of code nobody checked. Undetermined rather than a state of its own
// that moves nothing, because undetermined already says exactly that, and every count, band and
// report reads it as an analyzer that did not decide. A reachable verdict stays: a call path found in
// some revision never makes a finding look safer than it is.
func undetermineAbsence(results []sarif.Result) {
	for i := range results {
		r := results[i].Reachability
		if r == nil || r.State != sarif.ReachabilityUnreachable {
			continue
		}
		undetermined := *r
		undetermined.State = sarif.ReachabilityUnknown
		results[i].Reachability = &undetermined
		if msg, ok := strings.CutSuffix(results[i].Message, govulncheckNeverCalled); ok {
			results[i].Message = msg + ", reachability not determined: the file is bound to no commit"
		}
	}
}

// toolJSON is the format of a file that is a tool's own JSON rather than SARIF, and "" for SARIF.
func toolJSON(ft plugin.FileTarget) string {
	if ft.Format == saga.ImportFormatSARIF {
		return ""
	}
	return ft.Format
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
	// folded are the findings that repeated another of the file's in every respect, counted once.
	folded int
	// ownJSON is the file's format where it is a tool's own JSON, which has nowhere to name a
	// repository, so the remedy for findings not scoped is another component rather than the file.
	ownJSON string
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
		remedy := "Add versionControlProvenance to the file"
		if s.ownJSON != "" {
			remedy = "Move the " + s.ownJSON + " import to a component with one repository"
		}
		out = append(out, sarif.Field{Key: "not scoped", Value: english.Count(s.notScoped, "finding") +
			", not in any one repository, so paths and ignore were not applied. " + remedy})
	}
	if s.folded > 0 {
		out = append(out, sarif.Field{Key: "folded", Value: english.Count(s.folded, "finding") +
			" repeating another of the file's exactly, counted once"})
	}
	return out
}

// detail is the counts for a consumer, under the keys report.json reads them by.
func (s importScope) detail() []sarif.Field {
	var out []sarif.Field
	for _, c := range []struct {
		key string
		n   int
	}{{sarif.ImportOutsidePaths, s.outsidePaths}, {sarif.ImportIgnored, s.ignored}, {sarif.ImportNotScoped, s.notScoped},
		{sarif.ImportFolded, s.folded}} {
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

// foldRepeats says which findings to keep where several are one: alike in every respect the
// fingerprint compares, which for a dependency finding includes its package. It keeps the first and
// returns how many it folded into it.
//
// A merge would fold them anyway, since one fingerprint is one finding, and without a word, so a
// file that lists a finding twice would read exactly like one that lists it once. Folded here
// instead, where the count can be stated. Compared as the engine will stamp them, under the import
// scanner, because every finding of one file gets the same component and repository.
func foldRepeats(results []sarif.Result) ([]bool, int) {
	keep := make([]bool, len(results))
	seen := make(map[string]bool, len(results))
	folded := 0
	for i, r := range results {
		r.Scanner = plugin.ImportScanner
		fp := r.Fingerprint()
		if seen[fp] {
			folded++
			continue
		}
		seen[fp], keep[i] = true, true
	}
	return keep, folded
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
// on a level should say so. rated names the rating each result was read from, "" for none, and
// scored where a numeric score came from: security-severity in SARIF, a CVSS score in Trivy's JSON.
func severitySource(rep sarif.Report, rated []string, scored string) string {
	if len(rep.Results) == 0 {
		return "no findings"
	}
	type source struct {
		name  string
		count int
	}
	sources := []source{{name: scored}}
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
