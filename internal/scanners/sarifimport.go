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
	"slices"
	"strings"
	"time"

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

// importLog is the part of a SARIF log the import reads for itself: what FromSARIF does not keep.
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
	rep, err := sarif.FromSARIF(data)
	if err != nil {
		return sarif.Report{}, fmt.Errorf("%s: %s: %w", plugin.ImportScanner, ft.Path, err)
	}
	var meta importLog
	if err := json.Unmarshal(data, &meta); err != nil {
		return sarif.Report{}, fmt.Errorf("%s: %s: %w", plugin.ImportScanner, ft.Path, err)
	}
	if meta.Version != "2.1.0" {
		return sarif.Report{}, fmt.Errorf("%s: %s states SARIF version %q, and Draugr reads 2.1.0",
			plugin.ImportScanner, ft.Path, meta.Version)
	}
	if len(meta.Runs) == 0 {
		return sarif.Report{}, fmt.Errorf("%s: %s holds no runs, so it says nothing about what was scanned",
			plugin.ImportScanner, ft.Path)
	}
	revision, err := s.bind(ctx, ft, meta)
	if err != nil {
		return sarif.Report{}, fmt.Errorf("%s: %w", plugin.ImportScanner, err)
	}

	sum := sha256.Sum256(data)
	// What a reader needs first leads, and the digest, which a reader checks rather than reads,
	// comes last: the console cuts a long line short from the end.
	fields := []sarif.Field{
		{Key: "tool", Value: toolsOf(meta)},
		{Key: "file", Value: ft.Path},
		{Key: "written", Value: writtenAt(ft.Path, meta)},
		{Key: "severity", Value: severitySource(rep)},
		{Key: "commit", Value: revision},
	}
	if ft.Component != "" {
		fields = append(fields, sarif.Field{Key: "component", Value: ft.Component})
	}
	fields = append(fields, sarif.Field{Key: "sha256", Value: hex.EncodeToString(sum[:])})
	rep.Provenance = append(rep.Provenance, sarif.Provenance{Tool: plugin.ImportScanner, Fields: fields})
	return rep, nil
}

// bind holds a file to the revision this run reads, where the file states the revision it scanned.
//
// A file left from an old run reads exactly like a current scan, and the revision it names is the
// only thing that tells them apart. A file that names one for a different commit is refused; a file
// that names none is read and reported as unbound, so a gate can choose to refuse it too.
func (s sarifImport) bind(ctx context.Context, ft plugin.FileTarget, meta importLog) (string, error) {
	var stated []string
	for _, run := range meta.Runs {
		for _, vcp := range run.VersionControlProvenance {
			if vcp.RevisionID == "" {
				continue
			}
			repo, ok := matchRepository(vcp.RepositoryURI, ft.Repositories)
			if !ok {
				return "", fmt.Errorf("%s states repository %s, which component %s does not declare",
					ft.Path, vcp.RepositoryURI, ft.Component)
			}
			revision := repo.Revision
			if repo.WorkingTree {
				revision = ""
			}
			commit, err := s.resolve(ctx, repo.URL, revision)
			if err != nil {
				return "", fmt.Errorf("%s states commit %s, and the commit this run reads could not be resolved: %w",
					ft.Path, vcp.RevisionID, err)
			}
			if !sameCommit(commit, vcp.RevisionID) {
				return "", fmt.Errorf("%s was written for commit %s, and this run reads %s: run the tool "+
					"again on this commit, or remove the import", ft.Path, short(vcp.RevisionID), short(commit))
			}
			stated = append(stated, short(commit))
		}
	}
	if len(stated) == 0 {
		return notStated, nil
	}
	slices.Sort(stated)
	return strings.Join(slices.Compact(stated), ", "), nil
}

// matchRepository finds the repository a file's versionControlProvenance names. A component with
// one repository is the file's whichever address it gives, because a tool records the remote it saw
// and the descriptor may name the same repository by a local path. With several, the address has to
// name one of them.
func matchRepository(uri string, repos []plugin.RepositoryTarget) (plugin.RepositoryTarget, bool) {
	if len(repos) == 1 {
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
// tool scores them with, or the SARIF level, which a tool may use for something other than how bad
// a flaw is. A priority resting on a level should say so.
func severitySource(rep sarif.Report) string {
	scored := 0
	for _, r := range rep.Results {
		if r.HasScore {
			scored++
		}
	}
	switch {
	case len(rep.Results) == 0:
		return "no findings"
	case scored == len(rep.Results):
		return "security-severity"
	case scored == 0:
		return "SARIF level"
	}
	return fmt.Sprintf("security-severity for %d, SARIF level for %d", scored, len(rep.Results)-scored)
}
