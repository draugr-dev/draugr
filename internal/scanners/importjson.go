package scanners

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/draugr-dev/draugr/internal/english"
	"github.com/draugr-dev/draugr/internal/git"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// A dependency scanner's SARIF says which advisory and where, and says which package and which
// version fixes it only in prose, if at all; govulncheck's SARIF carries no call path. The tools' own
// JSON keeps all of it as fields, and Draugr already reads that JSON for its own runs of Trivy and
// govulncheck. So an import of a tool's JSON is read with the same parser, and an imported finding
// is the finding a native run of the tool makes of the same file.
//
// What the parsers take from a native run besides the output is the checkout the tool read. An
// import passes the local checkout of the component's one repository, where it has one, and reads
// from it only what a native run reads to place a finding: the line of a package's entry in its
// manifest, and the go.mod of each Go module. Neither decides whether a finding exists, its
// severity, or its verdict, and the commit binding is what says the checkout is the code the file
// was written from. Everything a native run reads of the build on this machine is left out, because
// the file was written from another machine's: see readGovulncheckImport.

// readTrivyImport reads the JSON `trivy fs --format json` writes, with the parser trivy-fs uses.
//
// The packages Trivy listed, and the dependency files it read, are left out of the report: a native
// run reports them for the tree it read, where the tree walk compares them with the checkout and the
// malicious-package check reads the list, and an imported file's are an account of a tree on another
// machine, read with options this run does not know.
func readTrivyImport(data []byte, ft plugin.FileTarget) (importRead, error) {
	var head struct {
		SchemaVersion int `json:"SchemaVersion"`
		Trivy         struct {
			Version string `json:"Version"`
		} `json:"Trivy"`
		CreatedAt string `json:"CreatedAt"`
	}
	// SchemaVersion is the one field every Trivy JSON report opens with, and no SARIF log,
	// CycloneDX document or other tool's JSON has it. Without the check such a file would decode to
	// a report with no results and read as a clean scan.
	if err := json.Unmarshal(data, &head); err != nil || head.SchemaVersion == 0 {
		return importRead{}, errNotTrivyJSON
	}
	if head.SchemaVersion != trivySchemaVersion {
		return importRead{}, fmt.Errorf("schema %d Trivy JSON; Draugr reads schema %d", head.SchemaVersion, trivySchemaVersion)
	}
	doc, err := decodeTrivyVulns(data)
	if err != nil {
		return importRead{}, errNotTrivyJSON
	}
	rep := trivyVulnReport(doc, importRoot(ft.Repositories), nil)
	rep.Inputs, rep.Inventory = nil, nil
	outside := relativeToCheckouts(rep.Results, checkoutRoots(ft.Repositories))

	rated := make([]string, len(rep.Results))
	for i, r := range rep.Results {
		if !r.HasScore {
			rated[i] = "Trivy's severity"
		}
	}
	var run importRun
	run.Tool.Driver = importDriver{Name: rep.Tool, Version: head.Trivy.Version}
	if head.CreatedAt != "" {
		run.Invocations = append(run.Invocations, importInvocation{EndTimeUTC: head.CreatedAt})
	}
	run.Results = make([]json.RawMessage, len(rep.Results))
	return importRead{rep: rep, outside: outside, meta: importLog{Runs: []importRun{run}}, rated: rated,
		scored: "CVSS score"}, nil
}

// trivySchemaVersion is the version of Trivy's JSON report the parser reads.
const trivySchemaVersion = 2

// errNotTrivyJSON is the error of a file that is not Trivy's JSON report, worded for the errors
// block, which keeps the clause after the last colon.
var errNotTrivyJSON = errors.New("not Trivy JSON. Write it with trivy fs --format json")

// errNotGovulncheckJSON is the error of a file that is not govulncheck's JSON stream.
var errNotGovulncheckJSON = errors.New("not govulncheck JSON. Write it with govulncheck -format json")

// readGovulncheckImport reads the stream `govulncheck -format json` writes, each run turned into
// findings by the function govulncheck's own runs use, so an imported finding carries the module,
// its fixed version and the verdict, with its call paths, that a native one does.
//
// The verdict needs nothing but the stream. Reachable is a call path the run found; unreachable
// needs the run to have analyzed symbols and to list the module in what it built, both of which the
// stream states. Each run is located at the go.mod of the module it analyzed, matched from the
// packages it started from to the modules of the component's checkout, as a native run's is.
//
// What a native run adds from this machine is left out. It plans a run per module and per platform
// and refuses output that does not match the plan, and it marks the requirements its runs did not
// compile as not built. Both describe the build on this machine, with its Go, its tags and its
// platforms, which may not be the build the file's runs analyzed; a requirement marked not built on
// that reading would be evidence about a build nobody checked. A verdict is not narrowed to the call
// paths that start in a component's own paths either: govulncheck reports a sample of the paths it
// found, so a narrowed verdict would be read only as undetermined, and an imported reachable verdict
// that keeps a path from elsewhere in the module still names a call the module makes.
func readGovulncheckImport(data []byte, ft plugin.FileTarget) (importRead, error) {
	msgs, err := decodeGovulncheckStream(data)
	if err != nil || len(msgs) == 0 {
		return importRead{}, errNotGovulncheckJSON
	}
	runs := splitGovulncheckRuns(msgs)
	// Every run govulncheck writes opens with its config, which says how far it looked. A stream
	// without one is some other JSON, which would decode to no findings and read as clean.
	for _, run := range runs {
		if run[0].Config == nil {
			return importRead{}, errNotGovulncheckJSON
		}
	}
	manifests := goModuleManifests(importRoot(ft.Repositories))
	asOf := fileDay(ft.Path)
	var rep sarif.Report
	rep.Tool = govulncheckScanner
	var meta importLog
	for _, run := range runs {
		results := govulncheckRunResults(run, manifests, asOf)
		rep.Results = append(rep.Results, results...)
		var r importRun
		cfg := run[0].Config
		r.Tool.Driver = importDriver{Name: cmp.Or(cfg.ScannerName, govulncheckScanner), Version: cfg.ScannerVersion}
		r.Results = make([]json.RawMessage, len(results))
		meta.Runs = append(meta.Runs, r)
	}
	rated := make([]string, len(rep.Results))
	for i := range rated {
		// The Go vulnerability database publishes no severity, and a native run's finding is read at
		// the level its parser gives every one, as an imported one is.
		rated[i] = "govulncheck states none, read as medium"
	}
	return importRead{rep: rep, meta: meta, rated: rated, scored: "security-severity"}, nil
}

// importRoot is the local directory of the repository an imported tool's JSON is about: the
// component's one repository, listed once or a subtree per entry, where its url is a path. Empty
// with several repositories, since the JSON names none, and for a repository named by a remote
// address, which has no directory here.
func importRoot(repos []plugin.RepositoryTarget) string {
	repo, ok := repositoryOf(nil, repos)
	if !ok || !git.IsLocalPath(repo.URL) {
		return ""
	}
	abs, err := filepath.Abs(repo.URL)
	if err != nil {
		return ""
	}
	return abs
}

// relativeToCheckouts makes each finding's absolute path relative to the local checkout that holds
// it, as the SARIF reader does, and returns the absolute paths no checkout holds, which are kept as
// written.
func relativeToCheckouts(results []sarif.Result, roots []string) []string {
	var outside []string
	for i := range results {
		uri := strings.TrimPrefix(results[i].Location.URI, "file://")
		if !filepath.IsAbs(uri) {
			continue
		}
		results[i].Location.URI = uri
		for _, root := range roots {
			if rel := repoRelPath(root, uri); rel != uri {
				results[i].Location.URI = rel
				break
			}
		}
		if results[i].Location.URI == uri && !slices.Contains(outside, uri) {
			outside = append(outside, uri)
		}
	}
	return outside
}

// fileDay is the day a file was last written, as a verdict dates its analysis, or "" where the file
// cannot be read.
func fileDay(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return ""
	}
	return info.ModTime().UTC().Format("2006-01-02")
}

// importFormatNames are what doctor calls each format.
var importFormatNames = map[string]string{
	saga.ImportFormatSARIF:           "SARIF 2.1.0",
	saga.ImportFormatTrivyJSON:       "Trivy JSON",
	saga.ImportFormatGovulncheckJSON: "govulncheck JSON",
}

// DescribeImport reads data as an import of format would, empty being SARIF, and says what it is and
// how much it holds: "SARIF 2.1.0, 3 results", "Trivy JSON, 4 findings". A file the scan would
// refuse returns the scan's error. Nothing is held to a commit or placed in a repository.
func DescribeImport(data []byte, format string) (string, error) {
	format = cmp.Or(format, saga.ImportFormatSARIF)
	read, err := readImport(data, plugin.FileTarget{Format: format})
	if err != nil {
		return "", err
	}
	noun := "finding"
	if format == saga.ImportFormatSARIF {
		noun = "result"
	}
	return importFormatNames[format] + ", " + english.Count(len(read.rep.Results), noun), nil
}
