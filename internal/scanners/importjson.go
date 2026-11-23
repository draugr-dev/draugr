package scanners

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
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
		switch {
		case r.Rating != nil && r.Rating.Detail == notScoredYet:
			rated[i] = "Trivy's UNKNOWN, " + notScoredYet + ", read as high"
		case !r.HasScore:
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
	if repo, ok := repositoryOf(nil, ft.Repositories); ok {
		rep.Inputs = govulncheckImportCoverage(runs, manifests, repo.Source())
	}
	return importRead{rep: rep, meta: meta, rated: rated, scored: "security-severity"}, nil
}

// govulncheckImportCoverage accounts for each Go module of the checkout as the file's runs covered
// it: analyzed where a run started from its packages, and not analyzed otherwise, with the command
// that would cover it.
//
// govulncheck analyzes the one module it is run in, so `govulncheck ./...` at the root of a
// repository with a second module says nothing about the second, and a dependency finding there
// gets no verdict. It keeps the band its manifest scanner gave it, which is the safe direction, but
// a report that names only what was analyzed reads as though the whole repository was. Each module
// is accounted for, analyzed or not, so a file per module, each imported, covers them all: the
// engine lists a module as not analyzed only where no report analyzed it.
//
// With no local checkout there are no modules to account for, and nothing is said.
//
// Each is stamped with the repository's identity as a native scanner's are, so a module one scanner
// read and the import did not analyze is one file.
func govulncheckImportCoverage(runs [][]govulncheckMessage, manifests map[string]string, repository string) []sarif.Input {
	if len(manifests) == 0 {
		return nil
	}
	covered := map[string]bool{}
	for _, run := range runs {
		for _, m := range run {
			if m.SBOM == nil {
				continue
			}
			if gomod, ok := govulncheckManifest(m.SBOM.Roots, manifests); ok {
				covered[gomod] = true
			}
		}
	}
	gomods := make([]string, 0, len(manifests))
	for _, gomod := range manifests {
		gomods = append(gomods, gomod)
	}
	slices.Sort(gomods)
	out := make([]sarif.Input, 0, len(gomods))
	for _, gomod := range gomods {
		in := sarif.Input{Scanner: plugin.ImportScanner, Repository: repository, Path: gomod, Analysis: true}
		if !covered[gomod] {
			in.Unread = notAnalyzedByImport(gomod)
		}
		out = append(out, in)
	}
	return out
}

// notAnalyzedByImport is why a Go module has no verdict from an imported govulncheck file, with the
// command whose output, imported too, would give it one. Short, and the command last, because the
// console cuts a caveat's reason at the width of its row.
func notAnalyzedByImport(gomod string) string {
	if dir := path.Dir(gomod); dir != "." {
		return "Run and import: govulncheck -C " + dir + " -format json ./..."
	}
	return "Run and import: govulncheck -format json ./... at the root"
}

// errNotGrypeJSON is the error of a file that is not Grype's JSON report.
var errNotGrypeJSON = errors.New("not Grype JSON. Write it with grype dir:. -o json")

// readGrypeImport reads the JSON `grype dir:<path> -o json` writes, with the parser grype-fs uses.
//
// grype-fs reads the two reports one Grype run writes: the SARIF, for each finding's message, level,
// score, location and fingerprint, and the JSON, for each finding's own package, the identifiers
// Grype relates to it, and the matches Grype's configuration ignored. A run asked for JSON alone
// writes no SARIF, so the reader writes it from the JSON's match records as Grype's SARIF output
// writes it (grypeSARIFOf), and reads the two together as grype-fs does. An imported finding is then
// the finding grype-fs makes of the same run, its related CVE included, which is what KEV and EPSS
// are read by when Grype reports a finding under a GitHub or Go advisory id.
//
// Only a scan of a directory is read. A finding of an image scan is about the image rather than the
// component's repositories, which place and scope an import, and Grype's SARIF locates and
// fingerprints it by the image's name, which its JSON does not state.
//
// The checkout is read for one thing a native run reads there: the `.grype.yaml` that may hold a rule
// that ignored a match, to name it as the suppression's source. With no local checkout, none is named.
func readGrypeImport(data []byte, ft plugin.FileTarget) (importRead, error) {
	var head struct {
		Matches    json.RawMessage `json:"matches"`
		Descriptor struct {
			Name      string `json:"name"`
			Version   string `json:"version"`
			Timestamp string `json:"timestamp"`
		} `json:"descriptor"`
	}
	// Every Grype JSON report names Grype in its descriptor and lists its matches, an empty list for a
	// clean scan. A SARIF log, a CycloneDX document or another tool's JSON has neither, and would
	// decode to no matches and read as a clean scan.
	if err := json.Unmarshal(data, &head); err != nil || head.Descriptor.Name != "grype" || len(head.Matches) == 0 {
		return importRead{}, errNotGrypeJSON
	}
	var doc grypeDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return importRead{}, errNotGrypeJSON
	}
	if doc.Source.Type != "directory" {
		return importRead{}, fmt.Errorf("%s scan; Draugr reads only directory scans. Run grype dir:. -o json", doc.Source.Type)
	}
	sarifOut, err := grypeSARIFOf(doc, head.Descriptor.Version)
	if err != nil {
		return importRead{}, err
	}
	rep, err := sarif.FromSARIF(sarifOut)
	if err != nil {
		return importRead{}, err
	}
	root := importRoot(ft.Repositories)
	var rules func() []grypeRuleFile
	if root != "" {
		rules = func() []grypeRuleFile { return grypeConfigRules(root) }
	}
	if err := withGrypeJSON(&rep, sarifOut, doc, rules); err != nil {
		return importRead{}, err
	}
	grypeRepoPaths(rep.Results, root)

	rated := make([]string, len(rep.Results))
	for i := range rated {
		// Grype scores every finding it reports, with the CVSS score it holds or else the lowest score
		// of the band its severity names. A match its configuration ignored and Grype rates
		// negligible carries no score, and is read at the level Grype's severity gives it.
		rated[i] = "Grype's severity"
	}
	var run importRun
	run.Tool.Driver = importDriver{Name: head.Descriptor.Name, Version: head.Descriptor.Version}
	if head.Descriptor.Timestamp != "" {
		run.Invocations = append(run.Invocations, importInvocation{EndTimeUTC: head.Descriptor.Timestamp})
	}
	run.Results = make([]json.RawMessage, len(rep.Results))
	return importRead{rep: rep, meta: importLog{Runs: []importRun{run}}, rated: rated,
		scored: "CVSS score, else Grype's severity"}, nil
}

// grypeSARIFOf writes the SARIF Grype writes for the matches of doc, a directory scan's JSON report:
// a rule for each advisory and package name, from its first match, and a result for each match, as
// Grype's SARIF output (grype/presenter/sarif) builds them from the same records. Checked against the
// SARIF and JSON one run of Grype 0.121.0 wrote.
func grypeSARIFOf(doc grypeDoc, version string) ([]byte, error) {
	in := grypeInputPath(doc)
	rules, results := []any{}, []any{}
	ruled := map[string]bool{}
	for _, m := range doc.Matches {
		id := m.Vulnerability.ID + "-" + m.Artifact.Name
		severity := grypeSeverityText(m.Vulnerability.Severity)
		at := grypePackagePath(m, in)
		if !ruled[id] {
			ruled[id] = true
			rules = append(rules, grypeReportedRule(m, id, severity, at))
		}
		results = append(results, map[string]any{
			"ruleId": id,
			"level":  grypeLevel(severity),
			"message": map[string]any{"text": fmt.Sprintf("A %s vulnerability in %s package: %s, version %s was found at: %s",
				severity, m.Artifact.Type, m.Artifact.Name, m.Artifact.Version, at)},
			"locations": []any{map[string]any{"physicalLocation": map[string]any{
				"artifactLocation": map[string]any{"uri": at},
				"region":           map[string]any{"startLine": 1, "startColumn": 1, "endLine": 1, "endColumn": 1},
			}}},
			"partialFingerprints": map[string]any{"primaryLocationLineHash": grypeLineHash(m, at)},
		})
	}
	return json.Marshal(map[string]any{"version": "2.1.0", "runs": []any{map[string]any{
		"tool":    map[string]any{"driver": map[string]any{"name": "grype", "version": cmp.Or(version, "0.0.0-dev"), "rules": rules}},
		"results": results,
	}}})
}

// grypeReportedRule is the rule Grype's SARIF writes for the first match m of an advisory and package
// name: severity is Grype's word for the match's severity and at the package's location.
func grypeReportedRule(m grypeMatch, id, severity, at string) map[string]any {
	v := m.Vulnerability
	link, helpURI := v.ID, "https://github.com/anchore/grype"
	switch {
	case v.DataSource != "":
		link, helpURI = fmt.Sprintf("[%s](%s)", v.ID, v.DataSource), v.DataSource
	case len(v.URLs) > 0:
		link, helpURI = fmt.Sprintf("[%s](%s)", v.ID, v.URLs[0]), v.URLs[0]
	}
	help := fmt.Sprintf("Vulnerability %s\nSeverity: %s\nPackage: %s\nVersion: %s\nFix Version: %s\nType: %s\nLocation: %s\nData Namespace: %s\nLink: %s",
		v.ID, severity, m.Artifact.Name, m.Artifact.Version, grypeFixVersions(m), m.Artifact.Type, at, v.Namespace, link)
	properties := map[string]any{"security-severity": grypeSecuritySeverity(m)}
	if m.Artifact.PURL != "" {
		properties["purls"] = []string{m.Artifact.PURL}
	}
	return map[string]any{
		"id":               id,
		"name":             cmp.Or(grypeMatcherName(m), v.ID),
		"helpUri":          helpURI,
		"shortDescription": map[string]any{"text": fmt.Sprintf("%s %s vulnerability for %s package", v.ID, severity, m.Artifact.Name)},
		"fullDescription":  map[string]any{"text": grypeSubtitle(m)},
		"help":             map[string]any{"text": help},
		"properties":       properties,
	}
}

// grypeSeverity is Grype's severity word, lowercased, and "unknown" for any it does not know.
func grypeSeverity(s string) string {
	switch s = strings.ToLower(s); s {
	case "negligible", "low", "medium", "high", "critical":
		return s
	}
	return "unknown"
}

// grypeSeverityText is the word Grype's SARIF uses for a severity, which names negligible and unknown
// low.
func grypeSeverityText(s string) string {
	switch s = grypeSeverity(s); s {
	case "critical", "high", "medium":
		return s
	}
	return "low"
}

// grypeSecuritySeverity is the security-severity Grype's SARIF writes: the highest CVSS base score of
// the match's vulnerability and the ones related to it, a vendor's before the NVD's CPE match, else
// the lowest score of the band its severity names, and 0.0 for negligible or unknown.
func grypeSecuritySeverity(m grypeMatch) string {
	all := append([]grypeVulnerability{m.Vulnerability}, m.RelatedVulnerabilities...)
	score := -1.0
	for _, vendorOnly := range []bool{true, false} {
		for _, v := range all {
			if vendorOnly && v.Namespace == "nvd:cpe" {
				continue
			}
			for _, c := range v.CVSS {
				score = max(score, c.Metrics.BaseScore)
			}
		}
		if score > 0 {
			return fmt.Sprintf("%.1f", score)
		}
	}
	if s, ok := map[string]string{"critical": "9.0", "high": "7.0", "medium": "4.0", "low": "1.0"}[grypeSeverity(m.Vulnerability.Severity)]; ok {
		return s
	}
	return "0.0"
}

// grypeFixVersions are the versions that fix a match, joined by commas, where Grype's record says a
// fix exists.
func grypeFixVersions(m grypeMatch) string {
	if m.Vulnerability.Fix.State != "fixed" {
		return ""
	}
	return strings.Join(m.Vulnerability.Fix.Versions, ",")
}

// grypeSubtitle is a rule's full description: the vulnerability's description, or else what its
// versions say.
func grypeSubtitle(m grypeMatch) string {
	if d := grypeDescription(m); d != "" {
		return d
	}
	if fix := grypeFixVersions(m); fix != "" {
		return fmt.Sprintf("Version %s is affected with an available fix in versions %s", m.Artifact.Version, fix)
	}
	return fmt.Sprintf("Version %s is affected with no fixes reported yet.", m.Artifact.Version)
}

// grypeInputPath is the directory a scan was given, without a leading ./, and empty for the
// directory Grype ran in.
func grypeInputPath(doc grypeDoc) string {
	var target string
	if json.Unmarshal(doc.Source.Target, &target) != nil {
		return ""
	}
	target = strings.TrimPrefix(target, "./")
	if target == "." {
		return ""
	}
	return target
}

// grypePackagePath is where Grype's SARIF locates a match: its package's first location, rooted at
// the directory scanned, or the directory where the package has none.
func grypePackagePath(m grypeMatch, in string) string {
	if len(m.Artifact.Locations) == 0 {
		return in
	}
	loc := strings.TrimPrefix(m.Artifact.Locations[0].Path, "./")
	if path.IsAbs(loc) || in == "" {
		return loc
	}
	return in + "/" + loc
}

// grypeLineHash is the primaryLocationLineHash Grype's SARIF writes for a match in a directory: the
// package's type, name, version and location, hashed, and line 1.
func grypeLineHash(m grypeMatch, at string) string {
	sum := sha256.Sum256([]byte(m.Artifact.Type + m.Artifact.Name + m.Artifact.Version + at))
	return fmt.Sprintf("%x:1", sum)
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
	saga.ImportFormatSARIF:                "SARIF 2.1.0",
	saga.ImportFormatTrivyJSON:            "Trivy JSON",
	saga.ImportFormatGovulncheckJSON:      "govulncheck JSON",
	saga.ImportFormatGrypeJSON:            "Grype JSON",
	saga.ImportFormatOSVScannerJSON:       "OSV-Scanner JSON",
	saga.ImportFormatVeracodePipelineJSON: "Veracode Pipeline Scan JSON",
	saga.ImportFormatConverter:            "converter file",
}

// DescribeImport reads data as an import of format would, empty being SARIF, and says what it is and
// how much it holds: "SARIF 2.1.0, 3 results", "Trivy JSON, 4 findings". A file the scan would
// refuse returns the scan's error. Nothing is held to a commit or placed in a repository; DescribeBound
// does that.
func DescribeImport(data []byte, format string) (string, error) {
	return DescribeFile(data, plugin.FileTarget{Format: format})
}

// DescribeFile is DescribeImport for the import ft plans, which for a converter's file carries the
// converter the descriptor declares and what it may set, both of which decide whether the file is
// read.
func DescribeFile(data []byte, ft plugin.FileTarget) (string, error) {
	detail, _, err := describeRead(data, ft)
	return detail, err
}

// DescribeBound is DescribeFile followed by the commit the scan holds the file to, worked out by the
// scan's own rule (sarifImport.bind), with resolve turning a repository's revision into a commit:
// "SARIF 2.1.0, 1 result, commit 0123456789ab", or the scan's account of a file nothing binds,
// "…, commit not stated, ${{ GITHUB_SHA }} is not set". A file the scan would refuse as written for
// another commit returns the scan's error, so a preflight fails it in the scan's words before the
// scan runs. An error resolve returns reaches the caller wrapped, for errors.Is.
func DescribeBound(ctx context.Context, data []byte, ft plugin.FileTarget,
	resolve func(ctx context.Context, url, revision string) (string, error)) (string, error) {
	detail, read, err := describeRead(data, ft)
	if err != nil {
		return "", err
	}
	commit, err := sarifImport{resolve: resolve}.bind(ctx, ft, read.meta)
	if err != nil {
		return "", err
	}
	if strings.HasPrefix(commit, notStated) {
		// Read and held to no commit, which the row would otherwise show as a plain pass.
		return detail + ", commit " + commit + ". The scan lists it under unbound-imports", nil
	}
	return detail + ", commit " + commit, nil
}

// describeRead reads data as the import ft plans and says what it is and how much it holds.
func describeRead(data []byte, ft plugin.FileTarget) (string, importRead, error) {
	format := cmp.Or(ft.Format, saga.ImportFormatSARIF)
	ft.Format = format
	read, err := readImport(data, ft)
	if err != nil {
		return "", importRead{}, err
	}
	noun := "finding"
	if format == saga.ImportFormatSARIF {
		noun = "result"
	}
	return importFormatNames[format] + ", " + english.Count(len(read.rep.Results), noun), read, nil
}
