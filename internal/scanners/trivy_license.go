package scanners

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/tooladapter"
)

// trivyLicenseScanner reports dependency licenses that carry an obligation. It serves the
// "licenses" control.
//
// This is the first scanner here that doesn't consume SARIF. Trivy only emits license findings in
// its JSON output. Its SARIF has none. So the conversion is ours.
const trivyLicenseScannerName = "trivy-license"

// trivyLicenseConfigSchema is the JSON Schema for the license scanner's Saga config
// (controllers.licenses.trivyLicense). additionalProperties:false rejects mistyped keys.
//
// The lists hold SPDX identifiers. They are policy rather than tuning: which licenses a release
// may carry is a decision about the release, so it belongs in the descriptor beside the
// component it applies to.
const trivyLicenseConfigSchema = `{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "full": {
      "type": "boolean",
      "description": "Also read LICENSE files and source headers, not only package metadata. Finds licenses no manifest declares, and is markedly slower, it reads every file rather than the dependency list."
    },
    "deny": {
      "type": "array",
      "items": { "type": "string" },
      "description": "SPDX identifiers that fail the gate, e.g. [\"AGPL-3.0-only\", \"SSPL-1.0\"]."
    },
    "warn": {
      "type": "array",
      "items": { "type": "string" },
      "description": "SPDX identifiers reported as warnings rather than failures, e.g. [\"GPL-3.0-only\"]."
    }
  }
}`

// NewTrivyLicense returns a Scanner that reports licenses carrying an obligation, in a
// component's repositories and in its images.
//
// Both, because the reader's question, what am I obliged by. Has no target kind in it. A license
// obligation inside an image was invisible while this read repositories only, and silently so: the
// control ran, reported covered, and the surface it had not examined had no name in the output. A
// third-party image is exactly where the source repository is not declared, because the team does
// not build it, so the gap landed hardest where the question was least answerable by hand.
//
// One scanner over two kinds rather than two scanners, so a component's license policy cannot
// differ by where the code happens to live, and `doctor` lists one tool.
func NewTrivyLicense() plugin.Scanner {
	info := plugin.ScannerInfo{
		Name:     trivyLicenseScannerName,
		Origin:   "aquasecurity",
		Data:     trivyData,
		Binary:   "trivy",
		Controls: []string{"licenses"},
		TargetKinds: []plugin.TargetKind{
			plugin.TargetRepository, plugin.TargetImage,
		},
		ConfigSchema: json.RawMessage(trivyLicenseConfigSchema),
	}

	repo := newRepoScannerWithParser(info, trivyLicenseArgs, parseTrivyLicenses)
	repo.cacheVersion = sharedTrivyVersion.cacheVersion
	repo.run = retryingRunInDir("trivy", repo.run)
	repo.accounts = true

	image := tooladapter.New(tooladapter.Config{
		Name:         info.Name,
		Origin:       info.Origin,
		Binary:       info.Binary,
		Controls:     info.Controls,
		TargetKinds:  []plugin.TargetKind{plugin.TargetImage},
		ConfigSchema: info.ConfigSchema,
		Argv:         trivyLicenseImageArgv,
		Run:          retryingRun("trivy", execArgv),
		Parse: func(out []byte, _ plugin.Target, cfg plugin.Config) (sarif.Report, error) {
			// No directory: an image has no checkout to resolve a line number against, and Trivy
			// reports an OS package's license without a file path at all.
			return parseTrivyLicenses(out, "", cfg)
		},
		CacheVersion: sharedTrivyVersion.cacheVersion,
		Prewarm:      sharedTrivyDB.warm,
		Refine:       imageRefLocations,
	})

	return licenseScanner{info: info, repo: repo, image: image}
}

// licenseScanner runs the right Trivy mode for the target it is handed.
//
// A dispatcher rather than a scanner that branches inside Scan, because the two modes genuinely
// differ in everything but the parser: one checks out a tree and runs `trivy fs` in it, the other
// names an image on the command line. Sharing the parser is the point. A license means the same
// thing wherever it was found, and two parsers would eventually disagree about that.
type licenseScanner struct {
	info  plugin.ScannerInfo
	repo  plugin.Scanner
	image plugin.Scanner
}

// Info describes the scanner.
func (s licenseScanner) Info() plugin.ScannerInfo { return s.info }

// Scan sends the target to whichever mode reads it.
func (s licenseScanner) Scan(ctx context.Context, target plugin.Target, cfg plugin.Config) (sarif.Report, error) {
	switch target.(type) {
	case plugin.ImageTarget:
		return s.image.Scan(ctx, target, cfg)
	case plugin.RepositoryTarget:
		return s.repo.Scan(ctx, target, cfg)
	default:
		return sarif.Report{}, fmt.Errorf("%s: unsupported target %T (want repository or image)",
			s.info.Name, target)
	}
}

// CacheVersion folds Trivy's version into the cache key, whichever mode ran.
func (s licenseScanner) CacheVersion(ctx context.Context) string {
	return sharedTrivyVersion.cacheVersion(ctx)
}

// Prewarm downloads Trivy's database once before the fan-out. Image mode needs it; repository mode
// is unharmed by it, and asking the question twice is what a thundering herd is made of.
func (s licenseScanner) Prewarm(ctx context.Context) error { return sharedTrivyDB.warm(ctx) }

// trivyLicenseArgs builds `trivy fs --quiet --scanners license --format json <dir>`.
//
// JSON rather than SARIF because Trivy's SARIF output contains no license findings at all. They
// exist only under Results[].Licenses[] in the JSON.
func trivyLicenseArgs(dir string, cfg plugin.Config) []string {
	argv := []string{"trivy", "fs", "--quiet", "--scanners", "license", "--format", "json"}
	return offlineTrivyArgs(append(showSuppressedArgs(licenseFullArg(argv, cfg)), dir))
}

// trivyLicenseImageArgv builds `trivy image --quiet --scanners license --format json <ref>`.
func trivyLicenseImageArgv(target plugin.Target, cfg plugin.Config) ([]string, error) {
	img, ok := target.(plugin.ImageTarget)
	if !ok {
		return nil, fmt.Errorf("%s: unsupported target %T (want image)", trivyLicenseScannerName, target)
	}
	ref := img.PinnedRef()
	if ref == "" {
		return nil, errors.New(trivyLicenseScannerName + ": image target has neither ref nor digest")
	}
	argv := []string{"trivy", "image", "--quiet", "--scanners", "license", "--format", "json"}
	return offlineTrivyArgs(append(showSuppressedArgs(licenseFullArg(argv, cfg)), ref)), nil
}

// licenseFullArg adds --license-full when the descriptor asked for it.
//
// Opt-in because it changes what the scan reads rather than how it reports: package metadata is a
// dependency list, and full scanning walks every file for a LICENSE or a header. It finds licenses
// no manifest declares. Which is the point. At a cost proportional to the size of the tree.
func licenseFullArg(argv []string, cfg plugin.Config) []string {
	if full, _ := cfg["full"].(bool); full {
		return append(argv, "--license-full")
	}
	return argv
}

// Config keys carrying the Saga's license policy into the scanner.
const (
	denyKey = "deny"
	warnKey = "warn"
)

// trivyLicenseDoc is the slice of Trivy's JSON this scanner reads.
type trivyLicenseDoc struct {
	Results []struct {
		// Target, Class and Packages name the file a set of packages was read from, which Trivy
		// reports beside the licenses it found in them. A license found in a file rather than in
		// package metadata arrives in a set of its own, class license-file, with no package name.
		Target   string         `json:"Target"`
		Class    string         `json:"Class"`
		Packages []trivyPackage `json:"Packages"`
		Licenses []trivyLicense `json:"Licenses"`
		// Modified is what Trivy set aside under a rule of its own, reported only when it runs with
		// --show-suppressed. Read the same way as for vulnerabilities (see trivyModified).
		Modified []trivyLicenseModified `json:"ExperimentalModifiedFindings"`
	} `json:"Results"`
}

// trivyLicenseModified is one entry of that section for a license. Its fields mean what they
// mean in trivyModified, whose finding is a vulnerability rather than a license.
type trivyLicenseModified struct {
	Type      string       `json:"Type"`
	Status    string       `json:"Status"`
	Statement string       `json:"Statement"`
	Source    string       `json:"Source"`
	Finding   trivyLicense `json:"Finding"`
}

type trivyLicense struct {
	Severity string `json:"Severity"`
	Category string `json:"Category"`
	PkgName  string `json:"PkgName"`
	FilePath string `json:"FilePath"`
	Name     string `json:"Name"`
	Link     string `json:"Link"`
}

// categoryLevel maps Trivy's license categories to a SARIF level, and to the sentence that
// explains why anyone should care.
//
// A category that isn't here is not reported at all. Permissive licenses are *inventory*, not
// findings. Every dependency has one, so listing them would bury the handful that carry an
// obligation under dozens that don't. The inventory question is what an SBOM answers, and
// `config.sbom` already produces one with a license per package.
//
// Restricted is a warning rather than an error because copyleft attaches to distribution, and a
// component run as a hosted service is usually not distributed. The message states that fact; the
// level is the decision taken from it.
var categoryLevel = map[string]struct {
	level sarif.Level
	why   string
}{
	"forbidden": {sarif.LevelError,
		"Trivy classifies this license as forbidden: it is generally incompatible with shipping " +
			"proprietary software."},
	"restricted": {sarif.LevelWarning,
		"Copyleft. Distributing software that includes this obliges you to offer your own source " +
			"under the same terms. Running it as a hosted service usually does not."},
	"reciprocal": {sarif.LevelNote,
		"File-level copyleft. Changes you make to the licensed files must be shared; your own " +
			"files are unaffected."},
	"unknown": {sarif.LevelNote,
		"Trivy could not identify this license. Read its terms before shipping it."},
}

// parseTrivyLicenses converts Trivy's license JSON into a report.
func parseTrivyLicenses(out []byte, dir string, cfg plugin.Config) (sarif.Report, error) {
	var doc trivyLicenseDoc
	if err := json.Unmarshal(out, &doc); err != nil {
		return sarif.Report{}, fmt.Errorf("decode trivy license json: %w", err)
	}
	deny, warn := stringList(cfg, denyKey), stringList(cfg, warnKey)

	report := sarif.Report{Tool: trivyLicenseScannerName, Rules: map[string]sarif.Rule{}}
	lineOf := doc.lineFinder(dir)

	for _, res := range doc.Results {
		if in, ok := trivyInput(dir, res.Class, res.Target, len(res.Packages)); ok {
			report.Inputs = append(report.Inputs, in)
		}
		for _, lic := range res.Licenses {
			level, why, ok := licenseLevel(lic, deny, warn)
			if !ok {
				continue
			}
			report.Results = append(report.Results, licenseResult(lic, level, why, lineOf))
			report.Rules[licenseRuleID(lic.Name, lic.PkgName)] = licenseRule(lic)
		}
		for _, m := range res.Modified {
			if m.Status != "ignored" || m.Type != "license" || m.Finding.Name == "" {
				continue
			}
			// Held to the same policy as a license Trivy reported. An excluded permissive license is
			// one this scanner would never have raised, and marking it suppressed would record an
			// acceptance of something that was never a finding.
			level, why, ok := licenseLevel(m.Finding, deny, warn)
			if !ok {
				continue
			}
			found := licenseResult(m.Finding, level, why, lineOf)
			found.Suppression = &sarif.Suppression{
				Kind:          "external",
				Origin:        sarif.OriginScanner,
				Justification: m.Statement,
				Source:        m.Source,
			}
			report.Results = append(report.Results, found)
			report.Rules[found.RuleID] = licenseRule(m.Finding)
		}
	}
	return report, nil
}

// licenseResult builds one license finding.
func licenseResult(lic trivyLicense, level sarif.Level, why string, lineOf func(trivyLicense) int) sarif.Result {
	return sarif.Result{
		Tool:     trivyLicenseScannerName,
		RuleID:   licenseRuleID(lic.Name, lic.PkgName),
		Level:    level,
		Message:  fmt.Sprintf("%s is %s. %s", licenseSubject(lic), lic.Name, why),
		Location: sarif.Location{URI: lic.FilePath, StartLine: lineOf(lic)},
	}
}

// licenseSubject is what a license finding is about: the package, or for a license Trivy found in
// a file (a LICENSE, a source header) rather than in package metadata, the file. Trivy reports
// those with no package name, and a message opening on a blank reads as a defect in the report.
func licenseSubject(lic trivyLicense) string {
	switch {
	case lic.PkgName != "":
		return lic.PkgName
	case lic.FilePath != "":
		return lic.FilePath
	}
	return "A file"
}

// licenseRule describes a license rule. A file-level rule, `license/<spdx>`, is shared by every
// file carrying that license, so its description names none of them; the finding's message does.
func licenseRule(lic trivyLicense) sarif.Rule {
	short := fmt.Sprintf("%s is licensed %s", lic.PkgName, lic.Name)
	if lic.PkgName == "" {
		short = "A file is licensed " + lic.Name
	}
	return sarif.Rule{
		Name:             lic.Name,
		ShortDescription: short,
		FullDescription:  categoryLevel[strings.ToLower(lic.Category)].why,
		HelpURI:          licenseHelpURI(lic),
	}
}

// lineFinder returns the line a license finding's package is declared on.
//
// Trivy reports a license with its package's name and manifest and no line. The line comes from
// the package list Trivy reports for the same manifest, where its parser records each package's
// own entry: in a package-lock.json that is `node_modules/<name>`, where the first mention of the
// name is the root's dependency list. Where the parser records no line, the manifest is searched,
// with the package's version to tell its entry from a reference to it.
func (d trivyLicenseDoc) lineFinder(dir string) func(trivyLicense) int {
	type key struct{ file, name string }
	packages := map[key]trivyPackage{}
	for _, res := range d.Results {
		for _, p := range res.Packages {
			k := key{res.Target, p.Name}
			if _, seen := packages[k]; !seen {
				packages[k] = p
			}
		}
	}
	lines := newLineIndex(dir)
	return func(lic trivyLicense) int {
		if lic.PkgName == "" {
			return 0 // a license in a file belongs to the whole file
		}
		p := packages[key{lic.FilePath, lic.PkgName}]
		if n := p.line(); n > 0 {
			return n
		}
		return lines.find(lic.FilePath, lic.PkgName, p.Version)
	}
}

// licenseLevel decides how loudly to report a license, and why. The Saga's deny/warn lists name
// SPDX ids directly and beat Trivy's category, because whether a license is acceptable depends on
// what you do with your software. Something Trivy cannot know and the team always does.
func licenseLevel(lic trivyLicense, deny, warn []string) (sarif.Level, string, bool) {
	switch {
	case slices.Contains(deny, lic.Name):
		return sarif.LevelError, "Denied by this project's license policy (config.controls.licenses.deny).", true
	case slices.Contains(warn, lic.Name):
		return sarif.LevelWarning, "Flagged by this project's license policy (config.controls.licenses.warn).", true
	}
	meta, ok := categoryLevel[strings.ToLower(lic.Category)]
	if !ok {
		return "", "", false // permissive, notice, unencumbered: inventory, not a finding
	}
	return meta.level, meta.why, true
}

// licenseRuleID names a finding as `license/<spdx>/<package>`.
//
// The order matters, and it is a user-facing decision rather than a cosmetic one: this string is
// what goes in a config.exclude rule. License first means "accept this license anywhere" is
// `license/MPL-2.0/*`, which is the common exemption; the full id stays available for "accept it
// in this one dependency". Package names contain slashes, which is why exclusion patterns match
// `*` across separators.
func licenseRuleID(spdx, pkg string) string {
	if pkg == "" {
		return "license/" + spdx
	}
	return "license/" + spdx + "/" + pkg
}

// licenseHelpURI points at the license's own text. Trivy sometimes supplies a link; SPDX is the
// stable fallback, and an id with a space or slash isn't an SPDX id (it may be an expression
// like "MIT OR Apache-2.0"), so no link is better than a broken one.
func licenseHelpURI(lic trivyLicense) string {
	if lic.Link != "" {
		return lic.Link
	}
	if lic.Name == "" || strings.ContainsAny(lic.Name, " /()") {
		return ""
	}
	return "https://spdx.org/licenses/" + lic.Name + ".html"
}

// stringList reads a []string out of a plugin.Config value, tolerating the []any that YAML
// decoding produces.
func stringList(cfg plugin.Config, key string) []string {
	if cfg == nil {
		return nil
	}
	switch v := cfg[key].(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// lineIndex finds the line a dependency is declared on, lazily and once per manifest.
//
// Trivy reports licenses against a manifest with no line number, unlike its vulnerability
// findings which arrive with one. Without this every license in a project lands at the top of
// go.mod in a pile, which is the same failure as an image finding reported at "library/python:1":
// technically a location, useless in an editor.
type lineIndex struct {
	dir   string
	files map[string][]string
}

func newLineIndex(dir string) *lineIndex {
	return &lineIndex{dir: dir, files: map[string][]string{}}
}

// maxManifestBytes caps what will be read looking for a declaration. A lockfile can be large, and
// a line number is a nicety, never worth reading an unbounded file into memory for.
const maxManifestBytes = 4 << 20 // 4 MiB

// find returns the 1-based line that declares pkg in the manifest, or 0 if it can't be
// determined. Zero is honest: the finding still points at the file.
//
// A line counts only where the name stands as a whole name, and never in a comment: a lockfile
// names a package in the comments explaining why something else is there ("# via flask"), and in
// the dependency lists of the packages that need it, before the package's own entry. Where the
// version is known, candidates are ranked by how much the line looks like the entry itself:
//
//  1. the name followed directly by the version: `minimist@1.2.5:`, `flask==0.12.2`,
//     `rack (2.2.3)`;
//  2. the name with the version on one of the next two lines: `name = "flask"` above
//     `version = "0.12.2"` in uv.lock, poetry.lock, Cargo.lock and composer.lock;
//  3. the name anywhere.
//
// A reference that happens to carry the version, `requires-dist = [{ name = "flask", specifier =
// "==0.12.2" }]`, has words between the two and ranks with the third.
func (l *lineIndex) find(relPath, pkg, version string) int {
	if relPath == "" || pkg == "" {
		return 0
	}
	lines, ok := l.files[relPath]
	if !ok {
		lines = readLines(filepath.Join(l.dir, relPath))
		l.files[relPath] = lines
	}
	var best [3]int
	for i, line := range lines {
		if isCommentLine(line) || !containsName(line, pkg) {
			continue
		}
		rank := 2
		switch {
		case version == "":
			return i + 1
		case versionFollowsName(line, pkg, version):
			rank = 0
		case versionBelow(lines, i, version):
			rank = 1
		}
		if best[rank] == 0 {
			best[rank] = i + 1
		}
	}
	for _, n := range best {
		if n > 0 {
			return n
		}
	}
	return 0
}

// versionFollowsName reports whether version comes right after a whole-name occurrence of name in
// line, with only separators between them.
func versionFollowsName(line, name, version string) bool {
	lower, want := strings.ToLower(line), strings.ToLower(name)
	for from := 0; ; {
		i := strings.Index(lower[from:], want)
		if i < 0 {
			return false
		}
		start, end := from+i, from+i+len(want)
		from = start + 1
		if (start > 0 && isNameByte(lower[start-1])) || (end < len(lower) && isNameByte(lower[end])) {
			continue
		}
		rest := strings.TrimLeft(lower[end:], "@=:~^<>!( \t\"'v")
		if strings.HasPrefix(rest, strings.ToLower(version)) {
			return true
		}
	}
}

// versionBelow reports whether one of the two lines after lines[i] carries version, the shape of an
// entry written one field per line.
func versionBelow(lines []string, i int, version string) bool {
	for j := i + 1; j <= i+2 && j < len(lines); j++ {
		if strings.Contains(lines[j], version) {
			return true
		}
	}
	return false
}

// isCommentLine reports whether a manifest line is a comment in any of the syntaxes lockfiles use.
func isCommentLine(line string) bool {
	t := strings.TrimSpace(line)
	return strings.HasPrefix(t, "#") || strings.HasPrefix(t, "//")
}

// containsName reports whether name appears in line as a whole package name, case-insensitively:
// `rack` in `rack (2.2.3)` and not in `rack-test`, `Flask==0.12.2` for `flask`.
func containsName(line, name string) bool {
	lower, want := strings.ToLower(line), strings.ToLower(name)
	for from := 0; ; {
		i := strings.Index(lower[from:], want)
		if i < 0 {
			return false
		}
		start, end := from+i, from+i+len(want)
		if (start == 0 || !isNameByte(lower[start-1])) && (end == len(lower) || !isNameByte(lower[end])) {
			return true
		}
		from = start + 1
	}
}

// isNameByte reports whether b can continue a package name, so that a match ending beside one is a
// longer name rather than this one.
func isNameByte(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-' || b == '_' || b == '.'
}

// readLines reads a manifest, returning nil on any problem, a missing line number degrades the
// finding, it doesn't invalidate it.
func readLines(path string) []string {
	f, err := os.Open(path) // #nosec G304 -- a manifest inside the checkout Draugr just made
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	if fi, err := f.Stat(); err != nil || fi.Size() > maxManifestBytes {
		return nil
	}
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if sc.Err() != nil {
		return nil
	}
	return lines
}
