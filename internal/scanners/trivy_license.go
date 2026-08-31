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
// This is the first scanner here that doesn't consume SARIF. Trivy only emits license findings
// in its JSON output — its SARIF has none — so the conversion is ours.
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
      "description": "Also read LICENSE files and source headers, not only package metadata. Finds licenses no manifest declares, and is markedly slower — it reads every file rather than the dependency list."
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
// Both, because the reader's question — what am I obliged by — has no target kind in it. A license
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
// names an image on the command line. Sharing the parser is the point — a license means the same
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
// JSON rather than SARIF because Trivy's SARIF output contains no license findings at all —
// they exist only under Results[].Licenses[] in the JSON.
func trivyLicenseArgs(dir string, cfg plugin.Config) []string {
	argv := []string{"trivy", "fs", "--quiet", "--scanners", "license", "--format", "json"}
	return offlineTrivyArgs(append(licenseFullArg(argv, cfg), dir))
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
	return offlineTrivyArgs(append(licenseFullArg(argv, cfg), ref)), nil
}

// licenseFullArg adds --license-full when the descriptor asked for it.
//
// Opt-in because it changes what the scan reads rather than how it reports: package metadata is a
// dependency list, and full scanning walks every file for a LICENSE or a header. It finds licenses
// no manifest declares — which is the point — at a cost proportional to the size of the tree.
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
		Licenses []trivyLicense `json:"Licenses"`
	} `json:"Results"`
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
// findings — every dependency has one, so listing them would bury the handful that carry an
// obligation under dozens that don't. The inventory question is what an SBOM answers, and
// `config.sbom` already produces one with a license per package.
var categoryLevel = map[string]struct {
	level sarif.Level
	why   string
}{
	"forbidden": {sarif.LevelError,
		"Trivy classifies this license as forbidden: it is generally incompatible with shipping " +
			"proprietary software."},
	"restricted": {sarif.LevelWarning,
		"Copyleft. Distributing software that includes this obliges you to offer your own source " +
			"under the same terms. Running it as a hosted service usually does not trigger that — " +
			"which is why this is a warning rather than a failure by default."},
	"reciprocal": {sarif.LevelNote,
		"File-level copyleft. Changes you make to the licensed files must be shared; your own " +
			"files are unaffected."},
	"unknown": {sarif.LevelNote,
		"Trivy could not identify this license. Terms nobody has read are the ones most worth a " +
			"human look."},
}

// parseTrivyLicenses converts Trivy's license JSON into a report.
func parseTrivyLicenses(out []byte, dir string, cfg plugin.Config) (sarif.Report, error) {
	var doc trivyLicenseDoc
	if err := json.Unmarshal(out, &doc); err != nil {
		return sarif.Report{}, fmt.Errorf("decode trivy license json: %w", err)
	}
	deny, warn := stringList(cfg, denyKey), stringList(cfg, warnKey)

	report := sarif.Report{Tool: trivyLicenseScannerName, Rules: map[string]sarif.Rule{}}
	lines := newLineIndex(dir)

	for _, res := range doc.Results {
		for _, lic := range res.Licenses {
			level, why, ok := licenseLevel(lic, deny, warn)
			if !ok {
				continue
			}
			ruleID := licenseRuleID(lic.Name, lic.PkgName)
			report.Results = append(report.Results, sarif.Result{
				Tool:    trivyLicenseScannerName,
				RuleID:  ruleID,
				Level:   level,
				Message: fmt.Sprintf("%s is %s. %s", lic.PkgName, lic.Name, why),
				Location: sarif.Location{
					URI:       lic.FilePath,
					StartLine: lines.find(lic.FilePath, lic.PkgName),
				},
			})
			report.Rules[ruleID] = sarif.Rule{
				Name:             lic.Name,
				ShortDescription: fmt.Sprintf("%s is licensed %s", lic.PkgName, lic.Name),
				FullDescription:  why,
				HelpURI:          licenseHelpURI(lic),
			}
		}
	}
	return report, nil
}

// licenseLevel decides how loudly to report a license, and why. The Saga's deny/warn lists name
// SPDX ids directly and beat Trivy's category, because whether a license is acceptable depends
// on what you do with your software — something Trivy cannot know and the team always does.
func licenseLevel(lic trivyLicense, deny, warn []string) (sarif.Level, string, bool) {
	switch {
	case slices.Contains(deny, lic.Name):
		return sarif.LevelError, "Denied by this project's license policy (config.controllers.licenses.deny).", true
	case slices.Contains(warn, lic.Name):
		return sarif.LevelWarning, "Flagged by this project's license policy (config.controllers.licenses.warn).", true
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

// maxManifestBytes caps what will be read looking for a declaration. A lockfile can be large,
// and a line number is a nicety — never worth reading an unbounded file into memory for.
const maxManifestBytes = 4 << 20 // 4 MiB

// find returns the 1-based line where pkg is mentioned in the manifest, or 0 if it can't be
// determined. Zero is honest: the finding still points at the file.
func (l *lineIndex) find(relPath, pkg string) int {
	if relPath == "" || pkg == "" {
		return 0
	}
	lines, ok := l.files[relPath]
	if !ok {
		lines = readLines(filepath.Join(l.dir, relPath))
		l.files[relPath] = lines
	}
	for i, line := range lines {
		if strings.Contains(line, pkg) {
			return i + 1
		}
	}
	return 0
}

// readLines reads a manifest, returning nil on any problem — a missing line number degrades the
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
