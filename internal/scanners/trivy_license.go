package scanners

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// trivyLicenseScanner reports dependency licences that carry an obligation. It serves the
// "licenses" control.
//
// This is the first scanner here that doesn't consume SARIF. Trivy only emits licence findings
// in its JSON output — its SARIF has none — so the conversion is ours.
const trivyLicenseScannerName = "trivy-license"

// NewTrivyLicense returns a Scanner that reports dependency licences carrying an obligation.
func NewTrivyLicense() plugin.Scanner {
	s := newRepoScannerWithParser(
		plugin.ScannerInfo{
			Name:        trivyLicenseScannerName,
			Origin:      "aquasecurity",
			Binary:      "trivy",
			Controls:    []string{"licenses"},
			TargetKinds: []plugin.TargetKind{plugin.TargetRepository},
		},
		trivyLicenseArgs,
		parseTrivyLicenses,
	)
	s.cacheVersion = sharedTrivyVersion.cacheVersion
	return s
}

// trivyLicenseArgs builds `trivy fs --quiet --scanners license --format json <dir>`.
//
// JSON rather than SARIF because Trivy's SARIF output contains no licence findings at all —
// they exist only under Results[].Licenses[] in the JSON.
func trivyLicenseArgs(dir string, _ plugin.Config) []string {
	return []string{"trivy", "fs", "--quiet", "--scanners", "license", "--format", "json", dir}
}

// Config keys carrying the Saga's licence policy into the scanner.
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

// categoryLevel maps Trivy's licence categories to a SARIF level, and to the sentence that
// explains why anyone should care.
//
// A category that isn't here is not reported at all. Permissive licences are *inventory*, not
// findings — every dependency has one, so listing them would bury the handful that carry an
// obligation under dozens that don't. The inventory question is what an SBOM answers, and
// `config.sbom` already produces one with a licence per package.
var categoryLevel = map[string]struct {
	level sarif.Level
	why   string
}{
	"forbidden": {sarif.LevelError,
		"Trivy classifies this licence as forbidden: it is generally incompatible with shipping " +
			"proprietary software."},
	"restricted": {sarif.LevelWarning,
		"Copyleft. Distributing software that includes this obliges you to offer your own source " +
			"under the same terms. Running it as a hosted service usually does not trigger that — " +
			"which is why this is a warning rather than a failure by default."},
	"reciprocal": {sarif.LevelNote,
		"File-level copyleft. Changes you make to the licensed files must be shared; your own " +
			"files are unaffected."},
	"unknown": {sarif.LevelNote,
		"Trivy could not identify this licence. Terms nobody has read are the ones most worth a " +
			"human look."},
}

// parseTrivyLicenses converts Trivy's licence JSON into a report.
func parseTrivyLicenses(out []byte, dir string, cfg plugin.Config) (sarif.Report, error) {
	var doc trivyLicenseDoc
	if err := json.Unmarshal(out, &doc); err != nil {
		return sarif.Report{}, fmt.Errorf("decode trivy licence json: %w", err)
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

// licenseLevel decides how loudly to report a licence, and why. The Saga's deny/warn lists name
// SPDX ids directly and beat Trivy's category, because whether a licence is acceptable depends
// on what you do with your software — something Trivy cannot know and the team always does.
func licenseLevel(lic trivyLicense, deny, warn []string) (sarif.Level, string, bool) {
	switch {
	case slices.Contains(deny, lic.Name):
		return sarif.LevelError, "Denied by this project's licence policy (config.controllers.licenses.deny).", true
	case slices.Contains(warn, lic.Name):
		return sarif.LevelWarning, "Flagged by this project's licence policy (config.controllers.licenses.warn).", true
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
// what goes in a config.exclude rule. Licence first means "accept this licence anywhere" is
// `license/MPL-2.0/*`, which is the common exemption; the full id stays available for "accept it
// in this one dependency". Package names contain slashes, which is why exclusion patterns match
// `*` across separators.
func licenseRuleID(spdx, pkg string) string {
	if pkg == "" {
		return "license/" + spdx
	}
	return "license/" + spdx + "/" + pkg
}

// licenseHelpURI points at the licence's own text. Trivy sometimes supplies a link; SPDX is the
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
// Trivy reports licences against a manifest with no line number, unlike its vulnerability
// findings which arrive with one. Without this every licence in a project lands at the top of
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
	f, err := os.Open(path) //nolint:gosec // a manifest inside the checkout Draugr just made
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
