package scanners

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/draugr-dev/draugr/internal/netpolicy"
	"github.com/draugr-dev/draugr/internal/toolexec"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/tooladapter"
)

// grypeConfigSchema is the JSON Schema for the two Grype scanners' Saga config
// (controllers.images.grype and controllers.sca.grypeFs). additionalProperties:false rejects
// mistyped keys.
//
// Grype's filtering flags are deliberately absent. `--only-fixed`, `--ignore-states`, `--exclude`
// and `--fail-on` all drop findings inside the tool, where Draugr cannot mark them suppressed or
// record who accepted them. `exclusions` in the Saga does that and keeps the evidence; the gate
// thresholds decide what fails.
//
// The database location is absent for a different reason: Grype takes it from the environment
// rather than a flag, so it is documented as `GRYPE_DB_UPDATE_URL` in the air-gapped guide. An
// option here would be a setting Draugr accepted and could not pass on.
const grypeConfigSchema = `{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "byCve": {
      "type": "boolean",
      "default": true,
      "description": "Report a finding under its CVE rather than the advisory ID the source used, where a CVE exists. On by default. Turn it off to see the advisory identifier Grype matched on."
    }
  }
}`

// NewGrype returns a Scanner that runs Anchore Grype against container images and returns its
// native SARIF output. It serves the "images" control, alongside Trivy rather than instead of it.
func NewGrype() plugin.Scanner {
	return tooladapter.New(tooladapter.Config{
		Name:         "grype",
		Origin:       "anchore",
		Data:         grypeData,
		Binary:       "grype",
		Controls:     []string{"images"},
		TargetKinds:  []plugin.TargetKind{plugin.TargetImage},
		ConfigSchema: json.RawMessage(grypeConfigSchema),
		Argv:         grypeArgv,
		Run: func(ctx context.Context, argv []string) ([]byte, error) {
			return runGrypeRecordingExclusions(func(a []string) ([]byte, error) { return grypeRun(ctx, a) }, "", argv)
		},
		Parse:        parseGrypeImageSARIF,
		CacheVersion: sharedGrypeVersion.cacheVersion,
		Prewarm:      sharedGrypeDB.warm,
		DataState:    sharedGrypeData.database,
		Refine:       imageRefLocations,
	})
}

// NewGrypeFS returns a Scanner that runs Grype over a checked-out repository to find dependency
// vulnerabilities (SCA). It serves the "sca" control.
func NewGrypeFS() plugin.Scanner {
	s := newRepoScannerWithParser(
		plugin.ScannerInfo{
			Name:         "grype-fs",
			Origin:       "anchore",
			Data:         grypeData,
			Binary:       "grype",
			Controls:     []string{"sca"},
			TargetKinds:  []plugin.TargetKind{plugin.TargetRepository},
			ConfigSchema: json.RawMessage(grypeConfigSchema),
		},
		grypeFSArgs,
		parseGrypeRepoSARIF,
	)
	s.cacheVersion = sharedGrypeVersion.cacheVersion
	s.prewarm = sharedGrypeDB.warm
	s.dataState = sharedGrypeData.database
	s.run = func(ctx context.Context, dir string, argv []string) ([]byte, error) {
		return runGrypeRecordingExclusions(func(a []string) ([]byte, error) { return grypeRunInDir(ctx, dir, a) }, dir, argv)
	}
	s.inventory = &inventoryOutput{args: grypeInventoryArgs, parse: parseGrypeInventory}
	return s
}

// grypeInventoryArgs has Grype write the packages it read, as CycloneDX, beside its SARIF. The
// SARIF names a file only where a package in it is vulnerable, so it cannot say what was read.
func grypeInventoryArgs(path string) []string {
	return []string{"-o", "cyclonedx-json=" + path}
}

// parseGrypeInventory counts the packages Grype read from each file.
//
// Syft records where it found a package as properties numbered from zero, rooted at the scanned
// directory as the SARIF paths are. A component of type file is a file Syft cataloged, not a
// package read from one, and is not counted.
func parseGrypeInventory(out []byte, dir string) ([]sarif.Input, error) {
	var doc struct {
		Components []struct {
			Type       string `json:"type"`
			Properties []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"properties"`
		} `json:"components"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		return nil, err
	}
	counts := map[string]int{}
	for _, c := range doc.Components {
		if c.Type == "file" {
			continue
		}
		for _, p := range c.Properties {
			if strings.HasPrefix(p.Name, "syft:location:") && strings.HasSuffix(p.Name, ":path") && p.Value != "" {
				counts[grypeRepoPath(dir, p.Value)]++
			}
		}
	}
	inputs := make([]sarif.Input, 0, len(counts))
	for path, n := range counts {
		inputs = append(inputs, sarif.Input{Path: path, Packages: n})
	}
	slices.SortFunc(inputs, func(a, b sarif.Input) int { return strings.Compare(a.Path, b.Path) })
	return inputs, nil
}

// grypeFSArgs builds `grype dir:<dir> -o sarif` for a checked-out repository.
//
// No -q. It silences Grype's log, which is the only place Grype says why a scan failed, and a scan
// error that holds nothing but an exit status gives the reader nothing to act on. The SARIF goes to
// stdout either way and the log to stderr, where toolexec finds the line that ended the run and
// quotes it in the error.
func grypeFSArgs(dir string, cfg plugin.Config) []string {
	return grypeOptions([]string{"grype", "dir:" + dir, "-o", "sarif"}, cfg)
}

// grypeArgv builds `grype registry:<ref> -o sarif` for an image target, without -q for the reason
// grypeFSArgs gives.
//
// The `registry:` scheme, not a bare reference: bare, Grype tries a local Docker daemon first and
// only then the registry. On a CI runner there is no daemon, so that is a failed connection before
// every scan; where there *is* one, it silently scans whatever the daemon happens to have cached
// under that tag rather than what the registry serves now, and a scan of the wrong bytes is worse
// than a slow one. Draugr resolves images to a digest where it can, and a digest is meaningless to
// a daemon that never pulled it.
func grypeArgv(target plugin.Target, cfg plugin.Config) ([]string, error) {
	img, ok := target.(plugin.ImageTarget)
	if !ok {
		return nil, fmt.Errorf("grype: unsupported target %T (want image)", target)
	}
	ref := img.PinnedRef()
	if ref == "" {
		return nil, errors.New("grype: image target has neither ref nor digest")
	}
	return grypeOptions([]string{"grype", "registry:" + ref, "-o", "sarif"}, cfg), nil
}

// grypeOptions appends the descriptor's options to a Grype command line. Shared by the image and
// repository scanners: the option means the same thing to both.
//
// --by-cve unless the descriptor turns it off, which is a departure from Grype's own default and
// is deliberate. Grype reports a language-ecosystem finding under the advisory that described it,
// GHSA-8q59-q68h-6hv4, where Trivy reports the CVE for the same flaw. Left alone, one
// vulnerability arrives under two identities depending on which scanner saw it, so it counts
// twice, and an exclusion someone wrote against the CVE keeps working right up until the day a
// second scanner starts reporting it. A qualification tool that normalizes everything else to one
// schema should not stop at the identifier.
func grypeOptions(argv []string, cfg plugin.Config) []string {
	if byCVE, ok := cfg["byCve"].(bool); ok && !byCVE {
		return argv
	}
	return append(argv, "--by-cve")
}

// grypeEnv is the environment Grype runs with, layered over the parent's.
//
// Always GRYPE_CHECK_FOR_APP_UPDATE=false. A scan otherwise asks toolbox-data.anchore.io whether a
// newer Grype exists, once per job and offline too, and logs the failed lookup at ERROR. The
// version is Draugr's pin, so the answer changes nothing, and with the log on stderr that ERROR
// line would be the one quoted when the scan fails for some other reason.
//
// Offline, GRYPE_DB_AUTO_UPDATE=false as well. Skipping the prewarm is not enough on its own: Grype
// checks for a newer database when it starts a scan too, so without this an offline run still
// reaches out, once per job. With it, Grype uses its local database and says plainly when there
// isn't one, a better message than anything Draugr could write on its behalf.
func grypeEnv() []string {
	env := []string{"GRYPE_CHECK_FOR_APP_UPDATE=false"}
	if netpolicy.Offline() {
		env = append(env, "GRYPE_DB_AUTO_UPDATE=false")
	}
	return env
}

// grypeRun and grypeRunInDir run one Grype scan, once the shared database has been read (see
// grypeDBWarmer.open). They are vars so a test can substitute the exec without arranging binaries
// on PATH.
var grypeRun = func(ctx context.Context, argv []string) ([]byte, error) {
	sharedGrypeDB.open(ctx)
	return toolexec.RunWithEnv(ctx, "", argv, grypeEnv())
}

var grypeRunInDir = func(ctx context.Context, dir string, argv []string) ([]byte, error) {
	sharedGrypeDB.open(ctx)
	return toolexec.RunWithEnv(ctx, dir, argv, grypeEnv())
}

// execGrype runs a Grype command that is not a scan, with the same environment a scan has.
func execGrype(ctx context.Context, argv []string) ([]byte, error) {
	return toolexec.RunWithEnv(ctx, "", argv, grypeEnv())
}

// parseGrypeRepoSARIF decodes Grype's SARIF and makes its paths repo-relative.
//
// Grype reports a directory finding at "/app/requirements.txt", rooted at the directory it
// scanned, which is not the same as rooted at the filesystem. The leading slash survives the
// checkout-relative rewrite every repository scanner does, because that rewrite correctly leaves
// an absolute path outside the checkout alone, and this path only looks like one.
//
// What it costs if left: the finding is one path away from the file it describes, so GitHub code
// scanning anchors it nowhere, and the same dependency reported by Trivy and by Grype arrives
// under two different paths and cannot be recognized as the same thing.
func parseGrypeRepoSARIF(out []byte, dir string, _ plugin.Config) (sarif.Report, error) {
	report, err := parseGrypeSARIF(out)
	if err != nil {
		return sarif.Report{}, err
	}
	for i := range report.Results {
		report.Results[i].Location.URI = grypeRepoPath(dir, report.Results[i].Location.URI)
	}
	return report, nil
}

// parseGrypeImageSARIF decodes Grype's SARIF for an image scan. The location is left as Grype
// wrote it, because imageRefLocations replaces it with the image reference afterwards.
func parseGrypeImageSARIF(out []byte, _ plugin.Target, _ plugin.Config) (sarif.Report, error) {
	return parseGrypeSARIF(out)
}

// parseGrypeSARIF decodes Grype's SARIF and gives each result its package. Shared by the image and
// repository scanners, which read the same document.
//
// A result normally arrives carrying the package of its own match, which withGrypeMatchPackages
// read from Grype's JSON report. One that does not falls back to its rule's help text, but only
// where that text is known to describe it: the rule has no other result, or the result's message
// states the version the rule does. Grype writes one rule per advisory and package name, so a rule
// with several results describes one of them, and any other result given its package would carry
// another match's version, fixed version and package URL. Such a result carries no package. It is
// then neither correlated with another scanner's copy nor matched by a VEX statement, which is the
// honest outcome for a finding whose package Draugr cannot name, and better than naming the wrong
// one.
func parseGrypeSARIF(out []byte) (sarif.Report, error) {
	report, err := sarif.FromSARIF(out)
	if err != nil {
		return sarif.Report{}, err
	}
	packages := grypePackages(out)
	perRule := map[string]int{}
	for _, r := range report.Results {
		perRule[r.RuleID]++
	}
	for i := range report.Results {
		r := &report.Results[i]
		if r.Package != nil {
			continue
		}
		pkg, ok := packages[r.RuleID]
		if !ok {
			continue
		}
		if _, version, _ := grypeMessagePackage(r.Message); perRule[r.RuleID] == 1 || version == pkg.Version {
			p := pkg
			r.Package = &p
		}
	}
	return report, nil
}

// grypeResultMessage matches the sentence Grype writes as each result's message, naming the
// package's type and the installed version that one match is about: "A medium vulnerability in npm
// package: minimatch, version 9.0.1 was found at: /pnpm-lock.yaml".
var grypeResultMessage = regexp.MustCompile(`in (\S+) package: .+, version (\S+) was found`)

// grypeMessagePackage reads the package type and version a Grype result's message states, and false
// for a message that states neither.
func grypeMessagePackage(message string) (kind, version string, ok bool) {
	m := grypeResultMessage.FindStringSubmatch(message)
	if m == nil {
		return "", "", false
	}
	return m[1], m[2], true
}

// grypeMatchPackage is the package one match of Grype's JSON report is about, in the terms the rule
// help text uses: the fixing versions joined by commas, the artifact type as the ecosystem.
func grypeMatchPackage(m grypeMatch) sarif.Package {
	return sarif.Package{
		Name:         m.Artifact.Name,
		Version:      m.Artifact.Version,
		FixedVersion: strings.Join(m.Vulnerability.Fix.Versions, ","),
		Ecosystem:    m.Artifact.Type,
		PURL:         m.Artifact.PURL,
	}
}

// withGrypeMatchPackages writes onto each result of Grype's SARIF the package of the match it
// reports, read from the JSON report the same invocation wrote, as the result property the SARIF
// reader takes a package from. SARIF with no result to stamp is returned unchanged.
//
// Paired with Grype's own SARIF result rather than rebuilt from the JSON, as an ignored match is.
// The SARIF stays the source of everything else a finding carries, its message, level, score,
// location and fingerprint, as Grype wrote them, so the change is confined to the one fact the
// SARIF states per rule instead of per result. Grype writes one rule per advisory and package name,
// so every match of one advisory in one package shares a rule, and the version, fixed version and
// package URL in its help text describe only the first.
func withGrypeMatchPackages(sarifOut []byte, matches []grypeMatch) ([]byte, error) {
	if len(matches) == 0 {
		return sarifOut, nil
	}
	dec := json.NewDecoder(bytes.NewReader(sarifOut))
	dec.UseNumber()
	var log map[string]any
	if err := dec.Decode(&log); err != nil {
		return nil, fmt.Errorf("read its SARIF: %w", err)
	}
	index := newGrypeMatchIndex(matches)
	stamped := 0
	runs, _ := log["runs"].([]any)
	for _, run := range runs {
		r, _ := run.(map[string]any)
		results, _ := r["results"].([]any)
		for _, res := range results {
			result, _ := res.(map[string]any)
			if result == nil {
				continue
			}
			pkg, ok := index.find(grypeSARIFResultFields(result))
			if !ok {
				continue
			}
			props, _ := result["properties"].(map[string]any)
			if props == nil {
				props = map[string]any{}
				result["properties"] = props
			}
			props["package"] = pkg
			stamped++
		}
	}
	if stamped == 0 {
		return sarifOut, nil
	}
	return json.Marshal(log)
}

// grypeSARIFResultFields reads what pairs a SARIF result with its match: the rule, the message that
// states the version, and the location.
func grypeSARIFResultFields(result map[string]any) (ruleID, message, uri string) {
	ruleID, _ = result["ruleId"].(string)
	if msg, ok := result["message"].(map[string]any); ok {
		message, _ = msg["text"].(string)
	}
	if locs, ok := result["locations"].([]any); ok && len(locs) > 0 {
		loc, _ := locs[0].(map[string]any)
		phys, _ := loc["physicalLocation"].(map[string]any)
		art, _ := phys["artifactLocation"].(map[string]any)
		uri, _ = art["uri"].(string)
	}
	return ruleID, message, uri
}

// grypeMatchIndex holds the matches of Grype's JSON report by rule id and installed version.
//
// The version is part of the key because the rule and the file are not enough. A pnpm lockfile
// commonly holds one package at several versions, each a match of the same advisory under the same
// rule at the same path, and the version Grype states in each result's message is the one fact that
// tells them apart.
type grypeMatchIndex map[string][]grypeMatch

func newGrypeMatchIndex(matches []grypeMatch) grypeMatchIndex {
	index := grypeMatchIndex{}
	for _, m := range matches {
		key := grypeMatchKey(m.Vulnerability.ID+"-"+m.Artifact.Name, m.Artifact.Version)
		index[key] = append(index[key], m)
	}
	return index
}

func grypeMatchKey(ruleID, version string) string { return ruleID + "\x00" + version }

// find returns the package of the match a result reports, and false where no match fits or the
// matches that fit disagree about the package.
//
// Matches of the rule and version are narrowed to the package type the message names, then to
// those whose first location, which is the one Grype writes as the result's, is the longest
// path-wise suffix of the result's location. A suffix rather than equality, because Grype prefixes
// an image finding's path with a short image name and may root a directory finding's path at the
// directory it was given.
func (x grypeMatchIndex) find(ruleID, message, uri string) (sarif.Package, bool) {
	kind, version, ok := grypeMessagePackage(message)
	if !ok {
		return sarif.Package{}, false
	}
	var best []grypeMatch
	longest := -1
	for _, m := range x[grypeMatchKey(ruleID, version)] {
		if m.Artifact.Type != kind {
			continue
		}
		switch n := grypeLocationSuffix(m, uri); {
		case n > longest:
			best, longest = []grypeMatch{m}, n
		case n == longest:
			best = append(best, m)
		}
	}
	if len(best) == 0 {
		return sarif.Package{}, false
	}
	pkg := grypeMatchPackage(best[0])
	for _, m := range best[1:] {
		if grypeMatchPackage(m) != pkg {
			return sarif.Package{}, false
		}
	}
	return pkg, true
}

// grypeLocationSuffix is the length of a match's first location where the result's location ends
// with it at a path boundary, and 0 where it does not.
func grypeLocationSuffix(m grypeMatch, uri string) int {
	if len(m.Artifact.Locations) == 0 {
		return 0
	}
	u := strings.TrimLeft(uri, "/")
	longest := 0
	for _, path := range []string{m.Artifact.Locations[0].Path, m.Artifact.Locations[0].AccessPath} {
		p := strings.TrimLeft(path, "/")
		if p != "" && (u == p || strings.HasSuffix(u, "/"+p)) {
			longest = max(longest, len(p))
		}
	}
	return longest
}

// grypePackages reads the dependency each rule is about, keyed by rule id.
//
// Grype states it on the *rule* rather than the result, a purl in the rule's property bag, and the
// version that fixes it inside the rule's help text, so the generic SARIF reader does not see it.
// The rule describes the first match of its advisory and package name, which is why
// parseGrypeSARIF reaches for it only where a result carries no package of its own.
//
// A finding with no package identity cannot be matched by a supplier's VEX document, cannot be
// recognized as the same flaw another scanner reported, and cannot be tied back to an SBOM entry.
func grypePackages(out []byte) map[string]sarif.Package {
	var doc struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID   string `json:"id"`
						Help struct {
							Text string `json:"text"`
						} `json:"help"`
						Properties struct {
							PURLs []string `json:"purls"`
						} `json:"properties"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		return nil // the report itself already parsed; a property bag we cannot read is not fatal
	}
	packages := map[string]sarif.Package{}
	for _, run := range doc.Runs {
		for _, rule := range run.Tool.Driver.Rules {
			if len(rule.Properties.PURLs) == 0 {
				continue
			}
			// Read from the help text rather than picked apart from the purl: what counts as the "name"
			// inside a purl is ecosystem-specific, pkg:deb/debian/libgnutls30 names a namespace the package
			// name is not, while pkg:golang/golang.org/x/text needs the whole path, and Grype states it
			// plainly one line away.
			pkg := sarif.Package{
				Name:         grypeHelpField(rule.Help.Text, "Package"),
				Version:      grypeHelpField(rule.Help.Text, "Version"),
				FixedVersion: grypeHelpField(rule.Help.Text, "Fix Version"),
				Ecosystem:    grypeHelpField(rule.Help.Text, "Type"),
				PURL:         rule.Properties.PURLs[0],
			}
			if pkg.Name == "" {
				continue
			}
			packages[rule.ID] = pkg
		}
	}
	return packages
}

// grypeHelpField reads one "Key: value" line out of a rule's help text, which is where Grype puts
// the facts its property bag leaves out. Empty when the field is absent, "no fix exists" and "the
// scanner did not say" are both reported as empty by every other scanner here.
func grypeHelpField(help, key string) string {
	for _, line := range strings.Split(help, "\n") {
		rest, ok := strings.CutPrefix(strings.TrimSpace(line), key+":")
		if ok {
			return strings.TrimSpace(rest)
		}
	}
	return ""
}

// grypeRepoPath turns a scan-root-relative path into a repository-relative one.
//
// A path under the checkout directory is made relative to it first: Grype roots its paths at what
// it scanned, but the message it writes and some sources embed the absolute path, and a scanner
// that handled one form and not the other would be right in testing and wrong in a pipeline.
func grypeRepoPath(dir, uri string) string {
	if rel := repoRelPath(dir, uri); rel != uri {
		return rel
	}
	return strings.TrimPrefix(uri, "/")
}

// grypeVersionProbe derives a cache-version string for the Grype-backed scanners that changes when
// the tool or its vulnerability database updates, so a database refresh invalidates cached results
// instead of waiting out the TTL. A cache that outlives the data it was computed from reports
// yesterday's answer about today's advisories, which is the one thing a vulnerability scanner must
// not do. The probe runs at most once (memoized); run is injectable for tests.
type grypeVersionProbe struct {
	once sync.Once
	val  string
	run  func(ctx context.Context, argv []string) ([]byte, error)
}

func newGrypeVersionProbe() *grypeVersionProbe {
	return &grypeVersionProbe{run: execArgv}
}

// cacheVersion returns a string like "grype@0.117.0;db@2026-08-14T06:39:10Z", or "" when it can't
// be determined (Grype absent, or no database yet), callers then fall back to a version-less cache
// key.
//
// Two commands, because Grype reports the tool and the database separately. Both matter and for
// different reasons: a new database changes which advisories exist, and a new Grype changes how
// packages are matched against them.
func (p *grypeVersionProbe) cacheVersion(ctx context.Context) string {
	p.once.Do(func() {
		out, err := p.run(ctx, []string{"grype", "version", "-o", "json"})
		if err != nil {
			return
		}
		var v struct {
			Version string `json:"version"`
		}
		if json.Unmarshal(out, &v) != nil || v.Version == "" {
			return
		}
		p.val = "grype@" + v.Version

		out, err = p.run(ctx, []string{"grype", "db", "status", "-o", "json"})
		if err != nil {
			return
		}
		var db struct {
			Built string `json:"built"`
		}
		if json.Unmarshal(out, &db) != nil || db.Built == "" {
			return
		}
		p.val += ";db@" + db.Built
	})
	return p.val
}

// sharedGrypeVersion is the process-wide probe used by both Grype-backed scanners, so the
// version is resolved once per process however many Grype scans a run plans.
var sharedGrypeVersion = newGrypeVersionProbe()

// grypeDBWarmer prepares Grype's vulnerability database once per process (memoized), downloading it
// and then reading it, so that a run's concurrent scans neither each cold-start the download nor
// each migrate the file. run is injectable for tests.
type grypeDBWarmer struct {
	updateOnce sync.Once
	openOnce   sync.Once
	err        error
	run        func(ctx context.Context, argv []string) ([]byte, error)
}

// warm runs `grype db update -q` at most once and returns any error (best-effort: callers treat
// failure as non-fatal, a real problem resurfaces at scan time, where it can name the scan it
// stopped), then reads the database it left (see open).
//
// Offline it downloads nothing rather than failing. There is nothing to fetch without a network,
// and a prewarm that failed would be the first thing an air-gapped run reported. About a download
// it was configured never to attempt.
func (w *grypeDBWarmer) warm(ctx context.Context) error {
	w.updateOnce.Do(func() {
		if netpolicy.Offline() {
			return
		}
		_, w.err = w.run(ctx, []string{"grype", "db", "update", "-q"})
	})
	w.open(ctx)
	return w.err
}

// open reads the database once, with `grype db providers`, before any scan reads it. Every Grype
// scan calls it first, and a scan that arrives while it runs waits for it.
//
// The first Grype to read a database that an older Grype imported migrates it in place, rewriting
// vulnerability.db and then recording the new digest in import.json. A scan that starts before
// both writes land migrates it again, fails with `bad db checksum`, or reads the file half-written
// and reports fewer vulnerabilities than the database holds. `grype db update` leaves such a
// database in place whenever nothing newer has been published, and offline it is the only
// database available, so the migration happens here, once, while nothing else has the file open.
//
// The scans call it rather than relying on warm because an offline run skips the prewarm. A
// failure here is not reported: the scan that follows reads the same database and quotes what
// Grype said about it.
func (w *grypeDBWarmer) open(ctx context.Context) {
	w.openOnce.Do(func() {
		_, _ = w.run(ctx, []string{"grype", "db", "providers", "-o", "json"})
	})
}

// sharedGrypeDB prepares the vulnerability database once per process for both Grype-backed
// scanners (they share Grype's on-disk cache), so one download serves image and repository scans.
var sharedGrypeDB = &grypeDBWarmer{run: execGrype}
