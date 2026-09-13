package scanners

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/draugr-dev/draugr/internal/netpolicy"
	"github.com/draugr-dev/draugr/internal/tools"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// NewRetireJS returns a Scanner that runs retire.js over a checked-out repository to find known
// vulnerable JavaScript that never appears in a lockfile. It serves the "sca" control, opt-in
// beside Trivy rather than instead of it.
//
// Lockfile-based SCA answers for what the package manager installed. Front-end code routinely
// ships JavaScript it did not: a library pulled from a CDN, a vendored file under static/, bundled
// output shipped without its manifest. retire.js fingerprints those by content, which is the only
// way to identify a file whose provenance was never recorded.
//
// The gap matters because of its shape rather than its size. A repository serving a five-year-old
// jQuery scans clean today. The control runs, reports, and passes, so nothing about the output
// suggests anywhere left to look.
func NewRetireJS() plugin.Scanner {
	s := newRepoScannerWithParser(
		plugin.ScannerInfo{
			Name:         "retirejs",
			Origin:       "RetireJS",
			Binary:       "retire",
			Controls:     []string{"sca"},
			TargetKinds:  []plugin.TargetKind{plugin.TargetRepository},
			ConfigSchema: json.RawMessage(noScannerOptions),
		},
		retireJSArgs,
		parseRetireJS,
	)
	s.cacheVersion = sharedRetireJSVersion.version
	s.prewarm = sharedRetireJSRepo.warm
	return s
}

// retireJSRepoWarmer fetches the advisory database once, before the jobs fan out.
//
// retire.js honors its own cache, so a warm one costs nothing however many jobs run. A cold one
// does not survive concurrency: three jobs starting together all find nothing, all fetch, and all
// write their own copy, which shows up as duplicate files a millisecond apart. Nothing prunes
// them, so the directory grows by a copy of the database per job per expiry.
//
// Warmed by running the tool against an empty directory, which takes about a fifth of a second and
// asks retire.js to populate its cache the way it would anyway. Draugr does not fetch the file
// itself: the URL and the format are retire.js's, and a copy Draugr placed would be Draugr's to
// keep valid against a tool that can change both.
type retireJSRepoWarmer struct {
	once sync.Once
	err  error
	run  func(ctx context.Context, dir string, argv []string) ([]byte, error)
}

var sharedRetireJSRepo = &retireJSRepoWarmer{run: execArgvInDir}

func (w *retireJSRepoWarmer) warm(ctx context.Context) error {
	w.once.Do(func() {
		cache := retireCacheDir()
		if cache == "" {
			return
		}
		if netpolicy.Offline() {
			// Nothing to fetch, and the scan reads whatever copy is already there. Said here
			// rather than left to the tool, because "offline with no local copy" is a different
			// problem from "offline", and only one of them stops the scan.
			if retireLocalRepo(cache) == "" {
				w.err = fmt.Errorf("offline and no cached retire.js advisory database in %s: "+
					"copy one across, or run once with a network", cache)
			}
			return
		}
		empty, err := os.MkdirTemp("", "draugr-retire-warm-")
		if err != nil {
			w.err = err
			return
		}
		defer func() { _ = os.RemoveAll(empty) }()
		if _, err := w.run(ctx, "", []string{
			"retire", "--path", empty, "--outputformat", "json", "--exitwith", "0",
			"--cachedir", cache,
		}); err != nil {
			w.err = err
			return
		}
		pruneRetireCache(cache)
	})
	return w.err
}

// retireIndex is retire.js's own cache index: each source URL against the copy it last wrote.
type retireIndex map[string]struct {
	Date int64  `json:"date"`
	File string `json:"file"`
}

// readRetireIndex reads the cache index, or nil where there is none to read.
func readRetireIndex(cache string) retireIndex {
	body, err := os.ReadFile(filepath.Join(cache, "index.json")) // #nosec G304 -- a path Draugr owns
	if err != nil {
		return nil
	}
	var idx retireIndex
	if json.Unmarshal(body, &idx) != nil {
		return nil
	}
	return idx
}

// retireLocalRepo is the cached advisory database retire.js would read, or "" where there is none.
func retireLocalRepo(cache string) string {
	for _, entry := range readRetireIndex(cache) {
		if entry.File == "" {
			continue
		}
		path := filepath.Join(cache, entry.File)
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return ""
}

// pruneRetireCache removes copies of the database the index no longer names.
//
// Each expiry leaves the previous copy behind, at roughly 420 KB a time, so a directory nothing
// tidies grows without limit while holding one useful file. Failing to remove one is not worth
// failing a scan over.
func pruneRetireCache(cache string) {
	keep := map[string]bool{"index.json": true}
	for _, entry := range readRetireIndex(cache) {
		keep[entry.File] = true
	}
	entries, err := os.ReadDir(cache)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() || keep[e.Name()] || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		_ = os.Remove(filepath.Join(cache, e.Name()))
	}
}

// retireJSArgs builds `retire --path <dir> --outputformat json --exitwith 0`.
//
// --exitwith 0 because retire.js exits 13 when it finds something, and a scanner that fails on
// findings makes the exit code the verdict. Severity is the controller's job and the findings
// belong in the report; this is the same reason Trivy is run with --exit-code 0.
//
// --cachedir moves the advisory database out of /tmp and into the directory Draugr already owns.
// retire.js bundles no database. It fetches one on first use and caches it. So the default
// location means a CI runner downloads it every job, and an air-gapped machine has nowhere to be
// handed one. Under ~/.draugr/data it travels with everything else the air-gapped guide says to
// copy across.
func retireJSArgs(dir string, _ plugin.Config) []string {
	argv := []string{"retire", "--path", dir, "--outputformat", "json", "--exitwith", "0"}
	cache := retireCacheDir()
	if cache == "" {
		return argv
	}
	argv = append(argv, "--cachedir", cache)
	// Offline, point the tool at the copy already on disk. Warming is not enough on its own:
	// retire.js checks its cache at scan time too, so a run whose copy has expired reaches out
	// again, once per job, on a machine that has said it has no network.
	if netpolicy.Offline() {
		if local := retireLocalRepo(cache); local != "" {
			argv = append(argv, "--jsrepo", local)
		}
	}
	return argv
}

// retireCacheDir is where the advisory database is kept, or "" when Draugr cannot work out a home
// directory, in which case retire.js uses its own default rather than the scan failing over a
// cache location.
func retireCacheDir() string {
	root, err := tools.DataRoot()
	if err != nil {
		return ""
	}
	return filepath.Join(root, "retirejs")
}

// retireReport is the part of retire.js's JSON output Draugr reads.
type retireReport struct {
	Data []struct {
		File    string `json:"file"`
		Results []struct {
			Component string `json:"component"`
			Version   string `json:"version"`
			// Detection is how the library was recognized, "filecontent", "filename", "uri".
			Detection       string             `json:"detection"`
			Vulnerabilities []retireVulnerable `json:"vulnerabilities"`
		} `json:"results"`
	} `json:"data"`
}

type retireVulnerable struct {
	// Below is the first version that is not affected, which is the fix.
	Below       string   `json:"below"`
	Severity    string   `json:"severity"`
	CWE         []string `json:"cwe"`
	Identifiers struct {
		Summary  string   `json:"summary"`
		CVE      []string `json:"CVE"`
		GitHubID string   `json:"githubID"`
		Issue    string   `json:"issue"`
		Bug      string   `json:"bug"`
		RetID    string   `json:"retid"`
	} `json:"identifiers"`
}

// parseRetireJS converts retire.js's JSON into SARIF results.
func parseRetireJS(out []byte, _ string, _ plugin.Config) (sarif.Report, error) {
	var report retireReport
	if err := json.Unmarshal(out, &report); err != nil {
		return sarif.Report{}, fmt.Errorf("decode retire.js output: %w", err)
	}
	var results []sarif.Result
	for _, entry := range report.Data {
		for _, found := range entry.Results {
			for _, v := range found.Vulnerabilities {
				level, score, hasScore := retireSeverity(v.Severity)
				results = append(results, sarif.Result{
					Tool:     "retirejs",
					RuleID:   retireRuleID(found.Component, v),
					Level:    level,
					Score:    score,
					HasScore: hasScore,
					Message:  retireMessage(found.Component, found.Version, found.Detection, v),
					Location: sarif.Location{URI: entry.File},
					Package: &sarif.Package{
						Name:         found.Component,
						Version:      found.Version,
						FixedVersion: v.Below,
						PURL:         retirePURL(found.Component, found.Version),
						Ecosystem:    "npm",
					},
				})
			}
		}
	}
	return sarif.Report{Tool: "retirejs", Results: results}, nil
}

// retireRuleID picks the most portable identifier the advisory carries.
//
// A CVE first, because it is the one a reader can look up and the one an exclusion is most likely
// to be written against. Then the GitHub advisory. Only when an advisory has neither does the rule
// fall back to retire.js's own identifier, prefixed, so it cannot be mistaken for a CVE, and
// stable, so a suppression written against it keeps working.
func retireRuleID(component string, v retireVulnerable) string {
	if len(v.Identifiers.CVE) > 0 && v.Identifiers.CVE[0] != "" {
		return v.Identifiers.CVE[0]
	}
	if v.Identifiers.GitHubID != "" {
		return v.Identifiers.GitHubID
	}
	for _, local := range []string{v.Identifiers.RetID, v.Identifiers.Issue, v.Identifiers.Bug} {
		if local != "" {
			return "retirejs:" + component + ":" + local
		}
	}
	// Nothing identifies it but the fix boundary, which is still stable for a given advisory.
	return "retirejs:" + component + ":below-" + v.Below
}

// retireMessage says what was found, in which library, and what fixes it.
func retireMessage(component, version, detection string, v retireVulnerable) string {
	summary := strings.TrimSpace(v.Identifiers.Summary)
	if summary == "" {
		summary = "known vulnerability"
	}
	// The version to move to goes with the library, before the advisory's own words, the same shape
	// every other dependency finding takes. A line has to fit a column and the advisory decides how
	// long its half is, so anything after it is the part that gets cut.
	subject := fmt.Sprintf("%s %s", component, version)
	if v.Below != "" {
		subject += " → " + v.Below
	} else {
		subject += ", no fix available"
	}
	msg := subject + ": " + summary
	// How the library was recognized, because it is the answer to "why is this not in my lockfile", a
	// file matched by content is one the package manager never installed.
	if detection != "" {
		msg += fmt.Sprintf(" [detected by %s]", detection)
	}
	if cwes := nonEmpty(v.CWE); len(cwes) > 0 {
		sort.Strings(cwes)
		msg += " (" + strings.Join(cwes, ", ") + ")"
	}
	return msg
}

// retirePURL builds the package URL for a library retire.js named.
//
// npm, because that is the ecosystem retire.js identifies against even for a file that was never
// installed from it, the vendored copy of jQuery and the npm package are the same library, and
// saying so is what lets a consumer correlate them.
func retirePURL(component, version string) string {
	if component == "" {
		return ""
	}
	purl := "pkg:npm/" + component
	if version != "" {
		purl += "@" + version
	}
	return purl
}

// retireSeverity maps retire.js's severity to a SARIF level and a CVSS-style score, set together
// so counts and prioritization agree. An unrecognized severity gets no score and falls to a note.
func retireSeverity(sev string) (sarif.Level, float64, bool) {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "critical":
		return sarif.LevelError, 9.5, true
	case "high":
		return sarif.LevelError, 8.0, true
	case "medium":
		return sarif.LevelWarning, 5.0, true
	case "low":
		return sarif.LevelNote, 2.0, true
	default:
		return sarif.LevelNote, 0, false
	}
}
