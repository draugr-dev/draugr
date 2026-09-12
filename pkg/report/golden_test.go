package report

import (
	"bytes"
	"flag"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/sbom"
)

// update rewrites the golden files instead of comparing against them:
//
//	go test ./pkg/report -update
var update = flag.Bool("update", false, "rewrite the console golden files")

// The console layout is copied by hand into four documents, and captured verbatim into the
// demo screenshot and the home page's terminal fragment. None of those notice when it changes. The assertions elsewhere in this package check that
// particular strings are present, which is the wrong shape for a *layout*: column widths, blank
// lines and ordering are exactly what a reader compares against their own terminal, and exactly
// what a `strings.Contains` check cannot see.
//
// So the whole frame is pinned. Any change to it fails here, at the pull request that made it, with
// a list of the artifacts that now disagree. See goldenMismatch below. Regenerating is one flag;
// the point is that it can't happen by accident.
func TestConsoleGolden(t *testing.T) {
	for _, tc := range []struct {
		name string
		data Data
	}{
		{"full", goldenFullData()},
		{"clean", goldenCleanData()},
		{"enriched", goldenEnrichedData()},
		// The default the CLI actually renders. The three above pin `--group none`, which is still
		// reachable and still worth pinning, but a golden that covers only the path most people never
		// take is a golden that does not describe the product.
		{"grouped", goldenGroupedData()},
		// --evidence, which is the auditor's view: the same run with what stands behind it.
		{"evidence", goldenEvidenceData()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// No terminal width, whatever the shell running the tests thinks. The compact listing
			// trims itself to the width it is given, and a golden that moved with the window would
			// pin the window rather than the layout.
			t.Setenv("COLUMNS", "")
			var b bytes.Buffer
			if err := (consoleReporter{}).Render(&b, tc.data); err != nil {
				t.Fatal(err)
			}
			assertGolden(t, filepath.Join("testdata", "console-"+tc.name+".golden"), b.Bytes())
		})
	}
}

func assertGolden(t *testing.T, path string, got []byte) {
	t.Helper()
	if *update {
		if err := os.WriteFile(path, got, 0o600); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s", path)
		return
	}
	want, err := os.ReadFile(path) //nolint:gosec // a fixed path under testdata/
	if err != nil {
		t.Fatalf("read golden: %v (run: go test ./pkg/report -update)", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s\n--- want ---\n%s\n--- got ---\n%s", goldenMismatch(path), want, got)
	}
}

// goldenMismatch names the artifacts that a console-layout change invalidates. The failure is
// the only moment anyone is looking at this, so it carries the checklist rather than a doc
// pointing at one.
func goldenMismatch(path string) string {
	return "console output changed, " + path + " is stale.\n\n" +
		"If the change is intended, regenerate and refresh what copies this layout:\n" +
		"  1. go test ./pkg/report -update\n" +
		"  2. make examples          # real output from the demo sandbox, to paste into docs\n" +
		"  3. update what quotes or describes the layout:\n" +
		"     pasted, and pinned by TestEveryPasteOfTheConsoleIsTracked:\n" +
		"       README.md (the block under \"See it in action\"),\n" +
		"       docs/concepts/verdict-and-gating.md,\n" +
		"       docs/getting-started/first-saga.md, docs/getting-started/quickstart.md,\n" +
		"       docs/reference/cli.md,\n" +
		"       docs/reference/saga-schema.md\n" +
		"     described rather than pasted, so only a shape change reaches them:\n" +
		"       docs/concepts/principles.md, docs/concepts/what-to-fix-first.md,\n" +
		"       docs/guides/findings-in-your-editor.md, docs/guides/caching-and-performance.md\n" +
		"  4. update the blog posts in the draugr.dev repo that quote console output:\n" +
		"     src/content/blog/{security-scan-with-zero-config,what-scanner-output-costs-your-agent}.md\n" +
		"     (grep for 'FIX FIRST' there; they are a separate repo, so nothing else will catch them)\n"
}

// goldenFullData exercises every element of the frame at once: a failing verdict with a release,
// priority counts, controls spanning all four severity bands, a control that errored, the
// suppression and SBOM evidence lines, a rule id long enough to be shortened, more findings than
// the table shows, findings attributed to two different components, and a scanner's account of
// what it measured.
//
// Every element, because an element the fixture omits is an element the golden does not pin. And
// the layout is copied into six documents, two blog posts and a screenshot that nothing else
// checks.
func goldenFullData() Data {
	sca := []sarif.Result{
		{RuleID: "CVE-2019-20477", Level: sarif.LevelError, Score: 9.8, HasScore: true, Priority: "P1",
			Tool: "trivy", Component: "payments", Location: sarif.Location{URI: "app/requirements.txt", StartLine: 4},
			Message: "PyYAML: command execution through python/object/apply constructor in FullLoader"},
		{RuleID: "CVE-2019-10906", Level: sarif.LevelError, Score: 8.6, HasScore: true, Priority: "P1",
			Tool: "trivy", Component: "payments", Location: sarif.Location{URI: "app/requirements.txt", StartLine: 5},
			Message: "python-jinja2: str.format_map allows sandbox escape",
			Package: &sarif.Package{Name: "jinja2", Version: "2.10", FixedVersion: "2.10.1", Ecosystem: "pip"}},
		{RuleID: "CVE-2018-1000656", Level: sarif.LevelWarning, Score: 7.5, HasScore: true, Priority: "P2",
			Tool: "trivy", Component: "internal-tool", Location: sarif.Location{URI: "app/requirements.txt", StartLine: 2},
			Message: "python-flask: Denial of Service via crafted JSON file"},
		{RuleID: "CVE-2020-28493", Level: sarif.LevelNote, Priority: "P4", Tool: "trivy",
			Location: sarif.Location{URI: "app/requirements.txt", StartLine: 5}, Message: "jinja2: ReDoS",
			// The same library as the P1 above, with a different fix. Two advisories, one upgrade, so the
			// golden pins that they fold into one row, and that the row keeps the worse of the two bands
			// rather than the later one.
			Package: &sarif.Package{Name: "jinja2", Version: "2.10", FixedVersion: "2.11.3", Ecosystem: "pip"}},
	}
	iac := []sarif.Result{
		{RuleID: "DS-0002", Level: sarif.LevelError, Score: 8.0, HasScore: true, Priority: "P1",
			Tool: "trivy", Component: "payments", Location: sarif.Location{URI: "app/Dockerfile", StartLine: 1},
			Message: "Image user should not be 'root'"},
		{RuleID: "KSV-0014", Level: sarif.LevelWarning, Score: 5.5, HasScore: true, Priority: "P3",
			Tool: "trivy", Location: sarif.Location{URI: "deploy/pod.yaml", StartLine: 8},
			Message: "Root file system is not read-only"},
	}
	sast := []sarif.Result{
		{RuleID: "python.flask.security.injection.tainted-sql-string.tainted-sql-string",
			Level: sarif.LevelError, Priority: "P2", Tool: "semgrep",
			Location: sarif.Location{URI: "app/main.py", StartLine: 42},
			Message:  "Detected user input flowing into a raw SQL string"},
	}
	licenses := []sarif.Result{
		{RuleID: "license/GPL-3.0-only/some-lib", Level: sarif.LevelWarning, Priority: "P3",
			Tool: "trivy-license", Location: sarif.Location{URI: "go.mod", StartLine: 17},
			Message: "some-lib is GPL-3.0-only. Copyleft."},
	}
	run := engine.Result{
		Controls: map[string]plugin.ControlResult{
			"sca": {Control: "sca", Report: sarif.Report{Tool: "trivy", Results: sca}},
			"iac": {Control: "iac", Report: sarif.Report{Tool: "trivy", Results: iac,
				Provenance: []sarif.Provenance{{Tool: "trivy", Version: "0.69.3"}}}},
			"sast": {Control: "sast", Report: sarif.Report{Tool: "semgrep", Results: sast}},
			"licenses": {Control: "licenses", Report: sarif.Report{Tool: "trivy-license", Results: suppressedLicenses(licenses),
				Provenance: []sarif.Provenance{{Tool: "trivy-license", Version: "0.69.3",
					Fields: []sarif.Field{{Key: "policy", Value: "deny copyleft"}}}}}},
		},
		ScanErrors: map[string][]string{"dast": {"nuclei: executable file not found in $PATH"}},
		// A run that saved work both ways: some jobs answered from the cache, one shared a scan
		// with an identical job. Both appear on every real cached run, so the layout the docs
		// copy has to include them.
		Stats: engine.Stats{
			Jobs: 11, Scans: 6, CacheHits: 4, Deduped: 1,
			Concurrency: 8, Duration: 34500 * time.Millisecond,
		},
		Suppressed: 2,
		// One suppression signed and one not, because the line renders them differently and an
		// element the fixture omits is an element the golden does not pin. This is the account
		// of who decided what, which is the half of a suppression an auditor comes for.
		SBOMs: []sbom.Document{{Format: "spdx-json"}, {Format: "spdx-json"}},
	}
	verdict := norn.Result{Verdict: norn.Fail, Controls: []norn.ControlOutcome{
		{Control: "iac", Verdict: norn.Fail, Counts: sarif.Counts{Error: 1, Warning: 1}},
		{Control: "licenses", Verdict: norn.Pass, Counts: sarif.Counts{Warning: 1}},
		{Control: "sast", Verdict: norn.Fail, Counts: sarif.Counts{Error: 1}},
		{Control: "sca", Verdict: norn.Fail, Counts: sarif.Counts{Error: 2, Warning: 1, Note: 1}},
	}}
	return Data{
		Project: "draugr-demo",
		Release: saga.Release{Version: "0.0.0"},
		Run:     run,
		Verdict: verdict,
		TopN:    5, // fewer than the findings above, so the truncation line is pinned too
		// A failing component, a clean one, and findings belonging to neither, the three states the
		// breakdown has to render, including the clean row, which is the one a reader takes back to their
		// team.
		Components: []ComponentVerdict{
			{Name: "payments", Verdict: norn.Fail, Controls: []string{"sca", "secrets"},
				Priorities: [4]int{3, 2, 1, 0}, Findings: 6},
			{Name: "internal-tool", Verdict: norn.Pass},
		},
		UnattributedFindings: 2,
	}
}

// goldenCleanData pins the other frame users see: nothing found, and the report has to say so
// without implying more than it checked.
func goldenCleanData() Data {
	return Data{
		Project: "my-app",
		Release: saga.Release{Version: "1.0"},
		Run: engine.Result{Controls: map[string]plugin.ControlResult{
			"images": {Control: "images", Report: sarif.Report{Tool: "trivy"}},
		}},
		Verdict: norn.Result{Verdict: norn.Pass, Controls: []norn.ControlOutcome{
			{Control: "images", Verdict: norn.Pass},
		}},
	}
}

// suppressedLicenses appends the two set-aside findings the Suppressed count refers to: one
// signed, one not, because the line renders them differently and an element the fixture omits is
// an element the golden does not pin.
func suppressedLicenses(base []sarif.Result) []sarif.Result {
	return append(append([]sarif.Result{}, base...),
		sarif.Result{RuleID: "license/GPL-3.0-only/x", Level: sarif.LevelWarning,
			Location: sarif.Location{URI: "go.mod"},
			Suppression: &sarif.Suppression{Kind: "external",
				Justification: "legal reviewed; we do not distribute", AcceptedBy: "a.reviewer"}},
		sarif.Result{RuleID: "license/GPL-3.0-only/y", Level: sarif.LevelWarning,
			Location:    sarif.Location{URI: "go.mod"},
			Suppression: &sarif.Suppression{Kind: "external", Justification: "same package tree"}})
}

// goldenEnrichedData is a run whose severities were raised by exploitability data.
//
// A separate case rather than a change to "full" on purpose: the layout in "full" is the one
// quoted in the README, the docs and the demo screenshot, and enrichment is off by default, so
// none of those should move because this shipped. If this case ever has to edit "full", that is
// the signal to go and refresh them.
func goldenEnrichedData() Data {
	fetched := time.Date(2026, 8, 1, 9, 12, 0, 0, time.UTC)
	sca := []sarif.Result{
		{RuleID: "CVE-2024-3094", Level: sarif.LevelError, Score: 8.1, HasScore: true, Priority: "P1",
			Tool: "trivy", Location: sarif.Location{URI: "go.mod", StartLine: 12},
			Message: "xz: malicious code in the upstream tarballs",
			Escalation: &sarif.Escalation{
				From: sarif.SeverityHigh, To: sarif.SeverityCritical,
				Signal: "kev", Detail: "on KEV", AsOf: "2026-08-01",
			}},
		{RuleID: "CVE-2019-20477", Level: sarif.LevelWarning, Score: 6.5, HasScore: true, Priority: "P1",
			Tool: "trivy", Location: sarif.Location{URI: "app/requirements.txt", StartLine: 4},
			Message: "PyYAML: command execution through python/object/apply constructor",
			Escalation: &sarif.Escalation{
				From: sarif.SeverityMedium, To: sarif.SeverityHigh,
				Signal: "epss", Detail: "EPSS 0.87", AsOf: "2026-08-02",
			}},
		// Not everything moves. A run where every row carries a note would not show that the
		// note means something.
		{RuleID: "CVE-2018-1000656", Level: sarif.LevelWarning, Score: 7.5, HasScore: true, Priority: "P2",
			Tool: "trivy", Location: sarif.Location{URI: "app/requirements.txt", StartLine: 2},
			Message: "python-flask: Denial of Service via crafted JSON file"},
	}
	run := engine.Result{
		Controls: map[string]plugin.ControlResult{
			"sca": {Control: "sca", Report: sarif.Report{Tool: "trivy", Results: sca}},
		},
	}
	return Data{
		Project: "acme-api",
		Release: saga.Release{Version: "1.4.0"},
		Run:     run,
		Verdict: norn.Result{Verdict: norn.Fail, Controls: []norn.ControlOutcome{
			{Control: "sca", Verdict: norn.Fail, Counts: sarif.Counts{Error: 2, Warning: 1}},
		}},
		Exploitability: []FeedProvenance{
			{Name: "kev", URL: "https://www.cisa.gov/…/known_exploited_vulnerabilities.json",
				FetchedAt: fetched, SHA256: "15b44d7c9c5713e2f5b1a0c4d8e93a76b1c0f2d3e4a5b6c7d8e9f0a1b2c3d4e5"},
			// Three days old against a 24-hour bar: the report says so, not just the log of the
			// run that produced it.
			{Name: "epss", URL: "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
				FetchedAt: fetched.Add(-72 * time.Hour), SHA256: "41c20e9dc3cf8a71e0d2b3c4f5a6978899aabbccddeeff00112233445566778", Stale: true},
		},
	}
}

// goldenGroupedData is the full fixture rendered the way `draugr scan` renders it.
func goldenGroupedData() Data {
	d := goldenFullData()
	d.View = ViewActions
	return d
}

// goldenEvidenceData is the full fixture rendered with --evidence.
func goldenEvidenceData() Data {
	d := goldenGroupedData()
	d.Evidence = true
	return d
}

// pastesConsoleOutput is every markdown file that quotes what the console prints, and the list the
// golden's failure message tells a reader to refresh.
//
// A file quoting the layout with nothing tracking it is how two pages came to show output the
// renderer had stopped producing. Neither was in the checklist, so neither was refreshed, and
// nothing failed: a stale paste is valid markdown that reads correctly to everybody who does not
// run the command beside it.
//
// A page may leave this list by describing the shape instead of pasting a run, which is what a
// concept page usually wants anyway. It may not leave it by staying pasted and unlisted.
var pastesConsoleOutput = map[string]bool{
	"README.md":                           true,
	"docs/concepts/verdict-and-gating.md": true,
	"docs/getting-started/first-saga.md":  true,
	"docs/getting-started/quickstart.md":  true,
	"docs/reference/cli.md":               true,
	"docs/reference/saga-schema.md":       true,
}

// consoleShapes are strings only this renderer produces, so a fence carrying one is a paste rather
// than a shell session or a scanner's own output.
var consoleShapes = []string{
	"DRAUGR  ", "FIX FIRST", "WHAT TO DO", "CONTROLS", "COMPONENTS", "MEASURED AGAINST",
	"NOT MEASURED", "NOT CHECKED", "REACHABILITY", "raised from ", "lowered from ",
	"suppressed by config.exclude",
}

func TestEveryPasteOfTheConsoleIsTracked(t *testing.T) {
	root := filepath.Join("..", "..")
	var docs, pasted []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// The changelog records what output looked like at a release, which is the one place
			// a stale paste is the correct content.
			if d.Name() == ".git" || d.Name() == "node_modules" || d.Name() == "changelog.d" {
				return fs.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".md" {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		rel = filepath.ToSlash(rel)
		if rel == "CHANGELOG.md" {
			return nil
		}
		docs = append(docs, rel)
		return nil
	})
	if err != nil {
		t.Fatalf("walking the repository: %v", err)
	}

	// Read after the walk rather than inside it, so nothing here opens a path the walk is still
	// resolving.
	for _, rel := range docs {
		// #nosec G304 -- a path this test collected from this repository's own tree.
		body, readErr := os.ReadFile(filepath.Join(root, rel))
		if readErr != nil {
			t.Fatalf("reading %s: %v", rel, readErr)
		}
		if fencedConsole(string(body)) {
			pasted = append(pasted, rel)
		}
	}

	for _, rel := range pasted {
		if !pastesConsoleOutput[rel] {
			t.Errorf("%s pastes console output and nothing tracks it.\n"+
				"Either describe the shape instead of pasting a run, which is what a concept page\n"+
				"usually wants, or add it to pastesConsoleOutput and to the checklist in\n"+
				"goldenMismatch so a layout change reaches it.", rel)
		}
	}
	for rel := range pastesConsoleOutput {
		if !slices.Contains(pasted, rel) {
			t.Errorf("%s is listed as pasting console output and no longer does. Remove it from\n"+
				"pastesConsoleOutput and from the checklist in goldenMismatch, so the list stays\n"+
				"the set of files a layout change actually invalidates.", rel)
		}
	}
}

// retiredShapes are strings this renderer used to produce and does not any more, wherever they
// appear inside a fenced block.
//
// The paste tracking says which documents quote a run; nothing said whether what they quote is
// still what the tool prints, and a document holding a layout from two releases ago reads as
// current to everybody except the person who changed it. These are cheap to check and they are
// exactly what goes stale.
var retiredShapes = []string{
	"Draugr · ", "Priorities:", "Fix first (", "Fix first · ",
	"↑ ranked as ", "↓ ranked as ", "more finding(s)",
}

// retiredHeadings are the section labels this renderer used to write, matched on the whole line.
//
// On the whole line because the words are ordinary: a Go struct literal and an MCP answer both say
// "Controls:" and neither is quoting this renderer. What made them headings was standing alone.
var retiredHeadings = []string{
	"Controls:", "Components:", "Reachability:", "Measured against:", "Not measured:",
	"Not checked:",
}

// TestNoPasteShowsAShapeTheRendererRetired reads every fenced block in the repository, not only the
// ones tracked as pastes: a block quoting a layout old enough carries none of the strings that
// identify a paste today, so the tracking cannot see it and this is what does.
func TestNoPasteShowsAShapeTheRendererRetired(t *testing.T) {
	for rel, body := range documents(t) {
		inFence := false
		for i, line := range strings.Split(body, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "```") ||
				strings.HasPrefix(strings.TrimSpace(line), "~~~") {
				inFence = !inFence
				continue
			}
			if !inFence {
				continue
			}
			stale := ""
			for _, shape := range retiredShapes {
				if strings.Contains(line, shape) {
					stale = shape
				}
			}
			for _, heading := range retiredHeadings {
				if strings.TrimSpace(line) == heading {
					stale = heading
				}
			}
			if stale == "" {
				continue
			}
			t.Errorf("%s:%d quotes %q, which this renderer no longer prints:\n  %s\n"+
				"Refresh it from a real run (make examples). If the shape is gone for good, take it\n"+
				"out of retiredShapes so the list stays what a stale document would be holding.",
				rel, i+1, stale, strings.TrimSpace(line))
		}
	}
}

// consolePasteWidth is how wide a quoted run may be.
//
// The same width every sentence Draugr prints is held to, and about what a code block shows before
// it scrolls sideways in a README on github.com. Past it the columns on the right are off the
// screen, and the rightmost is the one carrying what to do about the finding, so the example
// teaches the opposite of what it was pasted to teach.
//
// A real run is allowed to be wider than this; a pasted example is not. Choose a narrower run.
const consolePasteWidth = 96

// TestAPastedRunFitsWhereItIsRead holds every quoted run to that width.
func TestAPastedRunFitsWhereItIsRead(t *testing.T) {
	placeholder := regexp.MustCompile(`<[a-z][^>]*>`)
	for rel, body := range documents(t) {
		inFence, fence, at := false, []string{}, 0
		for i, line := range strings.Split(body, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "```") ||
				strings.HasPrefix(strings.TrimSpace(line), "~~~") {
				if inFence && pastesARun(fence, placeholder) {
					for n, quoted := range fence {
						if w := utf8.RuneCountInString(quoted); w > consolePasteWidth {
							t.Errorf("%s:%d is %d cells wide, past the %d a reader sees:\n  %s",
								rel, at+n+1, w, consolePasteWidth, quoted)
						}
					}
				}
				inFence, fence, at = !inFence, nil, i+1
				continue
			}
			if inFence {
				fence = append(fence, line)
			}
		}
	}
}

// documents reads every markdown file in the repository, keyed by its path.
//
// The changelog records what output looked like at a release, which is the one place a stale paste
// is the correct content.
func documents(t *testing.T) map[string]string {
	t.Helper()
	root := filepath.Join("..", "..")
	out, found := map[string]string{}, []string{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == "node_modules" || d.Name() == "changelog.d" {
				return fs.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".md" {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		rel = filepath.ToSlash(rel)
		if rel == "CHANGELOG.md" {
			return nil
		}
		found = append(found, rel)
		return nil
	})
	if err != nil {
		t.Fatalf("walking the repository: %v", err)
	}
	// Read after the walk rather than inside it, so nothing here opens a path the walk is still
	// resolving.
	for _, rel := range found {
		// #nosec G304 -- a path this test collected from this repository's own tree.
		body, readErr := os.ReadFile(filepath.Join(root, rel))
		if readErr != nil {
			t.Fatalf("reading %s: %v", rel, readErr)
		}
		out[rel] = string(body)
	}
	return out
}

// fencedConsole reports whether a fenced block in this document pastes a run.
//
// A block written as a schematic does not count, and is recognized by its placeholders. A layout
// change does not invalidate `<band>  <the action>  <control> · <n> findings`, which is the whole
// reason to write one: it says what the shape is without claiming to be a scan.
func fencedConsole(doc string) bool {
	placeholder := regexp.MustCompile(`<[a-z][^>]*>`)
	var fence []string
	inFence := false
	for _, line := range strings.Split(doc, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "```") || strings.HasPrefix(trimmed, "~~~") {
			if inFence && pastesARun(fence, placeholder) {
				return true
			}
			inFence = !inFence
			fence = nil
			continue
		}
		if inFence {
			fence = append(fence, line)
		}
	}
	return inFence && pastesARun(fence, placeholder)
}

func pastesARun(fence []string, placeholder *regexp.Regexp) bool {
	carries := false
	for _, line := range fence {
		if placeholder.MatchString(line) {
			return false
		}
		for _, shape := range consoleShapes {
			if strings.Contains(line, shape) {
				carries = true
			}
		}
	}
	return carries
}
