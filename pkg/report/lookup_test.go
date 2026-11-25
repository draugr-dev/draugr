package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/tui"
)

// goOnlyRun is two components in two repositories, each with a finding named only by its Go
// advisory id, and one finding named by its CVE.
func goOnlyRun() []sarif.Result {
	return []sarif.Result{
		xnet("GO-2026-0001-golang.org/x/net", "api", "repo-api"),
		xnet("GHSA-4rgh-jx4f-qfcq-golang.org/x/net", "worker", "repo-worker"),
		xnet("CVE-2026-0003", "worker", "repo-worker"),
	}
}

// A run that read KEV and EPSS and no Go vulnerability database says how many findings neither
// could check for want of their CVE, and what fetches the database. A run that read it, or read
// neither feed, says nothing more than its rows do.
func TestARunSaysWhichFindingsItCouldNotLookUp(t *testing.T) {
	const want = "KEV and EPSS did not check 2 findings named only by a Go or GitHub advisory id"
	d := cachedKEV(goOnlyRun())
	var b bytes.Buffer
	if err := (consoleReporter{}).Render(&b, d); err != nil {
		t.Fatal(err)
	}
	if out := b.String(); !strings.Contains(out, want) || !strings.Contains(out, "draugr feeds update govulndb") {
		t.Errorf("the console should count the findings it could not look up:\n%s", out)
	}

	// Where the Go database was read and gave them nothing, OSV.dev's Go advisories are what is left
	// to ask, and the note names the setting that reads them instead of the fetch.
	read := kevData(goOnlyRun())
	read.Exploitability = append(read.Exploitability, FeedProvenance{Name: "govulndb"})
	_, notes := signals(read, summarize(read))
	got := strings.Join(notes, "\n")
	if strings.Contains(got, want) || !strings.Contains(got, "KEV and EPSS did not check 2 Go findings with an advisory id "+
		"and no CVE. config.exploitability.advisories: [go] looks up their CVEs.") {
		t.Errorf("notes = %q, want the advisories setting where the database was read", notes)
	}
	// With both read and still no CVE, the note says why rather than what to turn on.
	read.Exploitability = append(read.Exploitability, FeedProvenance{Name: "osv-go"})
	if _, notes := signals(read, summarize(read)); strings.Contains(strings.Join(notes, "\n"), "advisories: [") ||
		!strings.Contains(strings.Join(notes, "\n"), "list no CVE, or different ones") {
		t.Errorf("notes = %q, want the unresolved note where both were read", notes)
	}

	unread := kevData(goOnlyRun())
	unread.Exploitability = nil
	if _, notes := signals(unread, summarize(unread)); len(notes) != 0 {
		t.Errorf("notes = %q, want none where neither KEV nor EPSS was read", notes)
	}

	// A finding the lookup gave a CVE is one KEV and EPSS checked, and is not counted.
	looked := goOnlyRun()
	looked[0].CVELookup = &sarif.CVELookup{CVEs: []string{"CVE-2026-0001"}, ID: "GO-2026-0001", Record: "GO-2026-0001"}
	d = cachedKEV(looked)
	if _, notes := signals(d, summarize(d)); !strings.Contains(strings.Join(notes, "\n"), "did not check 1 finding named") {
		t.Errorf("notes = %q, want the one finding left counted", notes)
	}
}

// The compact view drops the Signals notes, apart from the one that says the answer is less than it
// appears: findings KEV and EPSS could not check. It keeps that one even where no signal row is
// unread, so the section prints for it alone.
func TestTheCompactViewKeepsTheLookupNote(t *testing.T) {
	d := cachedKEV(goOnlyRun())
	s := summarize(d)
	var b bytes.Buffer
	writeSignals(&b, tui.Plain(), d, s, true)
	if out := b.String(); !strings.Contains(out, "did not check 2 findings") || !strings.Contains(out, "SIGNALS") {
		t.Errorf("compact signals = %q, want the lookup note under its heading", out)
	}

	// With the Go database read, the note that stays names the advisories setting instead.
	read := kevData(goOnlyRun())
	read.Exploitability = append(read.Exploitability, FeedProvenance{Name: "govulndb"})
	b.Reset()
	writeSignals(&b, tui.Plain(), read, summarize(read), true)
	if out := b.String(); strings.Contains(out, "did not check 2 findings") || !strings.Contains(out, "advisories: [go]") {
		t.Errorf("compact signals = %q, want the advisories note where the database was read", out)
	}
	read.Exploitability = append(read.Exploitability, FeedProvenance{Name: "osv-go"})
	b.Reset()
	writeSignals(&b, tui.Plain(), read, summarize(read), true)
	if out := b.String(); strings.Contains(out, "advisories: [") || !strings.Contains(out, "or different ones") {
		t.Errorf("compact signals = %q, want the unresolved note where both were read", out)
	}
}

// cachedKEV is kevData with KEV and EPSS read from the feed cache, which records where each came from.
func cachedKEV(results []sarif.Result) Data {
	d := kevData(results)
	for i := range d.Exploitability {
		d.Exploitability[i].URL = "https://example.com/" + d.Exploitability[i].Name
	}
	return d
}

// A run whose KEV and EPSS came from files given as paths read no cache, so it could not have read
// the Go vulnerability database either: the note says the lookup needs the cache rather than telling
// the reader to fetch a database the run would still not read.
func TestTheLookupNoteSaysAFilePathReadsNoCache(t *testing.T) {
	d := kevData(goOnlyRun())
	_, notes := signals(d, summarize(d))
	got := strings.Join(notes, "\n")
	if !strings.Contains(got, "did not check 2 findings") || !strings.Contains(got, "use --kev auto or --epss auto") ||
		strings.Contains(got, "draugr feeds update govulndb") {
		t.Errorf("notes = %q, want the cache named and no fetch suggested", notes)
	}
	cached := cachedKEV(goOnlyRun())
	_, notes = signals(cached, summarize(cached))
	if got := strings.Join(notes, "\n"); !strings.Contains(got, "Run draugr feeds update govulndb, then scan again") {
		t.Errorf("notes = %q, want the fetch and a rescan suggested", notes)
	}
}

// Findings of an ecosystem whose OSV.dev advisories were not read are counted by ecosystem, with
// the setting that reads them, and the sources of CVEs that were looked up are credited.
func TestSignalsNameTheAdvisoriesAndTheirSources(t *testing.T) {
	npm := func(rule string) sarif.Result {
		r := xnet(rule, "web", "repo-web")
		r.Package = &sarif.Package{Name: "lodash", Version: "4.17.4", Ecosystem: "npm"}
		return r
	}
	crate := xnet("RUSTSEC-2016-0001", "web", "repo-web")
	crate.Package = &sarif.Package{Name: "x", Ecosystem: "cargo"}
	looked := npm("GHSA-jf85-cpcp-j695")
	looked.CVELookup = &sarif.CVELookup{CVEs: []string{"CVE-2019-10744"}, ID: "GHSA-jf85-cpcp-j695",
		Record: "GHSA-jf85-cpcp-j695", Dataset: "osv-npm", Source: "GitHub Advisory Database", License: "CC-BY-4.0"}
	rustsec := xnet("RUSTSEC-2016-0002", "web", "repo-web")
	rustsec.CVELookup = &sarif.CVELookup{CVEs: []string{"CVE-2016-10932"}, Source: "RustSec Advisory Database", License: "CC0-1.0"}

	d := cachedKEV([]sarif.Result{npm("GHSA-4rgh-jx4f-qfcq"), npm("GHSA-2222-3333-4444"), crate, looked, rustsec})
	_, notes := signals(d, summarize(d))
	got := strings.Join(notes, "\n")
	for _, want := range []string{
		"KEV and EPSS did not check 2 npm and 1 crates.io findings with an advisory id and no CVE. " +
			"config.exploitability.advisories: [npm, crates.io] looks up their CVEs.",
		"CVE from OSV.dev for 2 findings: 1 from the GitHub Advisory Database (CC-BY-4.0), 1 from the RustSec Advisory Database (CC0-1.0)",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("notes missing %q:\n%s", want, got)
		}
	}
	d.Exploitability = append(d.Exploitability, FeedProvenance{Name: "osv-npm"}, FeedProvenance{Name: "osv-crates.io"})
	if _, notes := signals(d, summarize(d)); strings.Contains(strings.Join(notes, "\n"), "advisories:") {
		t.Errorf("notes = %q, want no setting named where each ecosystem was read", notes)
	}
}

// An imported finding the advisories note counts is not counted again as one naming no CVE.
func TestTheAdvisoriesNoteAndTheNoCVENoteCountEachFindingOnce(t *testing.T) {
	imp := func(rule string, eco string) sarif.Result {
		r := xnet(rule, "web", "repo-web")
		r.Scanner = plugin.ImportScanner
		r.Package = &sarif.Package{Name: "p", Version: "1", Ecosystem: eco}
		return r
	}
	d := cachedKEV([]sarif.Result{imp("GHSA-4rgh-jx4f-qfcq", "npm"), imp("SNYK-JS-X-1", "npm")})
	_, notes := signals(d, summarize(d))
	got := strings.Join(notes, "\n")
	if !strings.Contains(got, "did not check 1 npm finding with an advisory id and no CVE") ||
		!strings.Contains(got, "not checked against KEV or EPSS: 1 imported finding names no CVE") {
		t.Errorf("each imported finding should be counted once:\n%s", got)
	}
}

// With an ecosystem's advisories read, a finding they gave no CVE is counted, saying why, and an
// imported one is not counted again as naming no CVE.
func TestSignalsSayWhatTheAdvisoriesLeftUnresolved(t *testing.T) {
	r := xnet("GHSA-4rgh-jx4f-qfcq", "web", "repo-web")
	r.Scanner = plugin.ImportScanner
	r.Package = &sarif.Package{Name: "p", Version: "1", Ecosystem: "npm"}
	d := cachedKEV([]sarif.Result{r})
	d.Exploitability = append(d.Exploitability, FeedProvenance{Name: "osv-npm"})
	_, notes := signals(d, summarize(d))
	got := strings.Join(notes, "\n")
	if !strings.Contains(got, "KEV and EPSS did not check 1 npm finding with an advisory id and no CVE: OSV.dev's "+
		"records of their ids list no CVE, or different ones, so they are ranked without KEV or EPSS.") || strings.Contains(got, "advisories: [") ||
		strings.Contains(got, "imported finding") {
		t.Errorf("notes:\n%s", got)
	}
	var b bytes.Buffer
	writeSignals(&b, tui.Plain(), d, summarize(d), true)
	if !strings.Contains(b.String(), "or different ones") {
		t.Errorf("the compact view dropped the note:\n%s", b.String())
	}
}
