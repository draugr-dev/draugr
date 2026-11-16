package report

import (
	"bytes"
	"strings"
	"testing"

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

	read := kevData(goOnlyRun())
	read.Exploitability = append(read.Exploitability, FeedProvenance{Name: "govulndb"})
	if _, notes := signals(read, summarize(read)); strings.Contains(strings.Join(notes, "\n"), want[:20]) {
		t.Errorf("notes = %q, want nothing more where the database was read", notes)
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

	read := kevData(goOnlyRun())
	read.Exploitability = append(read.Exploitability, FeedProvenance{Name: "govulndb"})
	b.Reset()
	writeSignals(&b, tui.Plain(), read, summarize(read), true)
	if strings.Contains(b.String(), "did not check") {
		t.Errorf("compact signals = %q, want no lookup note where the database was read", b.String())
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
