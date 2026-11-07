package report

import (
	"regexp"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/skald"
)

// acceptedRun is a run with two decisions over two components and two controls, a decision with
// no reason, a lapsed entry, and one finding set aside by each of the other three authorities.
func acceptedRun() Data {
	byRule := func(id, prio, comp, loc string, sup *sarif.Suppression, pkg *sarif.Package) sarif.Result {
		tool := "gitleaks"
		if strings.HasPrefix(id, "CVE") {
			tool = "trivy"
		}
		return sarif.Result{
			RuleID: id, Level: sarif.LevelError, Priority: prio, Component: comp, Package: pkg, Tool: tool,
			Location: sarif.Location{URI: loc, StartLine: 3}, Suppression: sup,
		}
	}
	fixtures := func() *sarif.Suppression {
		return &sarif.Suppression{Kind: "external", Origin: sarif.OriginSaga, Justification: "fixtures hold fake credentials",
			Source: "draugr.saga.yaml", Line: 12, Expires: "2027-03-31"}
	}
	pinned := func() *sarif.Suppression {
		return &sarif.Suppression{Kind: "external", Origin: sarif.OriginSaga, Justification: "pinned for the legacy admin",
			Source: "team.saga-fragment.yaml", Line: 4}
	}
	return Data{
		Descriptor: &skald.DescriptorRef{Exclusions: []skald.Exclusion{
			{Source: "draugr.saga.yaml", Line: 12, Rules: []string{"gitleaks.*", "generic-api-key"}, Paths: []string{"fixtures/"},
				Reason: "fixtures hold fake credentials", Expires: "2027-03-31",
				VEX:        &skald.ExclusionVEX{Status: "not_affected", Justification: "vulnerable_code_not_present"},
				GitHistory: &saga.LineHistory{Commit: "4f2a9c1e0b3d5f7a", Author: "Ada Lovelace", Date: "2026-09-14T10:00:00Z"}},
			{Source: "team.saga-fragment.yaml", Line: 4, Rules: []string{"CVE-2023-0001"}, Reason: "pinned for the legacy admin",
				GitHistory: &saga.LineHistory{Unavailable: "the line is not committed"}},
		}},
		Run: engine.Result{
			Suppressed: 5, Imported: 1, Silenced: 1,
			Controls: map[string]plugin.ControlResult{
				"secrets": {Report: sarif.Report{Tool: "gitleaks", Results: []sarif.Result{
					byRule("aws-key", "P1", "api", "fixtures/a.env", fixtures(), nil),
					byRule("generic-api-key", "P2", "worker", "fixtures/b.env", fixtures(), nil),
					byRule("old-key", "P3", "api", "notes/old.txt", &sarif.Suppression{Kind: "external", Origin: sarif.OriginSaga,
						Source: "draugr.saga.yaml", Line: 30}, nil),
				}}},
				"sca": {Report: sarif.Report{Tool: "trivy", Results: []sarif.Result{
					byRule("CVE-2023-0001", "P1", "api", "requirements.txt", pinned(),
						&sarif.Package{Name: "openssl", Version: "1.1.1w"}),
					byRule("CVE-2024-0002", "P1", "worker", "go.sum", fixtures(), nil),
					byRule("CVE-VEX", "P2", "api", "go.sum", &sarif.Suppression{Kind: "external", Origin: sarif.OriginVEX,
						Justification: "the vendor says so"}, nil),
					byRule("CVE-IGNORED", "P4", "api", "go.sum", &sarif.Suppression{Kind: "external", Origin: sarif.OriginScanner,
						Justification: ".trivyignore"}, nil),
					byRule("CVE-DEV", "P4", "api", "go.sum", &sarif.Suppression{Kind: "external", Origin: sarif.OriginSetting,
						Source: "config.controls.sca.devDependencies", Justification: "a development dependency"}, nil),
				}}},
			},
			LapsedExclusions: []saga.ExcludeRule{{
				Rules: []string{"CVE-2019-11324"}, Reason: "accepted until the October release", Expires: "2026-10-01",
				Source: "draugr.saga.yaml", Line: 23,
			}},
		},
	}
}

var decisionTag = regexp.MustCompile(`(?s)<details class="dec" data-set ([^>]*)>`)

// decisionsOf is the Decisions list and nothing after it.
func decisionsOf(t *testing.T, page string) string {
	t.Helper()
	return section(t, page, `<section id="decisions">`, `</section>`)
}

// decisionRows splits the Decisions list into its rows, in order.
func decisionRows(t *testing.T, page string) []string {
	t.Helper()
	list := decisionsOf(t, page)
	parts := strings.Split(list, `<details class="dec"`)[1:]
	for i := range parts {
		parts[i] = `<details class="dec"` + parts[i]
	}
	return parts
}

// Reviewers ask about decisions before findings, so each decision is one row, titled by its reason,
// with one line of facts and the bands of what it covers.
func TestTheAcceptedTabDrawsOneRowPerDecision(t *testing.T) {
	rows := decisionRows(t, renderHTML(t, acceptedRun()))
	if len(rows) != 4 {
		t.Fatalf("got %d decision rows, want the three decisions and the lapsed entry", len(rows))
	}
	// Most findings first, then by where each is written, then the lapsed.
	for i, want := range []string{
		`<span class="name">fixtures hold fake credentials</span>`,
		`<span class="name"><span class="none">no reason recorded</span></span>`,
		`<span class="name">pinned for the legacy admin</span>`,
		`<span class="name">accepted until the October release</span>`,
	} {
		if !strings.Contains(rows[i], want) {
			t.Errorf("row %d is not titled %s:\n%s", i, want, rows[i])
		}
	}
	for i, want := range []string{
		`config.exclude<span class="faint"> · </span>written in <code>draugr.saga.yaml:12</code><span class="faint"> · </span>lapses 2027-03-31<span class="faint"> · </span>3 findings</div>`,
		`config.exclude<span class="faint"> · </span>written in <code>team.saga-fragment.yaml:4</code><span class="faint"> · </span>does not lapse<span class="faint"> · </span>1 finding</div>`,
		`config.exclude<span class="faint"> · </span>written in <code>draugr.saga.yaml:23</code><span class="faint"> · </span><span class="err">lapsed 2026-10-01</span><span class="faint"> · </span>no findings</div>`,
	} {
		row := rows[[]int{0, 2, 3}[i]]
		if !strings.Contains(row, want) {
			t.Errorf("the fact line is not\n%s\nin\n%s", want, row)
		}
	}
	// The bands of the findings each decision covers, and none on an entry that covers nothing.
	for _, want := range []string{`<span class="sev s-p1">2 P1</span>`, `<span class="sev s-p2">1 P2</span>`, `<span class="sev s-p3 off">0 P3</span>`} {
		if !strings.Contains(rows[0], want) {
			t.Errorf("the first decision's bands are missing %s", want)
		}
	}
	if strings.Contains(rows[3], `class="sevs"`) {
		t.Error("a lapsed entry draws bands for findings it no longer covers")
	}
}

// Opened, a decision lists every field its entry set, in the descriptor's order, then where it is
// written and git's record of that line, named for what blame is rather than for an approval.
func TestADecisionOpensToEveryFieldItsEntrySet(t *testing.T) {
	page := renderHTML(t, acceptedRun())
	rows := decisionRows(t, page)
	first := rows[0]
	order := []string{
		`<dt>Rules</dt><dd><code>gitleaks.*</code>, <code>generic-api-key</code></dd>`,
		`<dt>Paths</dt><dd><code>fixtures/</code></dd>`,
		`<dt>Expires</dt><dd><code>2027-03-31</code></dd>`,
		`<dt>VEX</dt><dd><code>not_affected</code> · <code>vulnerable_code_not_present</code></dd>`,
		`<dt>Written in</dt><dd><code>draugr.saga.yaml:12</code></dd>`,
		`<dt>Last changed</dt><dd>4f2a9c1e0b3d by Ada Lovelace, 2026-09-14</dd>`,
	}
	at := -1
	for _, want := range order {
		i := strings.Index(first, want)
		if i < 0 {
			t.Errorf("the opened row is missing %s:\n%s", want, first)
			continue
		}
		if i < at {
			t.Errorf("%s is out of the descriptor's order", want)
		}
		at = i
	}
	// Only the fields the entry set.
	second := rows[2]
	for _, absent := range []string{"<dt>Paths</dt>", "<dt>Expires</dt>", "<dt>VEX</dt>"} {
		if strings.Contains(second, absent) {
			t.Errorf("an entry that sets no such field shows %s", absent)
		}
	}
	if !strings.Contains(second, `<dt>Last changed</dt><dd><span class="err">unavailable: the line is not committed</span></dd>`) {
		t.Errorf("git's refusal is not shown as one:\n%s", second)
	}
	// A suppression no descriptor entry matches still says where it is and that nothing records it.
	if !strings.Contains(rows[1], `<dt>Written in</dt><dd><code>draugr.saga.yaml:30</code></dd>`) ||
		!strings.Contains(rows[1], `<dt>Last changed</dt><dd><span class="none">not recorded</span></dd>`) {
		t.Errorf("an entry the descriptor block lacks:\n%s", rows[1])
	}
	if !strings.Contains(rows[3], "<dt>Rules</dt><dd><code>CVE-2019-11324</code></dd>") ||
		!strings.Contains(rows[3], "the findings it matched are open again") {
		t.Errorf("a lapsed entry does not show its fields or why it covers nothing:\n%s", rows[3])
	}
	list := strings.ToLower(decisionsOf(t, page))
	for _, word := range []string{"approved by", "accepted by"} {
		if strings.Contains(list, word) {
			t.Errorf("git's record of a line is called %q, and blame is not approval", word)
		}
	}
}

// The findings a decision covers are listed under it and under no other, each with its band, rule,
// component, and its package where it is about one or its location where it is not.
func TestADecisionListsTheFindingsItCovers(t *testing.T) {
	rows := decisionRows(t, renderHTML(t, acceptedRun()))
	covered := func(row string) string { return section(t, row, `<ul class="covered">`, `</ul>`) }
	first, second := covered(rows[0]), covered(rows[2])
	for _, rule := range []string{"aws-key", "generic-api-key", "CVE-2024-0002"} {
		if !strings.Contains(first, rule) {
			t.Errorf("%s is not under the decision that set it aside", rule)
		}
		if strings.Contains(second, rule) {
			t.Errorf("%s is under a decision that did not set it aside", rule)
		}
	}
	for _, want := range []string{
		`<span class="pri P1">P1</span><span class="id">aws-key</span><span class="faint"> · </span><span class="lbl">component</span> api<span class="faint"> · </span><code>fixtures/a.env:3</code></li>`,
		`<span class="pri P2">P2</span><span class="id">generic-api-key</span><span class="faint"> · </span><span class="lbl">component</span> worker`,
	} {
		if !strings.Contains(first, want) {
			t.Errorf("the covered list is missing\n%s\nin\n%s", want, first)
		}
	}
	if !strings.Contains(second, `<span class="lbl">package</span> openssl 1.1.1w</li>`) {
		t.Errorf("a finding about a package is not named by it:\n%s", second)
	}
	// Most urgent first, then by where.
	if strings.Index(first, "aws-key") > strings.Index(first, "CVE-2024-0002") ||
		strings.Index(first, "CVE-2024-0002") > strings.Index(first, "generic-api-key") {
		t.Errorf("the covered findings are not ordered by band, then location:\n%s", first)
	}
	if strings.Contains(rows[3], `<ul class="covered">`) {
		t.Error("a lapsed entry lists findings")
	}
}

// The strip reads each row's values off its attributes. A decision holds every value its findings
// hold, one per line, so a menu keeps it where any of them matches.
func TestTheAcceptedStripReadsWhatEachRowCarries(t *testing.T) {
	page := renderHTML(t, acceptedRun())
	rows := decisionRows(t, page)
	attrs := func(row string) string {
		m := decisionTag.FindStringSubmatch(row)
		if m == nil {
			t.Fatalf("no decision tag in %s", row)
		}
		return m[1]
	}
	first := attrs(rows[0])
	for _, want := range []string{
		"data-p=\"P1\nP2\"", "data-s=\"high\"", "data-c=\"secrets\nsca\"", "data-m=\"api\nworker\"",
		"data-sc=\"gitleaks\ntrivy\"", `data-via="exclude"`, `data-ends="in-date"`,
	} {
		if !strings.Contains(first, want) {
			t.Errorf("the first decision does not carry %q:\n%s", want, first)
		}
	}
	// The order controls are iterated in decides the order these are met, so accept either.
	if !strings.Contains(first, "data-c=\"secrets\nsca\"") && !strings.Contains(first, "data-c=\"sca\nsecrets\"") {
		t.Errorf("controls: %s", first)
	}
	q := regexp.MustCompile(`data-q="([^"]*)"`).FindStringSubmatch(first)[1]
	for _, want := range []string{"fixtures hold fake credentials", "draugr.saga.yaml:12", "gitleaks.*", "fixtures/",
		"aws-key", "worker", "fixtures/a.env:3", "cve-2024-0002"} {
		if !strings.Contains(q, want) {
			t.Errorf("the search does not cover %q: %q", want, q)
		}
	}
	if strings.Contains(q, " - ") || strings.Contains(q, "  ") {
		t.Errorf("the search holds a placeholder or an empty word: %q", q)
	}
	if !strings.Contains(attrs(rows[2]), "openssl") {
		t.Error("the search does not cover the package of a covered finding")
	}
	if !strings.Contains(attrs(rows[2]), `data-ends="none"`) || !strings.Contains(attrs(rows[3]), `data-ends="lapsed"`) {
		t.Errorf("Ends: %s / %s", attrs(rows[2]), attrs(rows[3]))
	}

	// The findings in the other subsection carry the same menus, with where each is recorded.
	findings := section(t, page, `<section id="accepted">`, `</section>`)
	for rule, want := range map[string]string{
		"CVE-2023-0001": `data-via="exclude" data-ends="none"`,
		"aws-key":       `data-via="exclude" data-ends="in-date"`,
		"CVE-VEX":       `data-via="vex" data-ends="none"`,
		"CVE-IGNORED":   `data-via="scanner" data-ends="none"`,
		"CVE-DEV":       `data-via="setting" data-ends="none"`,
	} {
		row := regexp.MustCompile(`<div class="f" [^>]*data-q="` + regexp.QuoteMeta(strings.ToLower(rule)) + `[^"]*">`).FindString(findings)
		if !strings.Contains(row, want) {
			t.Errorf("%s: got %q, want %s", rule, row, want)
		}
	}
	// A reason is something a reader searches for.
	if !strings.Contains(findings, `the vendor says so vex">`) {
		t.Error("an accepted finding's search does not cover its reason and authority")
	}
}

// The menus offer Draugr's own vocabulary with a zero where nothing carries a value, and name
// themselves in each token they leave.
func TestTheAcceptedStripOffersItsMenus(t *testing.T) {
	page := renderHTML(t, acceptedRun())
	strip := section(t, page, `<div class="tools" id="accepted-tools" hidden>`, `<div class="tokens"></div>`)
	for _, want := range []string{
		`<input type="checkbox" data-k="via" value="exclude" data-label="config.exclude">config.exclude</span>
        <span class="c">5</span>`,
		`<input type="checkbox" data-k="via" value="vex" data-label="VEX">VEX</span>
        <span class="c">1</span>`,
		`<input type="checkbox" data-k="via" value="scanner" data-label="scanner exclusions">scanner exclusions</span>`,
		`<input type="checkbox" data-k="via" value="setting" data-label="setting">setting</span>`,
		`<input type="checkbox" data-k="ends" value="in-date" data-label="in date">in date</span>`,
		`<input type="checkbox" data-k="ends" value="lapsed" data-label="lapsed" disabled>lapsed</span>
        <span class="c">0</span>`,
		`<input type="checkbox" data-k="ends" value="none" data-label="no end date">no end date</span>`,
		`<input type="checkbox" data-k="p" value="P3">P3</span>`,
		`aria-label="Priority" data-token="priority"`,
		`aria-label="Recorded in" data-token="recorded in"`,
		`aria-label="Ends">`,
		`<span class="menu-anchor folded" data-k="s">`,
		`<span class="menu-anchor folded" data-k="m">`,
		`<span class="menu-anchor folded" data-k="c">`,
		`<span class="menu-anchor folded" data-k="sc">`,
		`<input type="checkbox" data-k="m" value="worker">worker</span>`,
	} {
		if !strings.Contains(strip, want) {
			t.Errorf("the Accepted strip is missing\n%s", want)
		}
	}
	// Above the lists it narrows.
	if strings.Index(page, `id="accepted-tools"`) > strings.Index(page, `<section id="decisions">`) {
		t.Error("the strip comes after the list it narrows")
	}
}

// One machine narrows every list, and the Findings tab still goes through it: a second copy of the
// filter code is a second thing to keep true.
func TestOneStripServesTheFindingsAndAcceptedTabs(t *testing.T) {
	d := acceptedRun()
	open := d.Run.Controls["secrets"]
	open.Report.Results = append(open.Report.Results, sarif.Result{RuleID: "live-key", Level: sarif.LevelError, Priority: "P1", Tool: "gitleaks"})
	d.Run.Controls["secrets"] = open
	page := renderHTML(t, d)
	for _, want := range []string{`strip(acceptedTools, {`, `strip(tools, {`} {
		if !strings.Contains(page, want) {
			t.Errorf("the script does not build a strip with %s", want)
		}
	}
	for _, once := range []string{"function passes(", "function held(", "function paint(", "function token("} {
		if n := strings.Count(page, once); n != 1 {
			t.Errorf("%s is defined %d times, want once", once, n)
		}
	}
	findings := section(t, page, `<div class="tools" id="tools" hidden>`, `<div class="tokens" id="tokens">`)
	if !strings.Contains(findings, `aria-label="Priority" data-token="priority"`) {
		t.Error("the Findings tab's Priority menu does not name itself in its token")
	}
	if strings.Contains(findings, `aria-label="Movement" data-token`) {
		t.Error("the Movement menu names itself before labels that are already phrases")
	}
}

// Without a decision the strip still narrows the findings, and with nothing accepted there is no
// strip at all.
func TestTheAcceptedStripFollowsWhatIsListed(t *testing.T) {
	d := mixedAcceptanceData()
	results := d.Run.Controls["sca"].Report.Results
	d.Run.Controls["sca"] = plugin.ControlResult{Control: "sca", Report: sarif.Report{Tool: "trivy", Results: results[1:]}}
	page := renderHTML(t, d)
	if strings.Contains(page, `<section id="decisions">`) {
		t.Error("a Decisions list is drawn with no decision in the run")
	}
	if !strings.Contains(page, `id="accepted-tools"`) || !strings.Contains(page, `<section id="accepted">`) {
		t.Error("accepted findings with no decision have no strip or no list")
	}
	if page := renderHTML(t, Data{}); strings.Contains(page, `id="accepted-tools"`) {
		t.Error("a strip is drawn with nothing accepted")
	}
}

func TestRecordedInAndEnds(t *testing.T) {
	for origin, want := range map[string]string{
		sarif.OriginSaga: recordedExclude, sarif.OriginVEX: recordedVEX, sarif.OriginTool: recordedScanner,
		sarif.OriginScanner: recordedScanner, sarif.OriginSetting: recordedSetting,
	} {
		if got := recordedIn(sarif.Result{Suppression: &sarif.Suppression{Origin: origin}}); got != want {
			t.Errorf("recordedIn(%s) = %s, want %s", origin, got, want)
		}
	}
	for _, c := range []struct {
		expires string
		lapsed  bool
		want    string
	}{{"", false, endsNone}, {"2027-01-01", false, endsInDate}, {"2026-01-01", true, endsLapsed}} {
		if got := endsOf(c.expires, c.lapsed); got != c.want {
			t.Errorf("endsOf(%q, %v) = %s, want %s", c.expires, c.lapsed, got, c.want)
		}
	}
	// Only a decision of this project's has a key; the rest are listed under no decision.
	for _, origin := range []string{sarif.OriginVEX, sarif.OriginTool, sarif.OriginScanner, sarif.OriginSetting} {
		if k := decisionKey(sarif.Result{Suppression: &sarif.Suppression{Origin: origin}}); k != "" {
			t.Errorf("a %s suppression has a decision key %q", origin, k)
		}
	}
	if decisionKey(sarif.Result{}) != "" {
		t.Error("an open finding has a decision key")
	}
}
