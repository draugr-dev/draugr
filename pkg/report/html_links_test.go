package report

import (
	"bytes"
	"regexp"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

func TestHTMLOpensEveryLinkOffTheReportInANewTab(t *testing.T) {
	// The report keeps what the reader filtered, folded and scrolled to, and following an advisory
	// in the same tab throws all of that away. Checked over every link that leaves the page rather
	// than over the two templates that write one today, so a third cannot be added without it.
	d := goldenCleanData()
	d.Run = engine.Result{Controls: map[string]plugin.ControlResult{"sca": {Report: sarif.Report{
		Tool: "trivy",
		Rules: map[string]sarif.Rule{
			"CVE-2020-14343": {HelpURI: "https://avd.aquasec.com/nvd/cve-2020-14343"},
			"CVE-2019-10906": {HelpURI: "https://avd.aquasec.com/nvd/cve-2019-10906"},
		},
		Results: []sarif.Result{
			{Tool: "Trivy", RuleID: "CVE-2020-14343", Level: sarif.LevelError,
				Message:  "PyYAML: incomplete fix for CVE-2020-1747",
				Location: sarif.Location{URI: "app/requirements.txt", StartLine: 3}},
			// Accepted findings are drawn by a second template, in the Accepted section.
			{Tool: "Trivy", RuleID: "CVE-2019-10906", Level: sarif.LevelWarning,
				Message:     "Jinja2: sandbox escape",
				Location:    sarif.Location{URI: "app/requirements.txt", StartLine: 5},
				Suppression: &sarif.Suppression{Kind: "external", Justification: "template input is never user-controlled"}},
		},
	}}}}
	d.Verdict = norn.Result{Verdict: norn.Fail,
		Controls: []norn.ControlOutcome{{Control: "sca", Verdict: norn.Fail}}}

	var b bytes.Buffer
	if err := (htmlReporter{}).Render(&b, d); err != nil {
		t.Fatal(err)
	}
	out := b.String()

	offPage := regexp.MustCompile(`<a [^>]*href="https?://[^"]*"[^>]*>`).FindAllString(out, -1)
	seen := map[string]bool{}
	for _, a := range offPage {
		if !regexp.MustCompile(`\starget="_blank"`).MatchString(a) || !regexp.MustCompile(`\srel="noopener noreferrer"`).MatchString(a) {
			t.Errorf("a link off the report opens in the same tab, or hands over the report's address:\n%s", a)
		}
		for _, id := range []string{"cve-2020-14343", "cve-2019-10906"} {
			if regexp.MustCompile(regexp.QuoteMeta(id)).MatchString(a) {
				seen[id] = true
			}
		}
	}
	// Both templates have to have drawn a link, or the loop above checked nothing.
	for _, id := range []string{"cve-2020-14343", "cve-2019-10906"} {
		if !seen[id] {
			t.Errorf("no link to %s in the report, so its template went unchecked", id)
		}
	}

	// A link within the report stays in the tab: it moves the view, it does not leave it.
	for _, a := range regexp.MustCompile(`<a [^>]*href="#[^"]*"[^>]*>`).FindAllString(out, -1) {
		if regexp.MustCompile(`\starget=`).MatchString(a) {
			t.Errorf("a link within the report opens a new tab:\n%s", a)
		}
	}
}
