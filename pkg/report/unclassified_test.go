package report

import (
	"bytes"
	"strings"
	"testing"
)

// A report states the caveat the console states. It is a caveat on every band, and somebody reading a
// report has no console beside it to tell them the ranking describes severity alone.
func TestEveryReportSaysBandsRankSeverityAlone(t *testing.T) {
	d := goldenFullData()
	d.Unclassified = true

	html := strings.Join(strings.Fields(renderHTML(t, d)), " ")
	for _, want := range []string{
		unclassifiedRead,
		"These bands rank severity alone. <code>draugr classify</code> makes them describe this application.",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("the HTML report does not say %q", want)
		}
	}
	if strings.Contains(html, "ranks differently on a public API") {
		t.Error("the HTML report says context moved a band in a run that declared none")
	}

	var md bytes.Buffer
	if err := (markdownReporter{}).Render(&md, d); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{unclassifiedRead, unclassifiedBands} {
		if !strings.Contains(md.String(), want) {
			t.Errorf("the markdown report does not say %q", want)
		}
	}
}

// A run that declares context has no such caveat, and its bands are explained by what moved them.
func TestAClassifiedReportExplainsPriorityByContext(t *testing.T) {
	d := goldenFullData()
	d.Unclassified = false

	html := strings.Join(strings.Fields(renderHTML(t, d)), " ")
	if strings.Contains(html, unclassifiedRead) {
		t.Error("the HTML report states the caveat on a classified run")
	}
	if !strings.Contains(html, "ranks differently on a public API") {
		t.Error("the HTML report dropped what priority combines")
	}
	var md bytes.Buffer
	if err := (markdownReporter{}).Render(&md, d); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(md.String(), unclassifiedRead) {
		t.Error("the markdown report states the caveat on a classified run")
	}
}
