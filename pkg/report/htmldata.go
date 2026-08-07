package report

import (
	"encoding/base64"
	"fmt"
	"html/template"
	"strings"

	"github.com/draugr-dev/draugr/pkg/skald"
)

// The HTML report carries its own data. A reader who wants to feed the findings into a
// spreadsheet, a ticket tracker or another tool would otherwise have to go back to whoever ran
// the scan and ask for the artifacts — and the HTML file is usually the only thing that
// travelled, because it is the one you can open.
//
// Both downloads are `data:` URIs on ordinary <a download> links, so they work with JavaScript
// disabled and under any content-security policy. That matters more here than the bytes it
// costs: this file gets emailed, attached to a build, and opened from disk.

// maxEmbeddedSARIF caps what will be inlined. A scan of a large monorepo can produce megabytes
// of SARIF, and base64 adds a third again — past this the report says so and points at `-o`
// rather than producing a file too big to open.
const maxEmbeddedSARIF = 8 << 20 // 8 MiB

// tsvColumns names the export's columns, in order. Tab-separated rather than comma: finding
// messages contain commas constantly, so CSV needs quoting that spreadsheet importers handle
// inconsistently, and several locales expect ';' as the delimiter instead. No field here can
// contain a tab, so TSV needs no escaping at all and opens on a double-click.
var tsvColumns = []string{
	"Priority", "Severity", "Score", "Rule", "Control", "Scanner", "Location", "Message", "Reference",
}

// buildSARIFDownload renders the run as SARIF and returns it as a data URI, or reports that it
// was too large to embed.
func buildSARIFDownload(d Data) (uri template.URL, tooBig bool) {
	var sb strings.Builder
	if err := skald.WriteSARIF(&sb, d.Run); err != nil {
		// A report that renders is worth more than no report; the download is an extra.
		return "", false
	}
	if sb.Len() > maxEmbeddedSARIF {
		return "", true
	}
	return dataURI("application/sarif+json", sb.String()), false
}

// buildTSVDownload renders the findings as a spreadsheet-ready table.
//
// Every finding, not the filtered listing: a download is the record, and someone who opens it in
// a spreadsheet can filter there. The suppressed ones are included with their justification in
// the Message column, marked, because "what did you decide to accept" is exactly the question a
// spreadsheet gets used for.
func buildTSVDownload(s summary) template.URL {
	var sb strings.Builder
	sb.WriteString(strings.Join(tsvColumns, "\t"))
	sb.WriteByte('\n')
	for _, f := range s.findings {
		writeTSVRow(&sb, f, "")
	}
	for _, f := range s.excluded {
		writeTSVRow(&sb, f, "SUPPRESSED: "+f.justification+" — ")
	}
	return dataURI("text/tab-separated-values", sb.String())
}

func writeTSVRow(sb *strings.Builder, f finding, prefix string) {
	fields := []string{
		dash(f.priority), string(f.severity), scoreStr(f), f.ruleID, f.control, dash(f.tool),
		dash(f.location), prefix + f.message, f.helpURI,
	}
	for i, v := range fields {
		if i > 0 {
			sb.WriteByte('\t')
		}
		sb.WriteString(tsvSafe(v))
	}
	sb.WriteByte('\n')
}

// tsvSafe flattens anything that would break a row. Tabs and newlines are the only characters
// TSV cannot carry, and a scanner message occasionally contains a newline.
func tsvSafe(v string) string {
	return strings.NewReplacer("\t", " ", "\r", " ", "\n", " ").Replace(v)
}

// dataURI builds the download link's href.
//
// The result is template.URL, which tells html/template to emit it verbatim. That bypasses the
// contextual escaping that would otherwise reject a data: URI outright — a sensible default,
// since `data:text/html` in an href is a script-injection vector.
//
// It is safe here because nothing about the URI comes from the scan. The scheme and MIME type
// are compile-time constants in this file, and the payload is base64, whose alphabet is letters,
// digits, '+', '/' and '=' — it cannot contain a quote, an angle bracket, or anything else that
// could end the attribute. Whatever a scanner put in a finding is inside the encoded blob, not
// in the markup.
func dataURI(mime, payload string) template.URL {
	// template.URL bypasses escaping by design here. See the comment above: the scheme and MIME
	// are constants in this file and the payload is base64, whose alphabet cannot terminate the
	// attribute. Nothing from the scan reaches the markup.
	return template.URL(fmt.Sprintf("data:%s;base64,%s", mime, base64.StdEncoding.EncodeToString([]byte(payload)))) // #nosec G203 -- see above
}
