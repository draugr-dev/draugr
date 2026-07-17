package report

import "bytes"

// Artifact is a rendered report plus the metadata a publisher needs to deliver it: a default
// filename, a MIME content type, and the bytes. It is the unit a Publisher (pkg/publish)
// delivers to a destination.
type Artifact struct {
	Format      string // the reporter format, e.g. "sarif"
	Filename    string // default base filename, e.g. "results.sarif"
	ContentType string // MIME type, e.g. "application/sarif+json"
	Bytes       []byte // the rendered report
}

// formatMeta maps each format to its default filename and MIME content type.
var formatMeta = map[string]struct{ filename, contentType string }{
	"json":     {"report.json", "application/json"},
	"sarif":    {"results.sarif", "application/sarif+json"},
	"markdown": {"report.md", "text/markdown"},
	"html":     {"report.html", "text/html; charset=utf-8"},
	"junit":    {"report.junit.xml", "application/xml"},
	"console":  {"report.txt", "text/plain; charset=utf-8"},
}

// Build renders Data in the given format and returns it as an Artifact ready to publish.
func Build(format string, d Data) (Artifact, error) {
	r, err := For(format)
	if err != nil {
		return Artifact{}, err
	}
	var buf bytes.Buffer
	if err := r.Render(&buf, d); err != nil {
		return Artifact{}, err
	}
	meta := formatMeta[format]
	return Artifact{
		Format:      format,
		Filename:    meta.filename,
		ContentType: meta.contentType,
		Bytes:       buf.Bytes(),
	}, nil
}
