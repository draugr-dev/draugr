package report

import (
	"bytes"

	"github.com/draugr-dev/draugr/pkg/saga"
)

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
//
// json and sarif keep the names pipelines already expect; the rest follow one shape so a
// directory listing reads as a set of reports rather than a pile of conventions.
var formatMeta = map[string]struct{ filename, contentType string }{
	"json":     {"report.json", "application/json"},
	"sarif":    {"results.sarif", "application/sarif+json"},
	"markdown": {"report.md", "text/markdown"},
	"html":     {"report.html", "text/html; charset=utf-8"},
	"junit":    {"report.junit.xml", "application/xml"},
	"console":  {"report.txt", "text/plain; charset=utf-8"},
	"vex":      {"openvex.json", "application/json"},
}

// Filename is what a format is written as, whether a publisher delivers it or `-o` writes it.
//
// One table, because the alternative is two that agree until they do not. A format written under
// one name locally and another by a publisher breaks whatever globs for it — and a CI step that
// globs for a file it never finds usually warns and carries on, which is a green run with no
// results in it.
func Filename(format string) string {
	if m, ok := formatMeta[format]; ok {
		return m.filename
	}
	return "report." + format
}

// Build renders a report as configured and returns it as an Artifact ready to publish. The
// "template" format renders a user-supplied Go text/template (cfg.Template / cfg.TemplateFile);
// all other formats use the built-in reporter registry. cfg.Filename overrides the default
// output filename.
func Build(cfg saga.ReportConfig, d Data) (Artifact, error) {
	// A report may declare its own band, which narrows this artifact and no other. Applied here
	// because every format is built through this one function, so a filter declared once cannot
	// reach some renderers and miss others.
	if cfg.MinPriority != "" {
		d.MinPriority = cfg.MinPriority
	}
	if cfg.Format == "template" {
		return buildTemplate(cfg, d)
	}
	r, err := For(cfg.Format)
	if err != nil {
		return Artifact{}, err
	}
	var buf bytes.Buffer
	if err := r.Render(&buf, d); err != nil {
		return Artifact{}, err
	}
	meta := formatMeta[cfg.Format]
	filename := meta.filename
	if cfg.Filename != "" {
		filename = cfg.Filename
	}
	return Artifact{
		Format:      cfg.Format,
		Filename:    filename,
		ContentType: meta.contentType,
		Bytes:       buf.Bytes(),
	}, nil
}
