package report

import (
	"slices"
	"testing"
)

// TestEveryDocumentFormatIsARealReporter closes the gap between the three lists a format has to
// appear in to work.
//
// A format registered as a document, and given a filename, but never added to the renderer
// registry is one the CLI rejects as unknown — while every unit test of the renderer itself
// passes, because those call it directly. Nothing else in the suite crosses the two lists.
func TestEveryDocumentFormatIsARealReporter(t *testing.T) {
	known := Formats()
	for format := range documentFormats {
		if !slices.Contains(known, format) {
			t.Errorf("%q is a document format with no reporter behind it, so `--report %s` is "+
				"rejected as unknown", format, format)
		}
	}
}

// TestEveryReporterHasAFilename is the other direction: a format that renders but has nowhere to
// be written lands under a default name, which is how two formats quietly overwrite each other.
func TestEveryReporterHasAFilename(t *testing.T) {
	for _, format := range Formats() {
		if _, ok := formatMeta[format]; !ok {
			t.Errorf("%q renders but has no filename, so writing it to -o has to guess", format)
		}
	}
}
