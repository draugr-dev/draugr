package report

import (
	"strings"
	"testing"
)

func TestBuildArtifact(t *testing.T) {
	cases := []struct {
		format, wantFile, wantType, wantContains string
	}{
		{"json", "report.json", "application/json", `"verdict"`},
		{"sarif", "results.sarif", "application/sarif+json", "runs"},
		{"markdown", "report.md", "text/markdown", "## Draugr"},
		{"html", "report.html", "text/html; charset=utf-8", "<!doctype html>"},
		{"junit", "report.junit.xml", "application/xml", "<testsuites"},
	}
	for _, tc := range cases {
		t.Run(tc.format, func(t *testing.T) {
			a, err := Build(tc.format, sampleData())
			if err != nil {
				t.Fatal(err)
			}
			if a.Format != tc.format || a.Filename != tc.wantFile || a.ContentType != tc.wantType {
				t.Errorf("meta = %+v", a)
			}
			if !strings.Contains(string(a.Bytes), tc.wantContains) {
				t.Errorf("%s bytes missing %q:\n%s", tc.format, tc.wantContains, a.Bytes)
			}
		})
	}
}

func TestBuildUnknownFormat(t *testing.T) {
	if _, err := Build("nope", sampleData()); err == nil {
		t.Error("expected error for unknown format")
	}
}
