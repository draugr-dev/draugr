package report

import (
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sbom"
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
			a, err := Build(saga.ReportConfig{Format: tc.format}, sampleData())
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
	if _, err := Build(saga.ReportConfig{Format: "nope"}, sampleData()); err == nil {
		t.Error("expected error for unknown format")
	}
}

func TestBuildFilenameOverride(t *testing.T) {
	a, err := Build(saga.ReportConfig{Format: "json", Filename: "custom.json"}, sampleData())
	if err != nil {
		t.Fatal(err)
	}
	if a.Filename != "custom.json" {
		t.Errorf("filename override = %q", a.Filename)
	}
}

func TestFilenameAgreesWithWhatAPublisherDelivers(t *testing.T) {
	// Two tables naming the same files agree until they do not, and near-agreement is the worst
	// outcome: nothing looks wrong until a pipeline globs for the one format they differ on.
	// Whatever `-o` writes and whatever a publisher hands to a destination have to be the same
	// name, so the invariant is asserted per format rather than trusted.
	// An SBOM, because gitlab-cyclonedx renders one rather than a view of the findings — and it
	// refuses to write a document with no packages in it, which is the right behavior and not
	// something this test is about.
	d := goldenCleanData()
	d.Run.SBOMs = []sbom.Document{{
		Project: true, Format: saga.SBOMCycloneDXJSON,
		Bytes: []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[
			{"type":"library","name":"flask","version":"0.12.2","purl":"pkg:pypi/flask@0.12.2"}]}`),
	}}
	for format := range reporters {
		art, err := Build(saga.ReportConfig{Format: format}, d)
		if err != nil {
			t.Errorf("%s: Build: %v", format, err)
			continue
		}
		if got := Filename(format); got != art.Filename {
			t.Errorf("%s: Filename() = %q but a publisher delivers %q", format, got, art.Filename)
		}
	}
}

func TestFilenameFallsBackForAnUnknownFormat(t *testing.T) {
	// "template" has no entry: its filename comes from the Saga. A caller still needs a name
	// rather than an empty string, which would write to the directory itself.
	if got := Filename("template"); got != "report.template" {
		t.Errorf("Filename(template) = %q", got)
	}
}
