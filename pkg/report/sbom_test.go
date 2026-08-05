package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/sbom"
)

func TestArtifactFilenames(t *testing.T) {
	docs := []sbom.Document{
		{Component: "web", Target: "https://github.com/acme/web", Format: saga.SBOMSPDXJSON, Bytes: []byte("a")},
		{Component: "API Gateway", Target: "python:3.8-slim@sha256:abc", Format: saga.SBOMCycloneDXJSON, Bytes: []byte("b")},
	}
	arts := SBOMArtifacts(docs)
	if len(arts) != 2 {
		t.Fatalf("artifacts = %d, want 2", len(arts))
	}
	want := []string{
		"sbom-web-https-github-com-acme-web.spdx.json",
		"sbom-api-gateway-python-3-8-slim-sha256-abc.cdx.json",
	}
	for i, a := range arts {
		if a.Filename != want[i] {
			t.Errorf("filename[%d] = %q, want %q", i, a.Filename, want[i])
		}
		if a.Format != "sbom" {
			t.Errorf("artifact[%d] format = %q, want sbom", i, a.Format)
		}
	}
	// Each format claims its own media type rather than a blanket application/json.
	for i, want := range []string{"application/spdx+json", "application/vnd.cyclonedx+json"} {
		if arts[i].ContentType != want {
			t.Errorf("contentType[%d] = %q, want %q", i, arts[i].ContentType, want)
		}
	}
}

func TestArtifactFilenamesDoNotCollideAcrossImages(t *testing.T) {
	// Two images in one component is ordinary. If the slug dropped tags, both would land on the
	// same filename and the second would silently overwrite the first.
	arts := SBOMArtifacts([]sbom.Document{
		{Component: "api", Target: "python:3.8-slim", Format: saga.SBOMSPDXJSON},
		{Component: "api", Target: "python:3.12-slim", Format: saga.SBOMSPDXJSON},
	})
	if arts[0].Filename == arts[1].Filename {
		t.Fatalf("both images produced %q", arts[0].Filename)
	}
}

func TestArtifactsEmpty(t *testing.T) {
	if got := SBOMArtifacts(nil); len(got) != 0 {
		t.Errorf("want no artifacts, got %d", len(got))
	}
}

func TestSlug(t *testing.T) {
	for in, want := range map[string]string{
		"web":                       "web",
		"API Gateway":               "api-gateway",
		"python:3.8-slim":           "python-3-8-slim",
		"https://github.com/a/b":    "https-github-com-a-b",
		"ghcr.io/org/img@sha256:ab": "ghcr-io-org-img-sha256-ab",
		"---":                       "",
		"":                          "",
	} {
		if got := slug(in); got != want {
			t.Errorf("slug(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEveryFormatHasAFileExtension(t *testing.T) {
	// A format the Saga accepts but that has no extension here would silently produce
	// "sbom-x-y.json" — readable, but not what a consumer keying on the suffix expects.
	for _, f := range saga.SBOMFormats {
		meta, ok := sbomMeta[f]
		if !ok {
			t.Errorf("format %q has no file extension or media type mapped", f)
			continue
		}
		// An XML or tag-value document labelled application/json would be a lie the moment a
		// publisher acts on the media type.
		if meta.ext == "" || meta.contentType == "" {
			t.Errorf("format %q has an incomplete mapping: %+v", f, meta)
		}
		if strings.HasSuffix(string(f), "-xml") && !strings.Contains(meta.contentType, "xml") {
			t.Errorf("format %q should not claim %q", f, meta.contentType)
		}
	}
}

func TestConsoleReportsSBOMsWithoutMakingThemAControl(t *testing.T) {
	d := Data{
		Release: saga.Release{Name: "app", Version: "1"},
		Run: engine.Result{SBOMs: []sbom.Document{
			{Component: "web", Target: "https://git/web", Format: saga.SBOMSPDXJSON},
			{Component: "api", Target: "api:1", Format: saga.SBOMSPDXJSON},
		}},
		Verdict: norn.Result{Verdict: norn.Pass},
	}
	var buf bytes.Buffer
	if err := (consoleReporter{}).Render(&buf, d); err != nil {
		t.Fatalf("Render: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "SBOM: 2 documents (spdx-json)") {
		t.Errorf("want the SBOM summary line:\n%s", out)
	}
	// It must not appear in the Controls table: every row there means "checked, and here is the
	// verdict", and an inventory has no verdict to give.
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "SBOM") && (strings.Contains(line, "pass") || strings.Contains(line, "FAIL")) {
			t.Errorf("SBOM should not be rendered as a control row: %q", line)
		}
	}
}

func TestConsoleReportsSBOMsOnACleanRun(t *testing.T) {
	// The early return for "no findings" must not swallow the evidence line — a clean scan
	// still produced the inventory.
	d := Data{
		Release: saga.Release{Name: "app", Version: "1"},
		Run:     engine.Result{SBOMs: []sbom.Document{{Component: "web", Target: "r", Format: saga.SBOMSPDXJSON}}},
		Verdict: norn.Result{Verdict: norn.Pass},
	}
	var buf bytes.Buffer
	if err := (consoleReporter{}).Render(&buf, d); err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(buf.String(), "SBOM: 1 document (spdx-json)") {
		t.Errorf("want a singular summary line on a clean run:\n%s", buf.String())
	}
}

func TestConsoleOmitsTheSBOMLineWhenThereAreNone(t *testing.T) {
	var buf bytes.Buffer
	d := Data{Release: saga.Release{Name: "app", Version: "1"}, Verdict: norn.Result{Verdict: norn.Pass}}
	if err := (consoleReporter{}).Render(&buf, d); err != nil {
		t.Fatalf("Render: %v", err)
	}
	if strings.Contains(buf.String(), "SBOM") {
		t.Errorf("no SBOMs means no line at all:\n%s", buf.String())
	}
}

func TestSBOMArtifactsCoverEveryEncoding(t *testing.T) {
	// The point of offering four formats is that a consumer picks one. Each has to produce a
	// distinct, recognisable filename — two of them are not JSON at all.
	docs := []sbom.Document{
		{Component: "c", Target: "t", Format: saga.SBOMSPDXJSON},
		{Component: "c", Target: "t", Format: saga.SBOMSPDXTagValue},
		{Component: "c", Target: "t", Format: saga.SBOMCycloneDXJSON},
		{Component: "c", Target: "t", Format: saga.SBOMCycloneDXXML},
	}
	want := []string{"sbom-c-t.spdx.json", "sbom-c-t.spdx", "sbom-c-t.cdx.json", "sbom-c-t.cdx.xml"}
	arts := SBOMArtifacts(docs)
	for i, a := range arts {
		if a.Filename != want[i] {
			t.Errorf("filename[%d] = %q, want %q", i, a.Filename, want[i])
		}
	}
	// Same component and target in four formats must not collide on disk.
	seen := map[string]bool{}
	for _, a := range arts {
		if seen[a.Filename] {
			t.Errorf("duplicate filename %q", a.Filename)
		}
		seen[a.Filename] = true
	}
}

func TestSBOMArtifactsSurviveAnUnmappedFormat(t *testing.T) {
	// Unreachable through the Saga, which validates first. If it ever happens, writing the
	// document with a dull suffix beats dropping evidence on the floor.
	arts := SBOMArtifacts([]sbom.Document{{Component: "c", Target: "t", Format: "future-format", Bytes: []byte("x")}})
	if len(arts) != 1 || arts[0].Filename != "sbom-c-t.sbom" {
		t.Errorf("artifact = %+v, want a written document with a fallback suffix", arts)
	}
	if len(arts[0].Bytes) == 0 {
		t.Error("the document must still carry its bytes")
	}
}

func TestConsoleReportsSuppressionsAndKeepsThemOutOfFixFirst(t *testing.T) {
	// An excluded finding that left no trace would read exactly like one that was never found.
	// The count is what makes the difference visible.
	rep := sarif.Report{Tool: "gitleaks", Results: []sarif.Result{
		{RuleID: "private-key", Level: sarif.LevelError, Message: "fake key",
			Location:    sarif.Location{URI: "test/fixture.go", StartLine: 1},
			Suppression: &sarif.Suppression{Kind: "external", Justification: "deliberate fixture"}},
	}}
	d := Data{
		Release: saga.Release{Name: "app", Version: "1"},
		Run:     engine.Result{Controls: map[string]plugin.ControlResult{"secrets": {Control: "secrets", Report: rep}}, Suppressed: 1},
		Verdict: norn.Result{Verdict: norn.Pass},
	}
	var buf bytes.Buffer
	if err := (consoleReporter{}).Render(&buf, d); err != nil {
		t.Fatalf("Render: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "1 finding suppressed by config.exclude") {
		t.Errorf("want the suppression count:\n%s", out)
	}
	if strings.Contains(out, "private-key") {
		t.Errorf("a suppressed finding must not appear in the fix-first list:\n%s", out)
	}
}

func TestConsoleSaysNothingWhenNothingWasSuppressed(t *testing.T) {
	var buf bytes.Buffer
	d := Data{Release: saga.Release{Name: "a", Version: "1"}, Verdict: norn.Result{Verdict: norn.Pass}}
	if err := (consoleReporter{}).Render(&buf, d); err != nil {
		t.Fatalf("Render: %v", err)
	}
	if strings.Contains(buf.String(), "suppressed") {
		t.Errorf("no exclusions means no line:\n%s", buf.String())
	}
}

// The assembled document has no component or target to be named after, and "the project" is the
// distinction a reader needs when both kinds land in one directory.
func TestSBOMArtifactsNameTheProjectDocument(t *testing.T) {
	arts := SBOMArtifacts([]sbom.Document{
		{Component: "api", Target: "https://git/api", Format: saga.SBOMCycloneDXJSON, Bytes: []byte("{}")},
		{Project: true, Format: saga.SBOMCycloneDXJSON, Bytes: []byte("{}")},
	})
	if len(arts) != 2 {
		t.Fatalf("artifacts = %d", len(arts))
	}
	if arts[0].Filename != "sbom-api-https-git-api.cdx.json" {
		t.Errorf("component document = %q", arts[0].Filename)
	}
	if arts[1].Filename != "sbom-project.cdx.json" {
		t.Errorf("project document = %q", arts[1].Filename)
	}
}

func TestSBOMLine(t *testing.T) {
	part := sbom.Document{Component: "api", Target: "t", Format: saga.SBOMCycloneDXJSON}
	project := sbom.Document{Project: true, Format: saga.SBOMCycloneDXJSON}
	for _, tc := range []struct {
		name string
		docs []sbom.Document
		want string
	}{
		{"nothing", nil, ""},
		{"parts only", []sbom.Document{part, part}, "SBOM: 2 documents (cyclonedx-json)"},
		{"project only", []sbom.Document{project}, "SBOM: 1 project document (cyclonedx-json)"},
		{"both", []sbom.Document{part, part, project},
			"SBOM: 1 project document + 2 component documents (cyclonedx-json)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := sbomLine(tc.docs); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}
