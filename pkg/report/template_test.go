package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/saga"
)

func TestTemplateInline(t *testing.T) {
	cfg := saga.ReportConfig{
		Format:   "template",
		Template: "{{.Verdict}} {{.Release.Name}} P1={{.Priorities.P1}}\n{{range .Findings}}- {{.RuleID}} ({{.Priority}})\n{{end}}",
	}
	a, err := Build(cfg, sampleData())
	if err != nil {
		t.Fatal(err)
	}
	s := string(a.Bytes)
	for _, want := range []string{"fail app", "P1=1", "- CVE-1 (P1)"} {
		if !strings.Contains(s, want) {
			t.Errorf("template output missing %q:\n%s", want, s)
		}
	}
	if a.Filename != "report.txt" || a.Format != "template" {
		t.Errorf("template artifact meta = %+v", a)
	}
}

func TestTemplateFile(t *testing.T) {
	dir := t.TempDir()
	tf := filepath.Join(dir, "r.tmpl")
	if err := os.WriteFile(tf, []byte("verdict={{.Verdict}}"), 0o600); err != nil {
		t.Fatal(err)
	}
	a, err := Build(saga.ReportConfig{Format: "template", TemplateFile: tf, Filename: "out.txt"}, sampleData())
	if err != nil {
		t.Fatal(err)
	}
	if string(a.Bytes) != "verdict=fail" {
		t.Errorf("template file output = %q", a.Bytes)
	}
	if a.Filename != "out.txt" {
		t.Errorf("filename = %q", a.Filename)
	}
}

func TestTemplateErrors(t *testing.T) {
	cases := []struct {
		name string
		cfg  saga.ReportConfig
	}{
		{"neither", saga.ReportConfig{Format: "template"}},
		{"both", saga.ReportConfig{Format: "template", Template: "x", TemplateFile: "y"}},
		{"bad-syntax", saga.ReportConfig{Format: "template", Template: "{{.Nope"}},
		{"missing-file", saga.ReportConfig{Format: "template", TemplateFile: "/no/such/file"}},
		{"bad-field", saga.ReportConfig{Format: "template", Template: "{{.DoesNotExist.X}}"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Build(tc.cfg, sampleData()); err == nil {
				t.Errorf("expected error for %s", tc.name)
			}
		})
	}
}
